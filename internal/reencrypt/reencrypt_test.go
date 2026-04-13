/*
Copyright 2024, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package reencrypt

import (
	"os"
	"path"

	"github.com/belastingdienst/opr-paas-cli/v2/internal/paasfile"
	"github.com/belastingdienst/opr-paas-cli/v2/pkg/crypt"
	"github.com/belastingdienst/opr-paas/v5/api/v1alpha2"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

var _ = Describe("Reencrypt", Ordered, func() {
	const (
		paasName   = "my-paas"
		secretName = "my-secret"
		capName    = "my-cap"
	)
	var (
		tmpDir           string
		paasFilePath     string
		myDecrypter      *crypt.Crypt
		reencryptService ConversionService
		secretValue      = []byte("my-secret-value")
		encrypted        string
		v2Paas           v1alpha2.Paas
		v2PaasBody       []byte
	)
	BeforeAll(func() {
		var (
			err         error
			myEncrypter *crypt.Crypt
		)

		tmpDir, err = os.MkdirTemp("", "migrate")
		Ω(err).Error().NotTo(HaveOccurred())

		// First round (generate encrypted secrets)
		encryptPrivKeyPath := path.Join(tmpDir, "private1")
		myEncrypter, err = crypt.NewGeneratedCrypt(encryptPrivKeyPath, path.Join(tmpDir, "public1"),
			paasName)
		Ω(err).Error().NotTo(HaveOccurred())

		// Second round (reencrypt secrets)
		reencryptedPrivKeyPath := path.Join(tmpDir, "private2")
		reencryptedPublicKeyPath := path.Join(tmpDir, "public2")
		err = crypt.GenerateKeyPair(reencryptedPrivKeyPath, reencryptedPublicKeyPath)
		Ω(err).Error().NotTo(HaveOccurred())

		reencryptService = ConversionService{
			Factory: &FileCryptFactory{
				PrivateKeyFiles: []string{encryptPrivKeyPath, reencryptedPrivKeyPath},
				PublicKeyFile:   reencryptedPublicKeyPath,
			},
		}

		// Third round (decrypt reencrypted secrets)
		Ω(err).Error().NotTo(HaveOccurred())
		myDecrypter, err = crypt.NewCryptFromFiles([]string{reencryptedPrivKeyPath}, reencryptedPublicKeyPath, paasName)
		Ω(err).Error().NotTo(HaveOccurred())

		paasFilesPath := path.Join(tmpDir, "paas")
		err = os.Mkdir(paasFilesPath, 0777)
		Ω(err).Error().NotTo(HaveOccurred())
		paasFilePath = path.Join(paasFilesPath, "v2.paas")

		encrypted, err = myEncrypter.Encrypt(secretValue)
		Ω(err).Error().NotTo(HaveOccurred())
	})

	BeforeEach(func() {
		var err error
		v2Paas = v1alpha2.Paas{
			TypeMeta: metav1.TypeMeta{
				APIVersion: paasfile.V2Version,
				Kind:       "paas",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: paasName,
				Labels: map[string]string{
					"some":  "label",
					"other": "label_too",
				},
			},
			Spec: v1alpha2.PaasSpec{
				Secrets: map[string]string{
					secretName: encrypted,
				},
				Capabilities: v1alpha2.PaasCapabilities{
					capName: v1alpha2.PaasCapability{
						Secrets: map[string]string{
							secretName: encrypted,
						},
					},
				},
			},
		}
		v2PaasBody, err = yaml.Marshal(v2Paas)
		Ω(err).Error().NotTo(HaveOccurred())
		f, err := os.Create(paasFilePath)
		Ω(err).Error().NotTo(HaveOccurred())
		_, err = f.Write(v2PaasBody)
		Ω(err).Error().NotTo(HaveOccurred())
	})
	AfterAll(func() {
		err := os.RemoveAll(tmpDir)
		Ω(err).Error().NotTo(HaveOccurred())
	})

	// 30 33-37 39-40 47-60 66-75 78-79 86-93 96-102 105-106 110-112 117-163 165-182 185-204
	When("Reencrypting", Ordered, func() {
		It("should succeed", func() {
			files, err := paasfile.FilesFromPaths([]string{paasFilePath}, paasfile.AutoFormat.String())
			Ω(err).Error().NotTo(HaveOccurred())
			err = reencryptService.ReencryptObjects(files)
			Ω(err).Error().NotTo(HaveOccurred())
			err = files.Write()
			Ω(err).Error().NotTo(HaveOccurred())

			pf := paasfile.File{Path: paasFilePath}
			paas, err := pf.GetPaas()
			Ω(err).Error().NotTo(HaveOccurred())
			Ω(paas.Spec.Capabilities).To(HaveLen(1))
			Ω(paas.Spec.Capabilities).To(HaveKey(capName))
			for _, secrets := range []map[string]string{
				paas.Spec.Secrets,
				paas.Spec.Capabilities[capName].Secrets,
			} {
				Ω(secrets).To(HaveLen(1))
				Ω(secrets).To(HaveKey(secretName))
				encrypted := secrets[secretName]
				decrypted, err := myDecrypter.Decrypt(encrypted)
				Ω(err).Error().NotTo(HaveOccurred())
				Ω(decrypted).To(Equal(secretValue))
			}
			Ω(paas.Spec.Capabilities[capName].Secrets[secretName]).NotTo(Equal(paas.Spec.Secrets[secretName]))
		})
	})
	When("Reencrypting with another key", func() {
		It("should not succeed", func() {
			var err error
			privKeyPath := path.Join(tmpDir, "private3")
			pubKeyPath := path.Join(tmpDir, "public3")
			err = crypt.GenerateKeyPair(privKeyPath, pubKeyPath)
			Ω(err).Error().NotTo(HaveOccurred())

			otherService := ConversionService{
				Factory: &FileCryptFactory{
					PrivateKeyFiles: []string{privKeyPath},
					PublicKeyFile:   pubKeyPath,
				},
			}
			files, err := paasfile.FilesFromPaths([]string{paasFilePath}, paasfile.AutoFormat.String())
			Ω(err).Error().NotTo(HaveOccurred())
			err = otherService.ReencryptObjects(files)
			Ω(err).Error().To(HaveOccurred())
		})
	})
})

type MockCrypt struct {
	mock.Mock
}

func (m *MockCrypt) Decrypt(secret string) ([]byte, error) {
	args := m.Called(secret)
	return []byte(args.String(0)), args.Error(1)
}

func (m *MockCrypt) Encrypt(data []byte) (string, error) {
	args := m.Called(data)
	return args.String(0), args.Error(1)
}

type MockCryptFactory struct {
	mock.Mock
	crypt crypt.Cryptor
}

func (f *MockCryptFactory) GetCrypt(paasName string) (crypt.Cryptor, error) {
	return f.crypt, nil
}

var _ = Describe("Reencrypt with a mock", Ordered, func() {
	const (
		originalSecret    = "old-encrypted"
		decryptedSecret   = "decrypted"
		reencryptedSecret = "new-encrypted"
	)
	var (
		paas = &v1alpha2.Paas{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-paas",
			},
			Spec: v1alpha2.PaasSpec{
				Secrets: map[string]string{
					"mysecret": originalSecret,
				},
				Capabilities: map[string]v1alpha2.PaasCapability{},
			},
		}

		mockCrypt   = &MockCrypt{}
		mockFactory = &MockCryptFactory{crypt: mockCrypt}

		service = &ConversionService{Factory: mockFactory}
	)

	BeforeAll(func() {
		mockCrypt.On("Decrypt", originalSecret).Return(decryptedSecret, nil)
		// dstCrypt.Encrypt returns reencryptedSecret
		mockCrypt.On("Encrypt", []byte(decryptedSecret)).Return(reencryptedSecret, nil)
	})

	AfterAll(func() {
	})

	When("Reencrypting", func() {
		It("should work as expected", func() {
			err := service.reencryptPaas(paas)
			Ω(err).Error().NotTo(HaveOccurred())
			Ω(paas.Spec.Secrets["mysecret"]).To(Equal(reencryptedSecret))
			mockCrypt.AssertExpectations(GinkgoT())
		})
	})
})
