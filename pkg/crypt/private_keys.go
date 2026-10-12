/*
Copyright 2025, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package crypt

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/belastingdienst/opr-paas-cli/v2/internal/utils"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/sirupsen/logrus"
)

const (
	// hashLen sets the langth of the hash to be used
	hashLen = 8
)

// PrivateKeys is an interface for handling multiple private keys (for rotation)
// and storing them in a list of PrivateKey's.
type PrivateKeys map[string]*PrivateKey

// NewPrivateKeysFromFiles returns a Crypt based on the provided privateKeyPaths
func NewPrivateKeysFromFiles(privateKeyPaths []string) (PrivateKeys, error) {
	var privateKeys = PrivateKeys{}
	var pk *PrivateKey
	var files []string
	var err error

	if files, err = utils.PathToFileList(privateKeyPaths); err != nil {
		return nil, fmt.Errorf("could not find files in '%v': %w", privateKeyPaths, err)
	}

	for _, file := range files {
		logrus.Debugf("reading file %v", file)
		if pk, err = NewPrivateKeyFromFile(file); err != nil {
			return nil, fmt.Errorf("invalid private key file %s", file)
		}

		privateKeys[pk.GetID()] = pk
	}

	return privateKeys, nil
}

// NewPrivateKeysFromSecretData returns a Crypt based on the provided privateKeyPaths
func NewPrivateKeysFromSecretData(privateKeyData map[string][]byte) (PrivateKeys, error) {
	var privateKeys = PrivateKeys{}
	var privateKey *PrivateKey
	var err error

	for name, value := range privateKeyData {
		if privateKey, err = NewPrivateKeyFromPem("", value); err != nil {
			return nil, err
		}

		privateKeys[name] = privateKey
	}

	return privateKeys, nil
}

// currentKey returns the PrivateKey to use when no public key was explicitly provided: the sole key if
// there is exactly one, or the key flagged 'current' when there are several. Callers branch on its
// Algorithm to get at the right kind of public component.
func (pks PrivateKeys) currentKey() (*PrivateKey, error) {
	if len(pks) == 0 {
		return nil, errors.New("cannot get Public key from an empty map of private keys")
	}
	if len(pks) == 1 {
		for _, pk := range pks {
			return pk, nil
		}
	}

	for _, pk := range pks {
		if pk.isCurrent {
			return pk, nil
		}
	}
	return nil, errors.New("cannot get Public key from multiple keys unless there is a 'current' key")
}

// PublicKey returns the RSA public key from a set of private keys in some scenarios (only one private
// key, or a 'current' key). It only supports RSA keys; use currentKey for algorithm-agnostic callers.
func (pks PrivateKeys) PublicKey() (*rsa.PublicKey, error) {
	pk, err := pks.currentKey()
	if err != nil {
		return nil, err
	}
	return &pk.privateKey.PublicKey, nil
}

// Compare checks 2 sets of private keys
func (pks PrivateKeys) Compare(other PrivateKeys) (same bool) {
	if len(pks) != len(other) {
		return false
	}

	for index, key := range pks {
		otherKey, exists := other[index]
		if !exists {
			return false
		}
		if key.algorithm != otherKey.algorithm {
			return false
		}
		if key.algorithm == AlgorithmMLKEM768 {
			if !bytes.Equal(key.privateKeyPem, otherKey.privateKeyPem) {
				return false
			}
			continue
		}
		if !key.privateKey.Equal(otherKey.privateKey) {
			return false
		}
	}

	return true
}

// AsSecretData returns the private keys as a map of string to byte slices.
// This is used when we need to persist the secret data in some form,
// such as storing it in a database or passing it through an API call.
//
// @return data A map where each key is the path to the corresponding private key
//
//	and the value is the PEM encoded representation of that key.
func (pks PrivateKeys) AsSecretData() (data map[string][]byte) {
	data = map[string][]byte{}
	for key, value := range pks {
		data[key] = value.privateKeyPem
	}
	return data
}

// A PrivateKey is used for decryption of encrypted secrets. Algorithm identifies which scheme it belongs
// to (AlgorithmRSAOAEP or AlgorithmMLKEM768); only the corresponding key field(s) below are populated --
// AlgorithmMLKEM768 populates both x25519PrivateKey and mlkemPrivateKey, since that scheme combines the
// two (see hybrid.go).
type PrivateKey struct {
	timestamp        time.Time
	fingerprint      string
	privateKeyPem    []byte
	privateKey       *rsa.PrivateKey
	algorithm        string
	x25519PrivateKey *ecdh.PrivateKey
	mlkemPrivateKey  *mlkem768.PrivateKey
	isCurrent        bool
}

// GetID returns an ID generated from public key has and date of insertion
func (pk PrivateKey) GetID() string {
	return fmt.Sprintf("%s-%s", pk.fingerprint[:hashLen], pk.timestamp.Format("2006-01-02"))
}

// NewPrivateKeyFromFile returns a CryptPrivateKey from a privateKeyFilePath
func NewPrivateKeyFromFile(privateKeyPath string) (*PrivateKey, error) {
	var privateKeyPem []byte
	var err error

	if privateKeyPath == "" {
		return nil, errors.New("cannot get private key without a specified path")
	}
	fi, err := os.Stat(privateKeyPath)
	if err != nil {
		return nil, err
	}
	if privateKeyPem, err = os.ReadFile(privateKeyPath); err != nil {
		return nil, err
	}

	pk, err := NewPrivateKeyFromPem(privateKeyPath, privateKeyPem)
	if err != nil {
		return nil, err
	}
	pk.timestamp = fi.ModTime()
	return pk, nil
}

// NewPrivateKeyFromPem returns a CryptPrivateKey from a privateKeyFilePath
func NewPrivateKeyFromPem(privateKeyPath string, privateKeyPem []byte) (*PrivateKey, error) {
	block, _ := pem.Decode(privateKeyPem)
	if block == nil {
		return nil, errors.New("error while decoding PEM")
	}

	isCurrent := filepath.Base(privateKeyPath) == "current"
	if isCurrent {
		isCurrent = true
	}

	if block.Type == mlkemPrivateKeyPEMType {
		return newMLKEM768PrivateKeyFromPem(privateKeyPem, block, isCurrent)
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		genericKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		var ok bool
		key, ok = genericKey.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("geen RSA private key gevonden in PKCS8 block")
		}
	}

	return &PrivateKey{
		timestamp:     time.Now(),
		fingerprint:   fmt.Sprintf("%x", sha256.Sum256(key.N.Bytes())),
		privateKeyPem: privateKeyPem,
		privateKey:    key,
		algorithm:     AlgorithmRSAOAEP,
		isCurrent:     isCurrent,
	}, nil
}

// newMLKEM768PrivateKeyFromPem parses the combined X25519+ML-KEM-768 private key packed into
// block.Bytes: the first x25519KeySize bytes are the raw X25519 scalar, followed by the packed
// ML-KEM-768 private key.
func newMLKEM768PrivateKeyFromPem(privateKeyPem []byte, block *pem.Block, isCurrent bool) (*PrivateKey, error) {
	wantSize := x25519KeySize + mlkem768.PrivateKeySize
	if len(block.Bytes) != wantSize {
		return nil, fmt.Errorf("invalid x25519+ml-kem-768 private key size: got %d, want %d",
			len(block.Bytes), wantSize)
	}

	x25519Priv, err := ecdh.X25519().NewPrivateKey(block.Bytes[:x25519KeySize])
	if err != nil {
		return nil, fmt.Errorf("x25519 private key invalid: %w", err)
	}

	key, err := mlkem768.Scheme().UnmarshalBinaryPrivateKey(block.Bytes[x25519KeySize:])
	if err != nil {
		return nil, fmt.Errorf("ml-kem-768 private key invalid: %w", err)
	}
	mlkemKey, ok := key.(*mlkem768.PrivateKey)
	if !ok {
		return nil, errors.New("unexpected ml-kem-768 key type")
	}
	pub, ok := mlkemKey.Public().(*mlkem768.PublicKey)
	if !ok {
		return nil, errors.New("unable to derive ml-kem-768 public key")
	}
	mlkemPubPacked := make([]byte, mlkem768.PublicKeySize)
	pub.Pack(mlkemPubPacked)

	fingerprint := sha256.Sum256(append(append([]byte{}, x25519Priv.PublicKey().Bytes()...), mlkemPubPacked...))

	return &PrivateKey{
		timestamp:        time.Now(),
		fingerprint:      fmt.Sprintf("%x", fingerprint),
		privateKeyPem:    privateKeyPem,
		algorithm:        AlgorithmMLKEM768,
		x25519PrivateKey: x25519Priv,
		mlkemPrivateKey:  mlkemKey,
		isCurrent:        isCurrent,
	}, nil
}

// WritePrivateKey writes a private key to a file at the specified path.
func (pk PrivateKey) WritePrivateKey(path string) error {
	if path == "" {
		return nil
	}

	var privateKeyPEM []byte
	if pk.algorithm == AlgorithmMLKEM768 {
		mlkemPacked := make([]byte, mlkem768.PrivateKeySize)
		pk.mlkemPrivateKey.Pack(mlkemPacked)
		combined := append(append([]byte{}, pk.x25519PrivateKey.Bytes()...), mlkemPacked...)
		privateKeyPEM = pem.EncodeToMemory(&pem.Block{Type: mlkemPrivateKeyPEMType, Bytes: combined})
	} else {
		privateKeyBytes := x509.MarshalPKCS1PrivateKey(pk.privateKey)
		privateKeyPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privateKeyBytes,
		})
	}

	if err := os.WriteFile(path, privateKeyPEM, fileModeUserReadWrite); err != nil {
		return fmt.Errorf("unable to write private key: %w", err)
	}
	fmt.Printf("Private key written to %s\n", path)
	return nil
}

// WritePublicKey writes the public key belonging to the private key to a file.
//
// If a path was specified when creating the Crypt object, the public key will be written
// to that location. The format used is PEM-encoded ASN.1 (RFC 1421) for RSA keys, or a PEM
// block carrying the raw packed key for ML-KEM-768 keys.
func (pk PrivateKey) WritePublicKey(path string) error {
	if path == "" {
		return nil
	}

	var publicKeyPEM []byte

	if pk.algorithm == AlgorithmMLKEM768 {
		mlkemPub, ok := pk.mlkemPrivateKey.Public().(*mlkem768.PublicKey)
		if !ok {
			return errors.New("invalid ml-kem-768 private key")
		}
		mlkemPacked := make([]byte, mlkem768.PublicKeySize)
		mlkemPub.Pack(mlkemPacked)
		combined := append(append([]byte{}, pk.x25519PrivateKey.PublicKey().Bytes()...), mlkemPacked...)
		publicKeyPEM = pem.EncodeToMemory(&pem.Block{Type: mlkemPublicKeyPEMType, Bytes: combined})
	} else {
		publicKeyBytes, err := x509.MarshalPKIXPublicKey(&pk.privateKey.PublicKey)
		if err != nil {
			return fmt.Errorf("unable to marshal public key: %w", err)
		}
		publicKeyPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: publicKeyBytes,
		})
	}

	if err := os.WriteFile(path, publicKeyPEM, fileModeUserReadWrite); err != nil {
		return fmt.Errorf("unable to write public key: %w", err)
	}

	fmt.Printf("Public key written to %s\n", path)
	return nil
}

// getPrivateKey returns the rsa.PrivateKey from the provided CryptPrivateKey.
//
// If it is not set yet, it will try to load it from the specified filePath. It
// also checks whether it is a valid PrivateKey.
func (pk *PrivateKey) getPrivateKey() (privateKey *rsa.PrivateKey, err error) {
	var privateRsaKey *rsa.PrivateKey

	// if privateKey is already loaded, return it from the CryptPrivateKey
	if pk.privateKey != nil {
		return pk.privateKey, nil
	} else if len(pk.privateKeyPem) == 0 {
		return nil, errors.New("invalid private key (Pem not set)")
	}

	// load privateKey from privateKeyPem
	if privateKeyBlock, _ := pem.Decode(pk.privateKeyPem); privateKeyBlock == nil {
		return nil, errors.New("cannot decode private key")
		// sanity check if the privatekey is a valid one
	} else if privateRsaKey, err = x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes); err != nil {
		return nil, fmt.Errorf("private key invalid: %w", err)
	}

	pk.privateKey = privateRsaKey
	return pk.privateKey, nil
}

// DecryptRsa decrypts data that was previously encrypted using RSA.
//
// Decryption is performed blockwise to prevent exceeding the maximum size for a
// single AES encryption operation.
//
// For an input message of length msgLen, it will attempt to process in chunks of
// step bytes, where step is the size of the private key.
func (pk *PrivateKey) DecryptRsa(data []byte, encryptionContext []byte) (decryptedBytes []byte, err error) {
	var privateKey *rsa.PrivateKey

	if privateKey, err = pk.getPrivateKey(); err != nil {
		return nil, err
	}

	hash := sha512.New()
	msgLen := len(data)
	step := privateKey.Size()
	random := rand.Reader

	for start := 0; start < msgLen; start += step {
		finish := min(start+step, msgLen)

		decryptedBlockBytes, err := rsa.DecryptOAEP(hash, random, privateKey, data[start:finish], encryptionContext)
		if err != nil {
			return nil, err
		}
		decryptedBytes = append(decryptedBytes, decryptedBlockBytes...)
	}
	return decryptedBytes, nil
}

// GeneratePrivateKey generates and returns a private key
func GeneratePrivateKey() (*PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, AESKeySize)
	if err != nil {
		return nil, fmt.Errorf("unable to generate private key: %w", err)
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	var pemBuffer bytes.Buffer
	err = pem.Encode(&pemBuffer, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	if err != nil {
		fmt.Printf("Error: %v", err)
		return nil, err
	}

	pubBytes := sha256.Sum256(privateKey.N.Bytes())
	fingerprint := fmt.Sprintf("%x", pubBytes)

	timestamp := time.Now()

	pk := PrivateKey{
		fingerprint:   fingerprint,
		timestamp:     timestamp,
		privateKey:    privateKey,
		privateKeyPem: pemBuffer.Bytes(),
		algorithm:     AlgorithmRSAOAEP,
	}
	return &pk, nil
}

// GenerateMLKEM768PrivateKey generates a new combined X25519+ML-KEM-768 (FIPS 203) key pair for the
// post-quantum hybrid scheme (see hybrid.go). It mirrors GeneratePrivateKey's shape so both algorithms
// can live side by side in the same PrivateKeys map, e.g. during a key-rotation migration via
// 'kubectl-paas reencrypt'.
func GenerateMLKEM768PrivateKey() (*PrivateKey, error) {
	x25519Priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("unable to generate x25519 private key: %w", err)
	}

	mlkemPub, mlkemPriv, err := mlkem768.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("unable to generate ml-kem-768 private key: %w", err)
	}

	mlkemPacked := make([]byte, mlkem768.PrivateKeySize)
	mlkemPriv.Pack(mlkemPacked)
	combined := append(append([]byte{}, x25519Priv.Bytes()...), mlkemPacked...)
	var pemBuffer bytes.Buffer
	if err := pem.Encode(&pemBuffer, &pem.Block{Type: mlkemPrivateKeyPEMType, Bytes: combined}); err != nil {
		return nil, fmt.Errorf("unable to encode x25519+ml-kem-768 private key: %w", err)
	}

	mlkemPubPacked := make([]byte, mlkem768.PublicKeySize)
	mlkemPub.Pack(mlkemPubPacked)
	fingerprintInput := append(append([]byte{}, x25519Priv.PublicKey().Bytes()...), mlkemPubPacked...)
	fingerprint := fmt.Sprintf("%x", sha256.Sum256(fingerprintInput))

	return &PrivateKey{
		fingerprint:      fingerprint,
		timestamp:        time.Now(),
		algorithm:        AlgorithmMLKEM768,
		x25519PrivateKey: x25519Priv,
		mlkemPrivateKey:  mlkemPriv,
		privateKeyPem:    pemBuffer.Bytes(),
	}, nil
}
