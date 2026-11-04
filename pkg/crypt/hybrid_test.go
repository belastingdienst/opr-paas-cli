/*
Copyright 2026, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package crypt

import (
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/mlkem"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeMLKEMKeyPair generates an ML-KEM-768 key pair and writes both halves to temp files, returning
// their paths (and registering cleanup via t.Cleanup).
func writeMLKEMKeyPair(t *testing.T) (privPath, pubPath string, pk *PrivateKey) {
	t.Helper()

	priv, err := os.CreateTemp("", "mlkem-private")
	require.NoError(t, err)
	t.Cleanup(func() { os.Remove(priv.Name()) })

	pub, err := os.CreateTemp("", "mlkem-public")
	require.NoError(t, err)
	t.Cleanup(func() { os.Remove(pub.Name()) })

	pk, err = GenerateMLKEM768PrivateKey()
	require.NoError(t, err, "generating ML-KEM-768 key pair")

	require.NoError(t, pk.WritePrivateKey(priv.Name()))
	require.NoError(t, pk.WritePublicKey(pub.Name()))

	return priv.Name(), pub.Name(), pk
}

func TestMLKEM768Generate(t *testing.T) {
	pk, err := GenerateMLKEM768PrivateKey()
	require.NoError(t, err)
	assert.Equal(t, AlgorithmMLKEM768, pk.algorithm)
	require.NotNil(t, pk.hybridKey)
	assert.Equal(t, hpke.MLKEM768X25519().ID(), pk.hybridKey.KEM().ID(), "key must be MLKEM768-X25519 (X-Wing)")
}

// TestMLKEM768KeyFileFormat checks the on-disk format: the private key PEM holds the 32-byte X-Wing seed
// and the public key PEM the 1,216-byte X-Wing encapsulation key, and both load back to the same key.
func TestMLKEM768KeyFileFormat(t *testing.T) {
	const (
		seedSize      = 32
		publicKeySize = 1216
	)
	privPath, pubPath, pk := writeMLKEMKeyPair(t)

	privPem, err := os.ReadFile(privPath)
	require.NoError(t, err)
	privBlock, _ := pem.Decode(privPem)
	require.NotNil(t, privBlock)
	assert.Equal(t, mlkemPrivateKeyPEMType, privBlock.Type)
	assert.Len(t, privBlock.Bytes, seedSize)

	pubPem, err := os.ReadFile(pubPath)
	require.NoError(t, err)
	pubBlock, _ := pem.Decode(pubPem)
	require.NotNil(t, pubBlock)
	assert.Equal(t, mlkemPublicKeyPEMType, pubBlock.Type)
	assert.Len(t, pubBlock.Bytes, publicKeySize)

	reloaded, err := NewPrivateKeyFromFile(privPath)
	require.NoError(t, err)
	assert.Equal(t, pk.fingerprint, reloaded.fingerprint, "a reloaded key must have the same fingerprint")
	assert.Equal(t, pubBlock.Bytes, reloaded.hybridKey.PublicKey().Bytes())
}

// TestMLKEM768EncryptDecrypt mirrors TestEncryptingAndDecrypting (the RSA case) for the new hybrid
// scheme: round-trips a secret through Crypt.Encrypt/Decrypt, and confirms a mismatched encryption
// context fails closed the same way it does for RSA.
func TestMLKEM768EncryptDecrypt(t *testing.T) {
	const (
		minimalEncryptedLength = 100
		original               = "Dit is een test"
		context1               = "context1"
		context2               = "context2"
	)

	privPath, pubPath, _ := writeMLKEMKeyPair(t)

	privateKeys, err := NewPrivateKeysFromFiles([]string{privPath})
	require.NoError(t, err)

	c, err := NewCryptFromKeys(privateKeys, pubPath, context1)
	require.NoError(t, err)

	encrypted, err := c.Encrypt([]byte(original))
	require.NoError(t, err, "encrypting")
	assert.Greater(t, len(encrypted), minimalEncryptedLength)
	assert.True(t, isHybridCiphertext(mustBase64Decode(t, encrypted)),
		"ciphertext produced with an ML-KEM-768 key must carry the hybrid envelope")

	decrypted, err := c.Decrypt(encrypted)
	require.NoError(t, err, "decrypting")
	assert.Equal(t, original, string(decrypted))

	wrongContext, err := NewCryptFromKeys(privateKeys, pubPath, context2)
	require.NoError(t, err)
	_, err = wrongContext.Decrypt(encrypted)
	require.Error(t, err, "decrypting with the wrong context must fail, exactly like the RSA scheme")
}

// TestMLKEM768RoundTripWithoutPublicKeyFile exercises the same "derive the current key from the private
// keys map" path NewCryptFromKeysWithNilPublicKey exercises for RSA, confirming it also works when that
// current key is an ML-KEM-768 key rather than an RSA key.
func TestMLKEM768RoundTripWithoutPublicKeyFile(t *testing.T) {
	const original = "Dit is een test"

	privPath, _, _ := writeMLKEMKeyPair(t)

	privateKeys, err := NewPrivateKeysFromFiles([]string{privPath})
	require.NoError(t, err)

	c, err := NewCryptFromKeys(privateKeys, nil, "context")
	require.NoError(t, err)
	assert.Nil(t, c.publicKey)
	assert.Nil(t, c.hybridPublicKey)

	encrypted, err := c.Encrypt([]byte(original))
	require.NoError(t, err, "encrypting with public key derived from the ML-KEM-768 private key")

	decrypted, err := c.Decrypt(encrypted)
	require.NoError(t, err)
	assert.Equal(t, original, string(decrypted))
}

// TestBackwardCompatDecryptExistingRsaSecretsAfterAddingMLKEMKey is the crux compatibility check for
// this migration: a PrivateKeys map that holds BOTH an old RSA key and a newly rotated-in ML-KEM-768
// "current" key must still decrypt secrets that were encrypted before the rotation (old RSA
// ciphertext), and also decrypt secrets encrypted after it (new hybrid ciphertext) — exactly the
// situation the 'reencrypt' command's key-rotation flow produces mid-migration.
func TestBackwardCompatDecryptExistingRsaSecretsAfterAddingMLKEMKey(t *testing.T) {
	const original = "Dit is een test"

	rsaPriv, err := os.CreateTemp("", "rsa-private")
	require.NoError(t, err)
	defer os.Remove(rsaPriv.Name())
	rsaPub, err := os.CreateTemp("", "rsa-public")
	require.NoError(t, err)
	defer os.Remove(rsaPub.Name())

	rsaCrypt, err := NewGeneratedCrypt(rsaPriv.Name(), rsaPub.Name(), "context")
	require.NoError(t, err)

	// Secret encrypted before the migration, under the old RSA key.
	legacyCiphertext, err := rsaCrypt.Encrypt([]byte(original))
	require.NoError(t, err)

	mlkemPk, err := GenerateMLKEM768PrivateKey()
	require.NoError(t, err)
	mlkemPk.isCurrent = true

	rsaKeys, err := NewPrivateKeysFromFiles([]string{rsaPriv.Name()})
	require.NoError(t, err)

	mixed := PrivateKeys{}
	for id, pk := range rsaKeys {
		mixed[id] = pk
	}
	mixed["mlkem-current"] = mlkemPk

	c, err := NewCryptFromKeys(mixed, nil, "context")
	require.NoError(t, err)

	// The old ciphertext must still decrypt via the RSA key that is still present in the map.
	decrypted, err := c.Decrypt(legacyCiphertext)
	require.NoError(t, err, "existing RSA-encrypted secrets must keep decrypting after an ML-KEM-768 key is added")
	assert.Equal(t, original, string(decrypted))

	// New encryptions use the current (ML-KEM-768) key, and round-trip through the same mixed map.
	newCiphertext, err := c.Encrypt([]byte(original))
	require.NoError(t, err)
	assert.True(t, isHybridCiphertext(mustBase64Decode(t, newCiphertext)),
		"once an ML-KEM-768 key is marked current, new encryptions must use it, not the legacy RSA key")

	decryptedNew, err := c.Decrypt(newCiphertext)
	require.NoError(t, err)
	assert.Equal(t, original, string(decryptedNew))
}

// TestPrivateKeysCompareMixedAlgorithms guards against a nil-pointer panic in PrivateKeys.Compare (used
// by the opr-paas operator to detect when its decrypt-keys Secret changed) once that map can hold
// ML-KEM-768 entries, whose privateKey field is nil.
func TestPrivateKeysCompareMixedAlgorithms(t *testing.T) {
	mlkemPk, err := GenerateMLKEM768PrivateKey()
	require.NoError(t, err)

	a := PrivateKeys{"k": mlkemPk}
	b := PrivateKeys{"k": mlkemPk}
	assert.True(t, a.Compare(b), "identical ML-KEM-768 keys should compare equal")

	otherMlkemPk, err := GenerateMLKEM768PrivateKey()
	require.NoError(t, err)
	c := PrivateKeys{"k": otherMlkemPk}
	assert.False(t, a.Compare(c), "different ML-KEM-768 keys should not compare equal")

	rsaPk, err := GeneratePrivateKey()
	require.NoError(t, err)
	d := PrivateKeys{"k": rsaPk}
	assert.NotPanics(t, func() { a.Compare(d) })
	assert.False(t, a.Compare(d), "keys of different algorithms should never compare equal")
}

// TestHybridCiphertextRequiresBothComponents proves the ML-KEM-768 and X25519 halves of the X-Wing key
// both contribute: decryption must fail if either half doesn't match the key the ciphertext was
// encrypted for.
func TestHybridCiphertextRequiresBothComponents(t *testing.T) {
	const original = "Dit is een test"
	const context = "context"

	mlkemA, err := mlkem.GenerateKey768()
	require.NoError(t, err)
	mlkemB, err := mlkem.GenerateKey768()
	require.NoError(t, err)
	x25519A, err := ecdh.X25519().GenerateKey(nil)
	require.NoError(t, err)
	x25519B, err := ecdh.X25519().GenerateKey(nil)
	require.NoError(t, err)

	keyA, err := hpke.NewHybridPrivateKey(mlkemA, x25519A)
	require.NoError(t, err)
	wrongX25519, err := hpke.NewHybridPrivateKey(mlkemA, x25519B)
	require.NoError(t, err)
	wrongMLKEM, err := hpke.NewHybridPrivateKey(mlkemB, x25519A)
	require.NoError(t, err)

	ciphertext, err := hybridEncrypt(keyA.PublicKey(), []byte(original), []byte(context))
	require.NoError(t, err)

	decrypted, err := hybridDecrypt(keyA, ciphertext, []byte(context))
	require.NoError(t, err)
	assert.Equal(t, original, string(decrypted))

	_, err = hybridDecrypt(wrongX25519, ciphertext, []byte(context))
	assert.Error(t, err, "a mismatched X25519 half must not decrypt")

	_, err = hybridDecrypt(wrongMLKEM, ciphertext, []byte(context))
	assert.Error(t, err, "a mismatched ML-KEM-768 half must not decrypt")
}

// TestHybridCiphertextHeader checks that a ciphertext names its HPKE suite, and that a ciphertext with
// another suite or a damaged body is rejected with an error.
func TestHybridCiphertextHeader(t *testing.T) {
	pk, err := GenerateMLKEM768PrivateKey()
	require.NoError(t, err)
	pub, err := hybridPublicKeyFromPrivate(pk)
	require.NoError(t, err)

	ciphertext, err := hybridEncrypt(pub, []byte("secret"), []byte(testContext))
	require.NoError(t, err)
	require.True(t, isHybridCiphertext(ciphertext))

	kem, kdf, aead := hybridSuite()
	assert.Equal(t, hybridMagic, string(ciphertext[:len(hybridMagic)]))
	assert.Equal(t, kem.ID(), binary.BigEndian.Uint16(ciphertext[4:6]))
	assert.Equal(t, kdf.ID(), binary.BigEndian.Uint16(ciphertext[6:8]))
	assert.Equal(t, aead.ID(), binary.BigEndian.Uint16(ciphertext[8:10]))

	otherSuite := append([]byte{}, ciphertext...)
	binary.BigEndian.PutUint16(otherSuite[8:10], hpke.ChaCha20Poly1305().ID())
	_, err = hybridDecrypt(pk.hybridKey, otherSuite, []byte(testContext))
	assert.ErrorContains(t, err, "unsupported hybrid ciphersuite")

	damaged := append([]byte{}, ciphertext...)
	damaged[len(damaged)-1] ^= flipAllBits
	_, err = hybridDecrypt(pk.hybridKey, damaged, []byte(testContext))
	assert.Error(t, err, "a modified ciphertext must not decrypt")

	_, err = hybridDecrypt(pk.hybridKey, ciphertext[:hybridHeaderSize+10], []byte(testContext))
	assert.Error(t, err, "a truncated ciphertext must not decrypt")
}

// TestPublicKeyWithHybridCurrentKey checks that the RSA-only accessors return an error instead of
// panicking when the current key is a hybrid key.
func TestPublicKeyWithHybridCurrentKey(t *testing.T) {
	pk, err := GenerateMLKEM768PrivateKey()
	require.NoError(t, err)
	keys := PrivateKeys{"current": pk}

	assert.NotPanics(t, func() {
		_, err = keys.PublicKey()
	})
	assert.Error(t, err)

	c, err := NewCryptFromKeys(keys, nil, testContext)
	require.NoError(t, err)
	assert.NotPanics(t, func() {
		_, err = c.GetPublicKey()
	})
	assert.Error(t, err)

	encrypted, err := c.Encrypt([]byte("secret"))
	require.NoError(t, err, "Encrypt must still work with a hybrid current key")
	decrypted, err := c.Decrypt(encrypted)
	require.NoError(t, err)
	assert.Equal(t, "secret", string(decrypted))
}

// TestNewCryptFromKeysWithHybridPublicKey checks that an in-memory hybrid public key is accepted, and
// that a public key of another HPKE KEM is refused.
func TestNewCryptFromKeysWithHybridPublicKey(t *testing.T) {
	pk, err := GenerateMLKEM768PrivateKey()
	require.NoError(t, err)

	c, err := NewCryptFromKeys(PrivateKeys{"k": pk}, pk.hybridKey.PublicKey(), testContext)
	require.NoError(t, err)
	encrypted, err := c.Encrypt([]byte("secret"))
	require.NoError(t, err)
	assert.True(t, isHybridCiphertext(mustBase64Decode(t, encrypted)))

	other, err := hpke.MLKEM768().GenerateKey()
	require.NoError(t, err)
	_, err = NewCryptFromKeys(PrivateKeys{"k": pk}, other.PublicKey(), testContext)
	assert.Error(t, err)
}

const (
	// testContext is the encryption context (the Paas name in production) used by the hybrid tests.
	testContext = "context"
	// flipAllBits inverts a byte to simulate a modified ciphertext.
	flipAllBits = 0xff
)

func mustBase64Decode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	require.NoError(t, err)
	return b
}
