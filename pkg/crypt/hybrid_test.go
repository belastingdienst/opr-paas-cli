/*
Copyright 2026, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package crypt

import (
	"encoding/base64"
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
	assert.NotNil(t, pk.mlkemPrivateKey)
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

// TestHybridCiphertextRequiresBothComponents proves the X25519 and ML-KEM-768 halves of the combined
// scheme both actually contribute to the derived key -- decryption must fail if either private key
// doesn't match the one the ciphertext was encrypted for, confirming neither component is silently
// unused (i.e. this is a real combined hybrid, not ML-KEM-768 alone with inert X25519 bytes attached).
func TestHybridCiphertextRequiresBothComponents(t *testing.T) {
	const original = "Dit is een test"
	const context = "context"

	pkA, err := GenerateMLKEM768PrivateKey()
	require.NoError(t, err)
	pkB, err := GenerateMLKEM768PrivateKey()
	require.NoError(t, err)

	pubA, err := hybridPublicKeyFromPrivate(pkA)
	require.NoError(t, err)

	ciphertext, err := hybridEncrypt(pubA, []byte(original), []byte(context))
	require.NoError(t, err)

	// Correct key on both halves: decrypts.
	decrypted, err := hybridDecrypt(pkA.x25519PrivateKey, pkA.mlkemPrivateKey, ciphertext, []byte(context))
	require.NoError(t, err)
	assert.Equal(t, original, string(decrypted))

	// Wrong X25519 half (pkB's), correct ML-KEM-768 half (pkA's): must fail.
	_, err = hybridDecrypt(pkB.x25519PrivateKey, pkA.mlkemPrivateKey, ciphertext, []byte(context))
	assert.Error(t, err, "a mismatched X25519 private key must not decrypt -- the ECDH half must actually matter")

	// Correct X25519 half (pkA's), wrong ML-KEM-768 half (pkB's): must fail.
	_, err = hybridDecrypt(pkA.x25519PrivateKey, pkB.mlkemPrivateKey, ciphertext, []byte(context))
	assert.Error(t, err, "a mismatched ML-KEM-768 private key must not decrypt -- the KEM half must actually matter")
}

func mustBase64Decode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	require.NoError(t, err)
	return b
}
