/*
Copyright 2023, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package crypt

import (
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRsaGenerate(t *testing.T) {
	context := "context"
	priv, err := os.CreateTemp("", "private")
	require.NoError(t, err, "Creating tempfile for private key")
	defer os.Remove(priv.Name()) // clean up

	pub, err := os.CreateTemp("", "public")
	require.NoError(t, err, "Creating tempfile for public key")
	defer os.Remove(pub.Name()) // clean up

	c, err := NewGeneratedCrypt(priv.Name(), pub.Name(), context)
	require.NoError(t, err, "Crypt object created")
	assert.NotNil(t, c, "Crypt object is not nil")
}

func TestRsa(t *testing.T) {
	context := "context"

	// generate private/public keys
	priv, err := os.CreateTemp("", "private")
	require.NoError(t, err, "Creating tempfile for private key")
	defer os.Remove(priv.Name()) // clean up

	pub, err := os.CreateTemp("", "public")
	require.NoError(t, err, "Creating tempfile for public key")
	defer os.Remove(pub.Name()) // clean up

	c, err := NewGeneratedCrypt(priv.Name(), pub.Name(), context)

	require.NoError(t, err, "Getting New Crypt")

	original := "WOEPTIDOE"

	encrypted, err := c.EncryptRsa([]byte(original))
	require.NoError(t, err, "Encrypting data")

	decrypted, err := c.DecryptRsa(encrypted)
	require.NoError(t, err, "Decrypting data")
	assert.Equal(t, string(decrypted), string(original))
}

func TestEncryptingAndDecrypting(t *testing.T) {
	const (
		minimalEncryptedLength = 100
	)
	var (
		original = "Dit is een test"
		context1 = "context1"
		context2 = "context2"
	)

	// generate private/public keys
	priv, err := os.CreateTemp("", "private")
	require.NoError(t, err, "Creating tempfile for private key")
	defer os.Remove(priv.Name()) // clean up

	pub, err := os.CreateTemp("", "public")
	require.NoError(t, err, "Creating tempfile for public key")
	defer os.Remove(pub.Name()) // clean up

	c, err := NewGeneratedCrypt(priv.Name(), pub.Name(), context1)
	require.NoError(t, err, "Getting New Crypt")

	encrypted, err := c.Encrypt([]byte(original))
	require.NoError(t, err, "Encrypting")
	assert.Greater(t, len(encrypted), minimalEncryptedLength)

	decrypted, err := c.Decrypt(encrypted)
	require.NoError(t, err, "Decrypting")
	assert.Equal(t, original, string(decrypted))

	c.encryptionContext = []byte(context2)
	_, err = c.Decrypt(encrypted)
	require.Error(t, err, "Decrypting with other context")
	encrypted, err = c.Encrypt([]byte(original))
	require.NoError(t, err, "Encrypting with other context should succeed")
	decrypted, err = c.Decrypt(encrypted)
	require.NoError(t, err, "Decrypting with other context")
	assert.Equal(t, original, string(decrypted))
}

func TestNewCryptFromKeysWithPublicKeyPath(t *testing.T) {
	context := "context"
	original := "Dit is een test"

	priv, err := os.CreateTemp("", "private")
	require.NoError(t, err, "Creating tempfile for private key")
	defer os.Remove(priv.Name()) // clean up

	pub, err := os.CreateTemp("", "public")
	require.NoError(t, err, "Creating tempfile for public key")
	defer os.Remove(pub.Name()) // clean up

	_, err = NewGeneratedCrypt(priv.Name(), pub.Name(), context)
	require.NoError(t, err, "Generating keys")

	privateKeys, err := NewPrivateKeysFromFiles([]string{priv.Name()})
	require.NoError(t, err, "Reading private key")

	c, err := NewCryptFromKeys(privateKeys, pub.Name(), context)
	require.NoError(t, err, "Getting New Crypt from public key path")

	encrypted, err := c.Encrypt([]byte(original))
	require.NoError(t, err, "Encrypting")

	decrypted, err := c.Decrypt(encrypted)
	require.NoError(t, err, "Decrypting")
	assert.Equal(t, original, string(decrypted))
}

func TestNewCryptFromKeysWithEmptyPublicKeyPath(t *testing.T) {
	context := "context"

	priv1, err := os.CreateTemp("", "private1")
	require.NoError(t, err, "Creating tempfile for first private key")
	defer os.Remove(priv1.Name()) // clean up

	pub1, err := os.CreateTemp("", "public1")
	require.NoError(t, err, "Creating tempfile for first public key")
	defer os.Remove(pub1.Name()) // clean up

	priv2, err := os.CreateTemp("", "private2")
	require.NoError(t, err, "Creating tempfile for second private key")
	defer os.Remove(priv2.Name()) // clean up

	pub2, err := os.CreateTemp("", "public2")
	require.NoError(t, err, "Creating tempfile for second public key")
	defer os.Remove(pub2.Name()) // clean up

	_, err = NewGeneratedCrypt(priv1.Name(), pub1.Name(), context)
	require.NoError(t, err, "Generating first key")
	_, err = NewGeneratedCrypt(priv2.Name(), pub2.Name(), context)
	require.NoError(t, err, "Generating second key")

	privateKeys, err := NewPrivateKeysFromFiles([]string{priv1.Name(), priv2.Name()})
	require.NoError(t, err, "Reading private keys")

	c, err := NewCryptFromKeys(privateKeys, "", context)
	require.NoError(t, err, "Getting New Crypt without public key")
	assert.NotNil(t, c)
	assert.Nil(t, c.publicKey)
}

func TestNewCryptFromKeysWithNilPublicKey(t *testing.T) {
	context := "context"
	original := "Dit is een test"

	priv, err := os.CreateTemp("", "private")
	require.NoError(t, err, "Creating tempfile for private key")
	defer os.Remove(priv.Name()) // clean up

	pub, err := os.CreateTemp("", "public")
	require.NoError(t, err, "Creating tempfile for public key")
	defer os.Remove(pub.Name()) // clean up

	_, err = NewGeneratedCrypt(priv.Name(), pub.Name(), context)
	require.NoError(t, err, "Generating keys")

	privateKeys, err := NewPrivateKeysFromFiles([]string{priv.Name()})
	require.NoError(t, err, "Reading private key")

	c, err := NewCryptFromKeys(privateKeys, nil, context)
	require.NoError(t, err, "Getting New Crypt without public key")
	assert.Nil(t, c.publicKey)

	encrypted, err := c.Encrypt([]byte(original))
	require.NoError(t, err, "Encrypting with public key derived from private key")

	decrypted, err := c.Decrypt(encrypted)
	require.NoError(t, err, "Decrypting")
	assert.Equal(t, original, string(decrypted))
}

const (
	secretTestContext = "my-paas"
	secretTestData    = "WOEPTIDOE"
)

// generatedSecretData returns keys secret data shaped like the output of `kubectl-paas generate`: every key
// under its ID, and the current key also under "current".
func generatedSecretData(current *PrivateKey, others ...*PrivateKey) map[string][]byte {
	pks := PrivateKeys{"current": current, current.GetID(): current}
	for _, pk := range others {
		pks[pk.GetID()] = pk
	}
	return pks.AsSecretData()
}

func encryptWithSecretData(t *testing.T, data map[string][]byte) (*Crypt, string) {
	t.Helper()
	keys, err := NewPrivateKeysFromSecretData(data)
	require.NoError(t, err)
	c, err := NewCryptFromKeys(keys, nil, secretTestContext)
	require.NoError(t, err)
	encrypted, err := c.Encrypt([]byte(secretTestData))
	require.NoError(t, err, "encrypting with keys from secret data")
	return c, encrypted
}

func decryptWithKey(t *testing.T, pk *PrivateKey, encrypted string) ([]byte, error) {
	t.Helper()
	c, err := NewCryptFromKeys(PrivateKeys{"only": pk}, nil, secretTestContext)
	require.NoError(t, err)
	return c.Decrypt(encrypted)
}

func TestNewPrivateKeysFromSecretDataMarksCurrent(t *testing.T) {
	pk, err := GeneratePrivateKey()
	require.NoError(t, err)

	keys, err := NewPrivateKeysFromSecretData(generatedSecretData(pk))
	require.NoError(t, err)
	assert.True(t, keys["current"].isCurrent, "entry named current is the current key")
	assert.False(t, keys[pk.GetID()].isCurrent, "entry named by ID is not marked current")

	pub, err := keys.PublicKey()
	require.NoError(t, err)
	assert.Equal(t, &pk.privateKey.PublicKey, pub)
}

func TestEncryptWithGeneratedSecretData(t *testing.T) {
	pk, err := GeneratePrivateKey()
	require.NoError(t, err)

	c, encrypted := encryptWithSecretData(t, generatedSecretData(pk))
	decrypted, err := c.Decrypt(encrypted)
	require.NoError(t, err)
	assert.Equal(t, secretTestData, string(decrypted))
}

func TestEncryptWithRotatedSecretData(t *testing.T) {
	oldKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	newKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	data := generatedSecretData(newKey, oldKey)

	// New data is encrypted with the current (new) key only.
	_, encrypted := encryptWithSecretData(t, data)
	decrypted, err := decryptWithKey(t, newKey, encrypted)
	require.NoError(t, err)
	assert.Equal(t, secretTestData, string(decrypted))
	_, err = decryptWithKey(t, oldKey, encrypted)
	require.Error(t, err, "old key cannot decrypt data encrypted after rotation")

	// Data encrypted with the old key still decrypts with the rotated secret.
	oldCrypt, err := NewCryptFromKeys(PrivateKeys{"current": oldKey}, nil, secretTestContext)
	require.NoError(t, err)
	oldEncrypted, err := oldCrypt.Encrypt([]byte(secretTestData))
	require.NoError(t, err)
	keys, err := NewPrivateKeysFromSecretData(data)
	require.NoError(t, err)
	rotated, err := NewCryptFromKeys(keys, nil, secretTestContext)
	require.NoError(t, err)
	decrypted, err = rotated.Decrypt(oldEncrypted)
	require.NoError(t, err)
	assert.Equal(t, secretTestData, string(decrypted))
}

func TestEncryptWithSingleEntrySecretData(t *testing.T) {
	pk, err := GeneratePrivateKey()
	require.NoError(t, err)

	_, encrypted := encryptWithSecretData(t, PrivateKeys{pk.GetID(): pk}.AsSecretData())
	decrypted, err := decryptWithKey(t, pk, encrypted)
	require.NoError(t, err)
	assert.Equal(t, secretTestData, string(decrypted))
}

func TestGetPublicKeyWithoutCurrentWrapsError(t *testing.T) {
	pk1, err := GeneratePrivateKey()
	require.NoError(t, err)
	pk2, err := GeneratePrivateKey()
	require.NoError(t, err)

	keys, err := NewPrivateKeysFromSecretData(PrivateKeys{"a": pk1, "b": pk2}.AsSecretData())
	require.NoError(t, err)
	c, err := NewCryptFromKeys(keys, nil, secretTestContext)
	require.NoError(t, err)

	_, err = c.GetPublicKey()
	require.Error(t, err)
	require.Error(t, errors.Unwrap(err), "error from private keys is wrapped")
	assert.NotContains(t, err.Error(), "%!", "error message is not garbled")
	assert.Contains(t, err.Error(), "unless there is a 'current' key")
}
