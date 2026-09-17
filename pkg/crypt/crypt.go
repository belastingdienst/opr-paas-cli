/*
Copyright 2023, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package crypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"regexp"

	"github.com/belastingdienst/opr-paas-cli/v2/internal/utils"
)

// Cryptor allows you to de- and encrypt data easily for use in a Paas
type Cryptor interface {
	Decrypt(string) ([]byte, error)
	Encrypt([]byte) (string, error)
}

// AESKeySize is the key size of AES in bits.
const AESKeySize = 4096

// Crypt represents a cryptographic object that performs various encryption and
// decryption tasks. publicKey and hybridPublicKey are mutually exclusive: which one (if either) is set
// determines the algorithm used by Encrypt, mirroring PrivateKey's Algorithm tag.
type Crypt struct {
	privateKeys       PrivateKeys
	publicKey         *rsa.PublicKey
	hybridPublicKey   *hybridPublicKey
	encryptionContext []byte
}

// Factory is an interface for creating Crypt objects.
type Factory interface {
	NewCryptFromFiles([]string, string, string) (Cryptor, error)
}

// resolvedPublicKey carries the result of reading or resolving a public key of either supported
// algorithm; exactly one of its fields is set.
type resolvedPublicKey struct {
	rsaKey    *rsa.PublicKey
	hybridKey *hybridPublicKey
}

// NewCryptFromFiles returns a Crypt based on the provided privateKeyPaths and publicKeyPath using the encryptionContext
func NewCryptFromFiles(privateKeyPaths []string, publicKeyPath string, encryptionContext string) (*Crypt, error) {
	privateKeys, err := NewPrivateKeysFromFiles(privateKeyPaths)
	if err != nil {
		return nil, err
	}
	c := &Crypt{
		privateKeys:       privateKeys,
		encryptionContext: []byte(encryptionContext),
	}
	if publicKeyPath != "" {
		resolved, err := readPublicKeyFromDisk(publicKeyPath)
		if err != nil {
			return nil, err
		}
		c.publicKey = resolved.rsaKey
		c.hybridPublicKey = resolved.hybridKey
	}
	return c, nil
}

// NewCryptFromKeys returns a Crypt based on the provided privateKeys and publicKey using the encryptionContext.
//
// publicKey accepts the historical public key path string argument, a *rsa.PublicKey or *hybridPublicKey
// for in-memory keys, or nil to derive the public key from the private keys.
func NewCryptFromKeys(privateKeys PrivateKeys, publicKey any, encryptionContext string) (*Crypt, error) {
	resolved, err := resolvePublicKey(privateKeys, publicKey)
	if err != nil {
		return nil, err
	}

	c := &Crypt{
		privateKeys:       privateKeys,
		encryptionContext: []byte(encryptionContext),
	}
	if resolved != nil {
		c.publicKey = resolved.rsaKey
		c.hybridPublicKey = resolved.hybridKey
	}
	return c, nil
}

func resolvePublicKey(privateKeys PrivateKeys, publicKey any) (*resolvedPublicKey, error) {
	switch value := publicKey.(type) {
	case nil:
		return nil, nil
	case *rsa.PublicKey:
		if value == nil {
			return nil, nil
		}
		return &resolvedPublicKey{rsaKey: value}, nil
	case *hybridPublicKey:
		if value == nil {
			return nil, nil
		}
		return &resolvedPublicKey{hybridKey: value}, nil
	case string:
		if value == "" {
			return nil, nil
		}
		return readPublicKeyFromDisk(value)
	default:
		return nil, fmt.Errorf("unsupported public key type %T", publicKey)
	}
}

// NewGeneratedCrypt generates a new Crypt instance with randomly generated private
// and public key pairs.
//
// The keys are stored on disk at the specified paths, and can be retrieved via
// the returned Crypt instance.
//
// This method returns an error if it is unable to generate a valid key pair or
// write the keys to disk.
func NewGeneratedCrypt(privateKeyPath string, publicKeyPath string, context string) (*Crypt, error) {
	var err error

	c := Crypt{
		encryptionContext: []byte(context),
	}
	pk, err := GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	c.privateKeys = PrivateKeys{pk.GetID(): pk}
	if err = pk.WritePrivateKey(privateKeyPath); err != nil {
		return nil, err
	}
	if err = pk.WritePublicKey(publicKeyPath); err != nil {
		return nil, err
	}
	c.publicKey = &pk.privateKey.PublicKey
	return &c, nil
}

// readPublicKeyFromDisk retrieves and returns the public key from a file, detecting whether it is an
// RSA or a combined X25519+ML-KEM-768 key from its PEM block type.
func readPublicKeyFromDisk(path string) (*resolvedPublicKey, error) {
	var publicRsaKey *rsa.PublicKey
	var ok bool

	paths, err := utils.PathToFileList([]string{path})
	if err != nil {
		return nil, fmt.Errorf("could not find files in '%v': %w", path, err)
	}
	if len(paths) != 1 {
		return nil, fmt.Errorf("zero or more than one files at %s", path)
	}
	path = paths[0]

	publicKeyPEM, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	publicKeyBlock, _ := pem.Decode(publicKeyPEM)
	if publicKeyBlock == nil {
		return nil, errors.New("cannot decode public key")
	}

	if publicKeyBlock.Type == mlkemPublicKeyPEMType {
		hybridKey, err := unpackHybridPublicKey(publicKeyBlock.Bytes)
		if err != nil {
			return nil, err
		}
		return &resolvedPublicKey{hybridKey: hybridKey}, nil
	}

	if publicKey, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes); err != nil {
		return nil, fmt.Errorf("public key invalid: %w", err)
	} else if publicRsaKey, ok = publicKey.(*rsa.PublicKey); !ok {
		return nil, errors.New("public key not rsa public key")
	}
	return &resolvedPublicKey{rsaKey: publicRsaKey}, nil
}

// GetPublicKey returns the public key from a crypt
func (c *Crypt) GetPublicKey() (*rsa.PublicKey, error) {
	if c.publicKey != nil {
		return c.publicKey, nil
	}
	if c.privateKeys != nil {
		pubKey, err := c.privateKeys.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("no public key set, and error while retrieving from private keys: %e", err)
		}
		return pubKey, nil
	}
	return nil, errors.New("no public key and no private keys")
}

// EncryptRsa encrypts the provided secret using RSA-OAEP encryption with the public key.
func (c *Crypt) EncryptRsa(secret []byte) (encryptedBytes []byte, err error) {
	var publicKey *rsa.PublicKey
	var encryptedBlock []byte

	if publicKey, err = c.GetPublicKey(); err != nil {
		return nil, err
	}

	random := rand.Reader
	hash := sha512.New()
	msgLen := len(secret)
	step := publicKey.Size() - 2*hash.Size() - 2
	for start := 0; start < msgLen; start += step {
		finish := start + step
		if finish > msgLen {
			finish = msgLen
		}

		encryptedBlock, err = rsa.EncryptOAEP(hash, random, publicKey, secret[start:finish], c.encryptionContext)
		if err != nil {
			return nil, err
		}

		encryptedBytes = append(encryptedBytes, encryptedBlock...)
	}
	return encryptedBytes, nil
}

// resolveEncryptionTarget determines which algorithm/public key to encrypt new data with: an explicitly
// configured key on the Crypt (publicKey or hybridPublicKey), or, if neither was set, the sole/current
// entry in its private keys (the same selection PrivateKeys.currentKey applies for decryption-key
// rotation), whichever algorithm that entry happens to be.
func (c *Crypt) resolveEncryptionTarget() (*resolvedPublicKey, error) {
	if c.hybridPublicKey != nil {
		return &resolvedPublicKey{hybridKey: c.hybridPublicKey}, nil
	}
	if c.publicKey != nil {
		return &resolvedPublicKey{rsaKey: c.publicKey}, nil
	}
	if c.privateKeys == nil {
		return nil, errors.New("no public key and no private keys")
	}
	pk, err := c.privateKeys.currentKey()
	if err != nil {
		return nil, fmt.Errorf("no public key set, and error while retrieving from private keys: %w", err)
	}
	if pk.algorithm == AlgorithmMLKEM768 {
		hybridKey, err := hybridPublicKeyFromPrivate(pk)
		if err != nil {
			return nil, err
		}
		return &resolvedPublicKey{hybridKey: hybridKey}, nil
	}
	return &resolvedPublicKey{rsaKey: &pk.privateKey.PublicKey}, nil
}

// Encrypt encrypts the secret and returns the result as a base64-encoded string, using whichever
// algorithm resolveEncryptionTarget selects: the legacy RSA-OAEP scheme, or the X25519+ML-KEM-768+AES-
// 256-GCM hybrid scheme (see hybrid.go) when a current ML-KEM-768 key is configured.
func (c *Crypt) Encrypt(secret []byte) (encrypted string, err error) {
	target, err := c.resolveEncryptionTarget()
	if err != nil {
		return "", err
	}

	if target.hybridKey != nil {
		raw, err := hybridEncrypt(target.hybridKey, secret, c.encryptionContext)
		if err != nil {
			return "", err
		}
		return base64.StdEncoding.EncodeToString(raw), nil
	}

	var asymEncrypted []byte
	if asymEncrypted, err = c.EncryptRsa(secret); err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(asymEncrypted), nil
}

// DecryptRsa attempts to decrypt given data using RSA private keys.
// It will try each key until it successfully decrypts the data or runs out of keys.
func (c *Crypt) DecryptRsa(data []byte) (decryptedBytes []byte, err error) {
	if len(c.privateKeys) < 1 {
		return nil, errors.New("cannot decrypt without any private key")
	}
	for _, pk := range c.privateKeys {
		if pk.algorithm == AlgorithmMLKEM768 {
			continue
		}
		if decryptedBytes, err = pk.DecryptRsa(data, c.encryptionContext); err != nil {
			continue
		}

		return decryptedBytes, nil
	}
	return nil, errors.New("unable to decrypt data with any of the private keys")
}

// decryptHybrid attempts to decrypt raw (an X25519+ML-KEM-768+AES-256-GCM hybrid ciphertext) using each
// ML-KEM-768 private key until one succeeds or none are left.
func (c *Crypt) decryptHybrid(raw []byte) ([]byte, error) {
	if len(c.privateKeys) < 1 {
		return nil, errors.New("cannot decrypt without any private key")
	}
	for _, pk := range c.privateKeys {
		if pk.algorithm != AlgorithmMLKEM768 {
			continue
		}
		decrypted, err := hybridDecrypt(pk.x25519PrivateKey, pk.mlkemPrivateKey, raw, c.encryptionContext)
		if err == nil {
			return decrypted, nil
		}
	}
	return nil, errors.New("unable to decrypt hybrid ciphertext with any of the private keys")
}

// Decrypt decrypts a base64-encoded message produced by Encrypt, dispatching to the RSA-OAEP or
// X25519+ML-KEM-768+AES-256-GCM hybrid scheme depending on which one produced it (see isHybridCiphertext).
func (c Crypt) Decrypt(b64 string) ([]byte, error) {
	// Removing all characters that do not comply to base64 encoding (mainly \n and ' ')
	re := regexp.MustCompile("[^ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=]")
	b64 = re.ReplaceAllLiteralString(b64, "")

	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}

	if isHybridCiphertext(raw) {
		return c.decryptHybrid(raw)
	}
	return c.DecryptRsa(raw)
}
