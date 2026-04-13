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
// decryption tasks.
type Crypt struct {
	privateKeys       PrivateKeys
	publicKey         *rsa.PublicKey
	encryptionContext []byte
}

// Factory is an interface for creating Crypt objects.
type Factory interface {
	NewCryptFromFiles([]string, string, string) (Cryptor, error)
}

// NewCryptFromFiles returns a Crypt based on the provided privateKeyPaths and publicKeyPath using the encryptionContext
func NewCryptFromFiles(privateKeyPaths []string, publicKeyPath string, encryptionContext string) (*Crypt, error) {
	privateKeys, err := NewPrivateKeysFromFiles(privateKeyPaths)
	if err != nil {
		return nil, err
	}
	var pubKey *rsa.PublicKey
	if publicKeyPath != "" {
		pubKey, err = readPublicKeyFromDisk(publicKeyPath)
		if err != nil {
			return nil, err
		}
	}
	return &Crypt{
		privateKeys:       privateKeys,
		publicKey:         pubKey,
		encryptionContext: []byte(encryptionContext),
	}, nil
}

// NewCryptFromKeys returns a Crypt based on the provided privateKeys and publicKey (from memory) using the
// encryptionContext
func NewCryptFromKeys(privateKeys PrivateKeys, publicKey *rsa.PublicKey, encryptionContext string) (*Crypt, error) {
	if publicKey == nil {
		var err error
		if publicKey, err = privateKeys.PublicKey(); err != nil {
			return nil, err
		}
	}
	return &Crypt{
		privateKeys:       privateKeys,
		publicKey:         publicKey,
		encryptionContext: []byte(encryptionContext),
	}, nil
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

// readPublicKeyFromDisk retrieves and returns the public key from a file
func readPublicKeyFromDisk(path string) (*rsa.PublicKey, error) {
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

	if publicKeyPEM, err := os.ReadFile(path); err != nil {
		panic(err)
	} else if publicKeyBlock, _ := pem.Decode(publicKeyPEM); publicKeyBlock == nil {
		return nil, errors.New("cannot decode public key")
	} else if publicKey, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes); err != nil {
		return nil, fmt.Errorf("public key invalid: %w", err)
	} else if publicRsaKey, ok = publicKey.(*rsa.PublicKey); !ok {
		return nil, errors.New("public key not rsa public key")
	}
	return publicRsaKey, nil
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

// Encrypt encrypts the secret using asymmetric encryption and returns the result
// as a base64-encoded string.
func (c *Crypt) Encrypt(secret []byte) (encrypted string, err error) {
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
		if decryptedBytes, err = pk.DecryptRsa(data, c.encryptionContext); err != nil {
			continue
		}

		return decryptedBytes, nil
	}
	return nil, errors.New("unable to decrypt data with any of the private keys")
}

// Decrypt decrypts an asymmetrically encrypted message using base64.
func (c Crypt) Decrypt(b64 string) ([]byte, error) {
	var decrypted []byte

	// Removing all characters that do not comply to base64 encoding (mainly \n and ' ')
	re := regexp.MustCompile("[^ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=]")
	b64 = re.ReplaceAllLiteralString(b64, "")
	if asymEncrypted, err := base64.StdEncoding.DecodeString(b64); err != nil {
		return nil, err
	} else if decrypted, err = c.DecryptRsa(asymEncrypted); err != nil {
		return nil, err
	}

	return decrypted, nil
}
