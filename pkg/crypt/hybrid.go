/*
Copyright 2026, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package crypt

import (
	"crypto/hpke"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// AlgorithmRSAOAEP identifies the legacy scheme: RSA-OAEP applied directly, blockwise, to the
	// secret (see EncryptRsa/DecryptRsa in crypt.go and private_keys.go).
	AlgorithmRSAOAEP = "RSA-OAEP"

	// AlgorithmMLKEM768 identifies the post-quantum hybrid scheme implemented in this file: HPKE (RFC 9180)
	// with the MLKEM768-X25519 KEM (a.k.a. X-Wing, draft-ietf-hpke-pq), HKDF-SHA256 and AES-256-GCM, all
	// from the Go standard library (crypto/hpke). X-Wing combines ML-KEM-768 (FIPS 203) with X25519, so
	// confidentiality holds as long as either of the two holds. This follows the AIVD/CWI/TNO
	// PQC-migratiehandboek's recommendation to use ML-KEM in a hybrid construction (2nd edition,
	// Sec. 4.2.1 / Tabel 4.1). No cryptographic construction in this file is custom.
	AlgorithmMLKEM768 = "MLKEM768-X25519+HKDF-SHA256+AES-256-GCM"

	// The private key is stored as the 32-byte X-Wing seed (HPKE SerializePrivateKey); the public key as
	// the 1,216-byte X-Wing encapsulation key (HPKE SerializePublicKey).
	mlkemPrivateKeyPEMType = "MLKEM768-X25519 PRIVATE KEY"
	mlkemPublicKeyPEMType  = "MLKEM768-X25519 PUBLIC KEY"

	// hybridMagic tags a ciphertext produced by hybridEncrypt so Crypt.Decrypt can tell it apart from a
	// legacy raw RSA-OAEP ciphertext, which carries no header of its own. It is followed by the HPKE
	// KEM, KDF and AEAD identifiers (2 bytes each, big endian), so the suite can change later without a
	// new magic and a ciphertext names the algorithms that produced it.
	hybridMagic      = "PQH1"
	hybridHeaderSize = len(hybridMagic) + 6
)

// hybridSuite returns the HPKE ciphersuite used for new and existing hybrid ciphertexts.
func hybridSuite() (hpke.KEM, hpke.KDF, hpke.AEAD) {
	return hpke.MLKEM768X25519(), hpke.HKDFSHA256(), hpke.AES256GCM()
}

// hybridHeader returns the magic followed by the suite identifiers.
func hybridHeader() []byte {
	kem, kdf, aead := hybridSuite()
	header := make([]byte, 0, hybridHeaderSize)
	header = append(header, hybridMagic...)
	header = binary.BigEndian.AppendUint16(header, kem.ID())
	header = binary.BigEndian.AppendUint16(header, kdf.ID())
	header = binary.BigEndian.AppendUint16(header, aead.ID())
	return header
}

// unpackHybridPublicKey parses a serialized MLKEM768-X25519 public key, as written by WritePublicKey.
func unpackHybridPublicKey(packed []byte) (hpke.PublicKey, error) {
	kem, _, _ := hybridSuite()
	pub, err := kem.NewPublicKey(packed)
	if err != nil {
		return nil, fmt.Errorf("invalid MLKEM768-X25519 public key: %w", err)
	}
	return pub, nil
}

// hybridPublicKeyFromPrivate returns the public half of pk (which must have algorithm AlgorithmMLKEM768)
// for encrypting new data -- used when a Crypt has no explicitly configured public key and falls back to
// the current entry in its private keys (see Crypt.resolveEncryptionTarget).
func hybridPublicKeyFromPrivate(pk *PrivateKey) (hpke.PublicKey, error) {
	if pk.algorithm != AlgorithmMLKEM768 || pk.hybridKey == nil {
		return nil, errors.New("not an MLKEM768-X25519 private key")
	}
	return pk.hybridKey.PublicKey(), nil
}

// isHybridCiphertext reports whether raw starts like a ciphertext produced by hybridEncrypt.
func isHybridCiphertext(raw []byte) bool {
	return len(raw) > hybridHeaderSize && string(raw[:len(hybridMagic)]) == hybridMagic
}

// hybridEncrypt seals secret to pub with single-shot HPKE, binding encryptionContext as the HPKE info
// the same way EncryptRsa binds it as the RSA-OAEP label. The result is self-describing (header ||
// encapsulated key || AES-256-GCM ciphertext), so hybridDecrypt needs only the recipient's private key.
func hybridEncrypt(pub hpke.PublicKey, secret []byte, encryptionContext []byte) ([]byte, error) {
	_, kdf, aead := hybridSuite()
	sealed, err := hpke.Seal(pub, kdf, aead, encryptionContext, secret)
	if err != nil {
		return nil, fmt.Errorf("hybrid encryption failed: %w", err)
	}
	return append(hybridHeader(), sealed...), nil
}

// hybridDecrypt reverses hybridEncrypt with priv. It returns an error if raw is malformed, uses an
// unsupported suite, was encrypted for a different key, or was encrypted under a different
// encryptionContext.
func hybridDecrypt(priv hpke.PrivateKey, raw []byte, encryptionContext []byte) ([]byte, error) {
	if !isHybridCiphertext(raw) {
		return nil, errors.New("not a hybrid ciphertext")
	}
	kem, kdf, aead := hybridSuite()
	suite := raw[len(hybridMagic):hybridHeaderSize]
	if binary.BigEndian.Uint16(suite[0:2]) != kem.ID() ||
		binary.BigEndian.Uint16(suite[2:4]) != kdf.ID() ||
		binary.BigEndian.Uint16(suite[4:6]) != aead.ID() {
		return nil, errors.New("unsupported hybrid ciphersuite")
	}
	return hpke.Open(priv, kdf, aead, encryptionContext, raw[hybridHeaderSize:])
}
