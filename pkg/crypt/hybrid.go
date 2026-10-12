/*
Copyright 2026, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

const (
	// AlgorithmRSAOAEP identifies the legacy scheme: RSA-OAEP applied directly, blockwise, to the
	// secret (see EncryptRsa/DecryptRsa in crypt.go and private_keys.go).
	AlgorithmRSAOAEP = "RSA-OAEP"

	// AlgorithmMLKEM768 identifies the post-quantum hybrid scheme implemented in this file: an
	// ephemeral X25519 key agreement and an ML-KEM-768 (FIPS 203) key encapsulation each establish a
	// shared secret; both are concatenated and expanded via HKDF-SHA256 into an AES-256 key used to
	// AES-256-GCM-seal the actual secret. Combining a classical (X25519) and a post-quantum (ML-KEM-768)
	// key-establishment mechanism this way -- rather than using ML-KEM-768 alone -- follows the AIVD/
	// CWI/TNO PQC-migratiehandboek's own recommendation (2nd edition, Sec. 4.2.1 / Tabel 4.1, footnote
	// 1): it keeps confidentiality resting on X25519's long-studied hardness even if a future weakness
	// is found in ML-KEM-768's still-young lattice-based assumptions, and vice versa. X25519, ML-KEM-768
	// and AES-256-GCM are all standard, NIST/IETF-specified primitives; no cryptographic primitive here
	// is custom, only the composition combining them.
	AlgorithmMLKEM768 = "X25519+ML-KEM-768+AES-256-GCM"

	mlkemPrivateKeyPEMType = "X25519+ML-KEM-768 PRIVATE KEY"
	mlkemPublicKeyPEMType  = "X25519+ML-KEM-768 PUBLIC KEY"

	// hybridMagic tags a ciphertext produced by hybridEncrypt so Crypt.Decrypt can tell it apart from a
	// legacy raw RSA-OAEP ciphertext, which carries no header of its own.
	hybridMagic        = "PQH1"
	hybridGCMNonceSize = 12
	hybridAESKeySize   = 32

	// x25519KeySize is the fixed size, in bytes, of both an X25519 private scalar and an X25519 public
	// point -- crypto/ecdh doesn't export this as a constant, so it's named here for clarity at every
	// call site that packs/unpacks one.
	x25519KeySize = 32
)

// hybridPublicKey bundles the two public components a recipient must publish for the combined
// X25519+ML-KEM-768 scheme: an encrypter needs both to derive the same combined shared secret the
// recipient's PrivateKey can later reconstruct.
type hybridPublicKey struct {
	x25519 *ecdh.PublicKey
	mlkem  *mlkem768.PublicKey
}

// unpackHybridPublicKey parses the combined X25519+ML-KEM-768 public key packed into packed: the first
// x25519KeySize bytes are the raw X25519 point, followed by the packed ML-KEM-768 public key -- the
// mirror image of how WritePublicKey (private_keys.go) lays a PrivateKey's public half out on disk.
func unpackHybridPublicKey(packed []byte) (*hybridPublicKey, error) {
	wantSize := x25519KeySize + mlkem768.PublicKeySize
	if len(packed) != wantSize {
		return nil, fmt.Errorf("invalid x25519+ml-kem-768 public key size: got %d, want %d", len(packed), wantSize)
	}

	x25519Pub, err := ecdh.X25519().NewPublicKey(packed[:x25519KeySize])
	if err != nil {
		return nil, fmt.Errorf("x25519 public key invalid: %w", err)
	}

	key, err := mlkem768.Scheme().UnmarshalBinaryPublicKey(packed[x25519KeySize:])
	if err != nil {
		return nil, fmt.Errorf("ml-kem-768 public key invalid: %w", err)
	}
	mlkemPub, ok := key.(*mlkem768.PublicKey)
	if !ok {
		return nil, errors.New("unexpected ml-kem-768 key type")
	}

	return &hybridPublicKey{x25519: x25519Pub, mlkem: mlkemPub}, nil
}

// hybridPublicKeyFromPrivate derives the public half of pk (which must have algorithm AlgorithmMLKEM768)
// for encrypting new data -- used when a Crypt has no explicitly configured public key and falls back to
// the current entry in its private keys (see Crypt.resolveEncryptionTarget).
func hybridPublicKeyFromPrivate(pk *PrivateKey) (*hybridPublicKey, error) {
	mlkemPub, ok := pk.mlkemPrivateKey.Public().(*mlkem768.PublicKey)
	if !ok {
		return nil, errors.New("invalid ml-kem-768 private key")
	}
	return &hybridPublicKey{x25519: pk.x25519PrivateKey.PublicKey(), mlkem: mlkemPub}, nil
}

// isHybridCiphertext reports whether raw was produced by hybridEncrypt.
func isHybridCiphertext(raw []byte) bool {
	return len(raw) > len(hybridMagic) && string(raw[:len(hybridMagic)]) == hybridMagic
}

// hybridEncrypt performs an ephemeral X25519 key agreement with pub.x25519 and an ML-KEM-768
// encapsulation to pub.mlkem, concatenates both shared secrets, expands them (bound to
// encryptionContext) into an AES-256 key via HKDF-SHA256, and uses that key to AES-256-GCM-seal secret.
// The returned bytes are self-describing (magic || ephemeralX25519PublicKey || kemCiphertext || nonce ||
// sealed) so hybridDecrypt needs no extra state beyond the recipient's own private key.
func hybridEncrypt(pub *hybridPublicKey, secret []byte, encryptionContext []byte) ([]byte, error) {
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral X25519 key: %w", err)
	}
	ecdhSharedSecret, err := ephemeral.ECDH(pub.x25519)
	if err != nil {
		return nil, fmt.Errorf("X25519 key agreement failed: %w", err)
	}

	kemCiphertext := make([]byte, mlkem768.CiphertextSize)
	kemSharedSecret := make([]byte, mlkem768.SharedKeySize)
	pub.mlkem.EncapsulateTo(kemCiphertext, kemSharedSecret, nil)

	gcm, err := newHybridAEAD(combineSharedSecrets(ecdhSharedSecret, kemSharedSecret), encryptionContext)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	sealed := gcm.Seal(nil, nonce, secret, nil)

	ephemeralPublic := ephemeral.PublicKey().Bytes()

	out := make([]byte, 0, len(hybridMagic)+len(ephemeralPublic)+len(kemCiphertext)+len(nonce)+len(sealed))
	out = append(out, []byte(hybridMagic)...)
	out = append(out, ephemeralPublic...)
	out = append(out, kemCiphertext...)
	out = append(out, nonce...)
	out = append(out, sealed...)
	return out, nil
}

// hybridDecrypt reverses hybridEncrypt using x25519Priv and mlkemPriv (the two halves of a PrivateKey
// with algorithm AlgorithmMLKEM768). It returns an error if raw is malformed, was encrypted for a
// different key, or was encrypted under a different encryptionContext.
func hybridDecrypt(
	x25519Priv *ecdh.PrivateKey, mlkemPriv *mlkem768.PrivateKey, raw []byte, encryptionContext []byte,
) ([]byte, error) {
	if !isHybridCiphertext(raw) {
		return nil, errors.New("not a hybrid ciphertext")
	}
	rest := raw[len(hybridMagic):]
	if len(rest) < x25519KeySize+mlkem768.CiphertextSize+hybridGCMNonceSize {
		return nil, errors.New("hybrid ciphertext truncated")
	}
	ephemeralPublicBytes := rest[:x25519KeySize]
	rest = rest[x25519KeySize:]
	kemCiphertext := rest[:mlkem768.CiphertextSize]
	rest = rest[mlkem768.CiphertextSize:]
	nonce := rest[:hybridGCMNonceSize]
	sealed := rest[hybridGCMNonceSize:]

	ephemeralPublic, err := ecdh.X25519().NewPublicKey(ephemeralPublicBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid ephemeral X25519 public key: %w", err)
	}
	ecdhSharedSecret, err := x25519Priv.ECDH(ephemeralPublic)
	if err != nil {
		return nil, fmt.Errorf("X25519 key agreement failed: %w", err)
	}

	kemSharedSecret := make([]byte, mlkem768.SharedKeySize)
	mlkemPriv.DecapsulateTo(kemSharedSecret, kemCiphertext)

	gcm, err := newHybridAEAD(combineSharedSecrets(ecdhSharedSecret, kemSharedSecret), encryptionContext)
	if err != nil {
		return nil, err
	}

	return gcm.Open(nil, nonce, sealed, nil)
}

// combineSharedSecrets concatenates the classical (X25519) and post-quantum (ML-KEM-768) shared
// secrets before they're expanded into an AES key. Concatenation followed by an HKDF pass (as
// newHybridAEAD does) is the standard KEM combiner used by e.g. TLS 1.3 hybrid key exchange and the
// X-Wing combined-KEM construction: the derived key stays secret as long as at least one of the two
// inputs does, so breaking confidentiality requires breaking both X25519 and ML-KEM-768, not either one
// alone.
func combineSharedSecrets(ecdhSharedSecret, kemSharedSecret []byte) []byte {
	combined := make([]byte, 0, len(ecdhSharedSecret)+len(kemSharedSecret))
	combined = append(combined, ecdhSharedSecret...)
	combined = append(combined, kemSharedSecret...)
	return combined
}

// newHybridAEAD derives an AES-256 key from a combined shared secret via HKDF-SHA256 (RFC 5869),
// binding encryptionContext as the HKDF 'info' the same way EncryptRsa/DecryptRsa bind it as an
// RSA-OAEP label, and wraps it in AES-256-GCM.
func newHybridAEAD(sharedSecret []byte, encryptionContext []byte) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, sharedSecret, nil, string(encryptionContext), hybridAESKeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to derive AES key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to init AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to init AES-GCM: %w", err)
	}
	return gcm, nil
}
