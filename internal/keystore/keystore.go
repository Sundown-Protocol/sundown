// Package keystore handles passphrase-based encryption of node private keys.
//
// Private keys are the most sensitive data in a Sundown node. They must never
// be stored in plaintext. This package wraps and unwraps key material using:
//
//   - Argon2id (RFC 9106) to derive an encryption key from the passphrase.
//     Argon2id is memory-hard, making brute-force attacks expensive.
//   - AES-256-GCM to encrypt the key bytes. The authentication tag
//     detects any tampering with the stored blob.
//
// The encrypted blob format (all concatenated):
//
//	[16 bytes salt][12 bytes IV][N bytes ciphertext+tag]
//
// This is self-contained — everything needed to decrypt is in the blob.
// Defined in spec Section 11.1.
package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters. These follow the RFC 9106 "second recommended option"
// suitable for interactive logins on constrained hardware. Increasing memory
// or iterations increases security at the cost of slower unlock.
//
// Tuning guidance:
//   - memory: 64 MiB is the RFC minimum for interactive. Increase for higher security.
//   - time: 1 pass with 64 MiB is already strong against GPU attacks.
//   - threads: match available CPU cores on the target deployment machine.
const (
	argonTime    uint32 = 1
	argonMemory  uint32 = 64 * 1024 // 64 MiB
	argonThreads uint8  = 4
	argonKeyLen  uint32 = 32 // 256-bit AES key
	saltLen             = 16 // 128-bit random salt
	ivLen               = 12 // 96-bit AES-GCM nonce
)

// Wrap encrypts keyMaterial with a key derived from passphrase.
// Returns a self-contained encrypted blob (salt + IV + ciphertext).
// Call this when storing private keys to disk or to the hosted server.
func Wrap(passphrase string, keyMaterial []byte) ([]byte, error) {
	// Generate a fresh random salt for every wrap operation.
	// Reusing salts allows precomputation attacks against the KDF.
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generating salt: %w", err)
	}

	// Derive the AES key from the passphrase + salt using Argon2id.
	aesKey := argon2.IDKey([]byte(passphrase), salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	// Encrypt the key material with AES-256-GCM.
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	iv := make([]byte, ivLen)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("generating IV: %w", err)
	}

	ciphertext := gcm.Seal(nil, iv, keyMaterial, nil)

	// Pack: salt || IV || ciphertext
	blob := make([]byte, saltLen+ivLen+len(ciphertext))
	copy(blob[0:saltLen], salt)
	copy(blob[saltLen:saltLen+ivLen], iv)
	copy(blob[saltLen+ivLen:], ciphertext)

	return blob, nil
}

// Unwrap decrypts an encrypted key blob using the given passphrase.
// Returns the original key material, or an error if the passphrase is wrong
// or the blob has been tampered with. The error is intentionally opaque —
// we do not distinguish "wrong passphrase" from "tampered blob".
func Unwrap(passphrase string, blob []byte) ([]byte, error) {
	minLen := saltLen + ivLen + 16 // 16 = minimum GCM auth tag
	if len(blob) < minLen {
		return nil, errors.New("invalid key blob: too short")
	}

	salt := blob[0:saltLen]
	iv   := blob[saltLen : saltLen+ivLen]
	ct   := blob[saltLen+ivLen:]

	// Re-derive the AES key from the passphrase and the stored salt.
	aesKey := argon2.IDKey([]byte(passphrase), salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, iv, ct, nil)
	if err != nil {
		// Intentionally opaque — do not leak whether it was a wrong
		// passphrase or tampered data.
		return nil, errors.New("decryption failed: wrong passphrase or corrupted key")
	}
	return plaintext, nil
}

// WrapMultiple encrypts several key materials with the same passphrase,
// each with its own independent salt and IV. Used during node init to
// wrap the private key, signing key, and content key in one call.
func WrapMultiple(passphrase string, keys ...[]byte) ([][]byte, error) {
	blobs := make([][]byte, len(keys))
	for i, k := range keys {
		blob, err := Wrap(passphrase, k)
		if err != nil {
			return nil, fmt.Errorf("wrapping key %d: %w", i, err)
		}
		blobs[i] = blob
	}
	return blobs, nil
}
