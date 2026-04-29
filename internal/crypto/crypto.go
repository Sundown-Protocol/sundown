// Package crypto implements all cryptographic primitives for the Sundown protocol.
// Every function corresponds directly to a section in the Sundown Protocol
// Specification (Ontario, v1.0). Uses Go standard library only.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

const hkdfInfo = "sundown-content-v1"

type KeyPair struct {
	Private *ecdh.PrivateKey
	Public  *ecdh.PublicKey
}

type SigningKeyPair struct {
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
}

type EncryptedPayload struct {
	IV         []byte
	Ciphertext []byte
}

func GenerateKeyPair() (*KeyPair, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating X25519 keypair: %w", err)
	}
	return &KeyPair{Private: priv, Public: priv.PublicKey()}, nil
}

func GenerateSigningKeyPair() (*SigningKeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating Ed25519 keypair: %w", err)
	}
	return &SigningKeyPair{Private: priv, Public: pub}, nil
}

func NodeID(pub *ecdh.PublicKey) string {
	raw := pub.Bytes()
	h := hex.EncodeToString(raw)
	if len(h) > 48 {
		h = h[:48]
	}
	return "sd:" + h
}

// hkdfSHA256 is a single-block HKDF-SHA-256 (RFC 5869) using stdlib only.
func hkdfSHA256(ikm, salt, info []byte, length int) ([]byte, error) {
	if length > 32 {
		return nil, fmt.Errorf("hkdfSHA256: length %d exceeds one SHA-256 block", length)
	}
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	prk := mac.Sum(nil)
	mac = hmac.New(sha256.New, prk)
	mac.Write(info)
	mac.Write([]byte{0x01})
	return mac.Sum(nil)[:length], nil
}

func DeriveContentKey(myPrivate *ecdh.PrivateKey, theirPublic *ecdh.PublicKey) ([]byte, error) {
	sharedSecret, err := myPrivate.ECDH(theirPublic)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}
	salt := make([]byte, 32)
	return hkdfSHA256(sharedSecret, salt, []byte(hkdfInfo), 32)
}

func Encrypt(key, plaintext []byte) (*EncryptedPayload, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM: %w", err)
	}
	iv := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("IV: %w", err)
	}
	return &EncryptedPayload{IV: iv, Ciphertext: gcm.Seal(nil, iv, plaintext, nil)}, nil
}

func Decrypt(key []byte, payload *EncryptedPayload) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM: %w", err)
	}
	plain, err := gcm.Open(nil, payload.IV, payload.Ciphertext, nil)
	if err != nil {
		return nil, errors.New("decryption failed: invalid key or tampered data")
	}
	return plain, nil
}

func GenerateContentKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	return key, err
}

func WrapKey(myPrivate *ecdh.PrivateKey, theirPublic *ecdh.PublicKey, contentKey []byte) (*EncryptedPayload, error) {
	wk, err := DeriveContentKey(myPrivate, theirPublic)
	if err != nil {
		return nil, err
	}
	return Encrypt(wk, contentKey)
}

func UnwrapKey(myPrivate *ecdh.PrivateKey, theirPublic *ecdh.PublicKey, wrapped *EncryptedPayload) ([]byte, error) {
	wk, err := DeriveContentKey(myPrivate, theirPublic)
	if err != nil {
		return nil, err
	}
	return Decrypt(wk, wrapped)
}

func Sign(priv ed25519.PrivateKey, data []byte) []byte {
	return ed25519.Sign(priv, data)
}

func Verify(pub ed25519.PublicKey, data, sig []byte) bool {
	return ed25519.Verify(pub, data, sig)
}
