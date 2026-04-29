package crypto_test

import (
	"bytes"
	"testing"

	"github.com/sundown/sundown/internal/crypto"
)

// TestKeyExchange proves that two nodes independently derive the same
// content key from ECDH — the core of the Sundown handshake (spec Section 5).
func TestKeyExchange(t *testing.T) {
	// John and Melanie each generate their own keypairs independently.
	johnKP, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("John keypair: %v", err)
	}
	melanieKP, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Melanie keypair: %v", err)
	}

	// Both derive the shared content key using each other's public key.
	// Neither transmits the result — they compute it independently.
	johnKey, err := crypto.DeriveContentKey(johnKP.Private, melanieKP.Public)
	if err != nil {
		t.Fatalf("John derives key: %v", err)
	}
	melanieKey, err := crypto.DeriveContentKey(melanieKP.Private, johnKP.Public)
	if err != nil {
		t.Fatalf("Melanie derives key: %v", err)
	}

	if !bytes.Equal(johnKey, melanieKey) {
		t.Errorf("ECDH key mismatch:\n  John:    %x\n  Melanie: %x", johnKey, melanieKey)
	}
	t.Logf("Shared content key: %x", johnKey)
}

// TestEncryptDecrypt proves the AES-256-GCM round-trip works correctly.
func TestEncryptDecrypt(t *testing.T) {
	key, err := crypto.GenerateContentKey()
	if err != nil {
		t.Fatalf("generating content key: %v", err)
	}

	plaintext := []byte("Hello from my node. This is private content.")

	payload, err := crypto.Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}

	// Ciphertext must not equal plaintext.
	if bytes.Equal(payload.Ciphertext[:len(plaintext)], plaintext) {
		t.Error("ciphertext looks like plaintext — encryption failed")
	}

	decrypted, err := crypto.Decrypt(key, payload)
	if err != nil {
		t.Fatalf("decrypting: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted text mismatch:\n  want: %s\n  got:  %s", plaintext, decrypted)
	}
}

// TestDecryptWrongKey proves that AES-GCM rejects decryption with the wrong key.
// This is the auth tag verification — tampered data or wrong key both fail.
func TestDecryptWrongKey(t *testing.T) {
	key1, _ := crypto.GenerateContentKey()
	key2, _ := crypto.GenerateContentKey()

	payload, err := crypto.Encrypt(key1, []byte("secret"))
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}

	_, err = crypto.Decrypt(key2, payload)
	if err == nil {
		t.Error("expected decryption to fail with wrong key, but it succeeded")
	}
	t.Logf("Correctly rejected wrong key: %v", err)
}

// TestWrapUnwrapKey proves the full connection key exchange:
// John wraps his content key for Melanie; Melanie unwraps it.
// After this, Melanie holds John's content key and can decrypt his posts.
func TestWrapUnwrapKey(t *testing.T) {
	johnKP, _ := crypto.GenerateKeyPair()
	melanieKP, _ := crypto.GenerateKeyPair()

	// John's content key — what he encrypts all his posts with.
	johnsContentKey, err := crypto.GenerateContentKey()
	if err != nil {
		t.Fatalf("generating content key: %v", err)
	}

	// John wraps his content key for Melanie using their ECDH shared secret.
	wrapped, err := crypto.WrapKey(johnKP.Private, melanieKP.Public, johnsContentKey)
	if err != nil {
		t.Fatalf("wrapping key: %v", err)
	}

	// Melanie unwraps it using her private key and John's public key.
	unwrapped, err := crypto.UnwrapKey(melanieKP.Private, johnKP.Public, wrapped)
	if err != nil {
		t.Fatalf("unwrapping key: %v", err)
	}

	if !bytes.Equal(unwrapped, johnsContentKey) {
		t.Errorf("unwrapped key mismatch:\n  want: %x\n  got:  %x", johnsContentKey, unwrapped)
	}

	// Now prove Melanie can decrypt a post John encrypted with his content key.
	postPlaintext := []byte("Just set up my node. Feels good to own my own space again.")
	encrypted, err := crypto.Encrypt(johnsContentKey, postPlaintext)
	if err != nil {
		t.Fatalf("encrypting post: %v", err)
	}

	decrypted, err := crypto.Decrypt(unwrapped, encrypted)
	if err != nil {
		t.Fatalf("Melanie decrypting John's post: %v", err)
	}

	if !bytes.Equal(decrypted, postPlaintext) {
		t.Errorf("post content mismatch:\n  want: %s\n  got:  %s", postPlaintext, decrypted)
	}
	t.Logf("Full handshake verified. Melanie reads: %q", decrypted)
}

// TestNodeID proves the node ID format matches the spec (Section 3.2).
func TestNodeID(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generating keypair: %v", err)
	}
	id := crypto.NodeID(kp.Public)

	if len(id) != 51 { // "sd:" (3) + 48 hex chars
		t.Errorf("node ID wrong length: got %d, want 51 — %s", len(id), id)
	}
	if id[:3] != "sd:" {
		t.Errorf("node ID missing sd: prefix: %s", id)
	}
	t.Logf("Node ID: %s", id)
}

// TestFreshIVEachEncryption proves that encrypting the same plaintext twice
// produces different ciphertext (different IV each time).
// IV reuse with AES-GCM is catastrophic — this must always pass.
func TestFreshIVEachEncryption(t *testing.T) {
	key, _ := crypto.GenerateContentKey()
	plaintext := []byte("same message")

	p1, _ := crypto.Encrypt(key, plaintext)
	p2, _ := crypto.Encrypt(key, plaintext)

	if bytes.Equal(p1.IV, p2.IV) {
		t.Error("IV reuse detected — two encryptions produced the same nonce")
	}
	if bytes.Equal(p1.Ciphertext, p2.Ciphertext) {
		t.Error("ciphertext collision — same plaintext produced identical ciphertext")
	}
	t.Logf("IV 1: %x", p1.IV)
	t.Logf("IV 2: %x", p2.IV)
}
