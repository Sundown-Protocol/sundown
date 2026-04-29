package keystore_test

import (
	"bytes"
	"testing"

	"github.com/sundown/sundown/internal/keystore"
)

// TestWrapUnwrapRoundtrip proves that a key encrypted with a passphrase
// can be recovered with the same passphrase.
func TestWrapUnwrapRoundtrip(t *testing.T) {
	passphrase := "correct horse battery staple"
	original   := []byte("this-is-a-32-byte-private-key!!")

	blob, err := keystore.Wrap(passphrase, original)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	// Blob must be longer than the original (salt + IV + tag overhead).
	if len(blob) <= len(original) {
		t.Errorf("blob (%d bytes) not longer than original (%d bytes)", len(blob), len(original))
	}

	recovered, err := keystore.Unwrap(passphrase, blob)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}

	if !bytes.Equal(recovered, original) {
		t.Errorf("recovered key mismatch:\n  want: %x\n  got:  %x", original, recovered)
	}
	t.Logf("Blob size: %d bytes (original: %d)", len(blob), len(original))
}

// TestWrongPassphraseRejected proves Argon2id + AES-GCM rejects a wrong passphrase.
// This is the critical security property — a brute-force attacker gets no oracle.
func TestWrongPassphraseRejected(t *testing.T) {
	blob, err := keystore.Wrap("correct-passphrase", []byte("secret-key-bytes"))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	_, err = keystore.Unwrap("wrong-passphrase", blob)
	if err == nil {
		t.Error("expected error with wrong passphrase, got nil")
	}
	t.Logf("Correctly rejected wrong passphrase: %v", err)
}

// TestTamperedBlobRejected proves the AES-GCM auth tag catches tampering.
// An attacker who modifies stored ciphertext cannot produce a valid blob.
func TestTamperedBlobRejected(t *testing.T) {
	passphrase := "my-passphrase"
	blob, err := keystore.Wrap(passphrase, []byte("secret-key"))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	// Flip one byte in the ciphertext portion (after salt + IV).
	tampered := make([]byte, len(blob))
	copy(tampered, blob)
	tampered[30] ^= 0xFF // flip bits in the ciphertext

	_, err = keystore.Unwrap(passphrase, tampered)
	if err == nil {
		t.Error("expected error for tampered blob, got nil — auth tag not checked")
	}
	t.Logf("Correctly rejected tampered blob: %v", err)
}

// TestFreshSaltEachWrap proves two wraps of the same key produce different blobs.
// Salt reuse would allow precomputation attacks against the KDF.
func TestFreshSaltEachWrap(t *testing.T) {
	passphrase := "same-passphrase"
	key        := []byte("same-key-bytes-32-bytes-exactly!")

	blob1, _ := keystore.Wrap(passphrase, key)
	blob2, _ := keystore.Wrap(passphrase, key)

	if bytes.Equal(blob1, blob2) {
		t.Error("two wraps of the same key produced identical blobs — salt reuse detected")
	}

	// Both must still decrypt correctly.
	r1, err := keystore.Unwrap(passphrase, blob1)
	if err != nil { t.Fatalf("unwrap blob1: %v", err) }
	r2, err := keystore.Unwrap(passphrase, blob2)
	if err != nil { t.Fatalf("unwrap blob2: %v", err) }

	if !bytes.Equal(r1, key) { t.Error("blob1 recovered incorrectly") }
	if !bytes.Equal(r2, key) { t.Error("blob2 recovered incorrectly") }
	t.Log("Both blobs are distinct but both decrypt correctly")
}

// TestWrapMultiple proves WrapMultiple encrypts all keys independently.
func TestWrapMultiple(t *testing.T) {
	passphrase := "test-passphrase"
	privKey    := []byte("private-key-32-bytes-exactly!!!!")
	sigKey     := []byte("signing-key-64-bytes-ed25519-priv")
	contentKey := []byte("content-aes-key-32-bytes-exactly")

	blobs, err := keystore.WrapMultiple(passphrase, privKey, sigKey, contentKey)
	if err != nil {
		t.Fatalf("WrapMultiple: %v", err)
	}
	if len(blobs) != 3 {
		t.Fatalf("expected 3 blobs, got %d", len(blobs))
	}

	// Each blob must be distinct (independent salts).
	if bytes.Equal(blobs[0], blobs[1]) || bytes.Equal(blobs[1], blobs[2]) {
		t.Error("WrapMultiple produced duplicate blobs — independent encryption not working")
	}

	// All must decrypt correctly.
	keys := [][]byte{privKey, sigKey, contentKey}
	for i, blob := range blobs {
		recovered, err := keystore.Unwrap(passphrase, blob)
		if err != nil {
			t.Fatalf("unwrap key %d: %v", i, err)
		}
		if !bytes.Equal(recovered, keys[i]) {
			t.Errorf("key %d recovered incorrectly", i)
		}
	}
	t.Log("All 3 keys wrapped and unwrapped correctly with independent salts")
}

// TestEmptyBlobRejected proves malformed blobs are caught before any crypto.
func TestEmptyBlobRejected(t *testing.T) {
	_, err := keystore.Unwrap("any-passphrase", []byte{})
	if err == nil {
		t.Error("expected error for empty blob, got nil")
	}
	_, err = keystore.Unwrap("any-passphrase", []byte{0x01, 0x02})
	if err == nil {
		t.Error("expected error for too-short blob, got nil")
	}
}
