// Package models defines the core data structures for the Sundown protocol.
// These map directly to the entities described in the spec and to database rows.
package models

import "time"

// Node represents a Sundown node — one per user.
// The private key is stored encrypted; it is never held in plaintext at rest.
type Node struct {
	ID          string    // "sd:..." — derived from X25519 public key
	Handle      string    // local handle, e.g. "john"
	DisplayName string    // human-readable name
	AvatarURL   string    // relative path to avatar image
	Bio         []byte    // encrypted bytes, or nil
	PublicKey   []byte    // raw X25519 public key bytes
	// EncryptedPrivateKey is the X25519 private key, encrypted with a
	// key derived from the user's passphrase. Never transmitted.
	EncryptedPrivateKey []byte
	// EncryptedContentKey is the node's AES-256-GCM content key,
	// encrypted with the same passphrase-derived key.
	EncryptedContentKey []byte
	// EncryptedSigningKey is the Ed25519 private key, encrypted at rest.
	EncryptedSigningKey []byte
	SigningPublicKey     []byte    // raw Ed25519 public key bytes
	PublicMode          bool      // if true, content is served unencrypted
	PollIntervalSeconds int       // declared preferred poll interval
	PollIntervalMax     int       // declared maximum poll interval
	Theme               []byte    // JSON-encoded theme object
	CreatedAt           time.Time
}

// Post is a single piece of content published by a node.
// The Body is always stored and served as ciphertext.
type Post struct {
	ID        string    // UUID
	NodeID    string    // owner node
	IV        []byte    // AES-GCM nonce
	Body      []byte    // AES-GCM ciphertext (includes auth tag)
	CreatedAt time.Time
	// Media holds references to encrypted media attached to this post.
	Media []Media
}

// Media is a reference to an encrypted media blob attached to a post.
type Media struct {
	ID     string // UUID, used as the URL path segment
	PostID string
	Type   string // "image" — only type in v1
	IV     []byte // AES-GCM nonce for the media blob
	// The encrypted media bytes are stored on disk, not in the DB.
	// The URL is constructed as /media/{ID}.
}

// Connection represents a confirmed mutual connection between this node
// and a remote node. Both sides hold each other's content key.
type Connection struct {
	ID               string    // UUID
	LocalNodeID      string    // this node
	RemoteNodeID     string    // their node
	RemotePublicKey  []byte    // their X25519 public key
	RemoteNodeURL    string    // their node's base URL
	RemoteHandle     string    // their display handle
	RemoteAvatarURL  string
	// EncryptedTheirKey is their content key, wrapped with our ECDH-derived
	// wrap key. Unwrapped client-side only.
	EncryptedTheirKey []byte
	EncryptedTheirIV  []byte
	ConfirmedAt       time.Time
	CreatedAt         time.Time
}

// PendingRequest is an inbound connection request awaiting confirmation.
type PendingRequest struct {
	ID              string    // UUID
	LocalNodeID     string    // the node receiving the request
	FromNodeID      string    // requester's node ID
	FromPublicKey   []byte    // requester's X25519 public key
	FromDisplayName string
	FromAvatarURL   string
	FromNodeURL     string    // needed to fetch their descriptor after confirmation
	Intro           string    // optional free-text message, max 500 chars
	ReceivedAt      time.Time
}

// Theme is the declarative presentation config for a node's profile.
// It lives inside Node.Theme as JSON but is also parsed into this struct.
type Theme struct {
	Version    int          `json:"version"`
	Colors     ThemeColors  `json:"colors"`
	Typography ThemeFont    `json:"typography"`
	Layout     ThemeLayout  `json:"layout"`
}

type ThemeColors struct {
	Accent     string `json:"accent"`
	Background string `json:"background"`
	Surface    string `json:"surface"`
	Text       string `json:"text"`
	TextMuted  string `json:"text_muted"`
}

type ThemeFont struct {
	FontFamily string  `json:"font_family"` // "sans" | "serif" | "mono"
	FontScale  float64 `json:"font_scale"`  // clamped to [0.85, 1.2]
}

type ThemeLayout struct {
	Mode    string `json:"mode"`    // "list" | "grid" | "magazine"
	Density string `json:"density"` // "compact" | "comfortable" | "spacious"
}
