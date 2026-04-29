// Package auth implements Sundown node authentication.
//
// Two token types are supported (spec Section 7):
//   - Self-signed: a JWT signed with the node's Ed25519 private key.
//     Used by self-hosted nodes. Verified against the stored public key.
//   - Server-issued: an opaque token issued by the hosted tier after
//     passphrase authentication. Verified against a shared HMAC secret.
//
// Both token types use the same Authorization: Bearer header and are
// indistinguishable to the node API layer.
package auth

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// TokenClaims are the JWT payload fields we care about.
type TokenClaims struct {
	Subject string // node_id ("sd:...")
	Scope   string // "node:admin"
	IssuedAt  int64
	ExpiresAt int64
}

// jwtHeader is fixed for all self-signed tokens.
var jwtHeader = mustB64(mustJSON(map[string]string{
	"alg": "EdDSA",
	"typ": "JWT",
}))

// IssueSelfsignedToken creates a JWT signed with the node's Ed25519 private key.
// Tokens are valid for 24 hours. Called by the node owner's client at login.
func IssueSelfsignedToken(nodeID string, signingKey ed25519.PrivateKey) (string, error) {
	now := time.Now().UTC()
	claims := map[string]any{
		"sub":   nodeID,
		"scope": "node:admin",
		"iat":   now.Unix(),
		"exp":   now.Add(24 * time.Hour).Unix(),
	}

	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshalling claims: %w", err)
	}
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// The signing input is header.payload — exactly as per JWT spec.
	signingInput := jwtHeader + "." + payload
	sig := ed25519.Sign(signingKey, []byte(signingInput))
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return signingInput + "." + sigB64, nil
}

// ValidateSelfSignedToken verifies a self-signed JWT against the node's
// Ed25519 public key. Returns the claims if valid.
func ValidateSelfSignedToken(token string, pubKey ed25519.PublicKey, nodeID string) (*TokenClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed token: expected 3 parts")
	}

	// Verify signature over header.payload
	signingInput := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("malformed token: invalid signature encoding")
	}
	if !ed25519.Verify(pubKey, []byte(signingInput), sig) {
		return nil, errors.New("invalid token signature")
	}

	// Decode and validate claims
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("malformed token: invalid payload encoding")
	}

	var raw map[string]any
	if err := json.Unmarshal(payloadJSON, &raw); err != nil {
		return nil, errors.New("malformed token: invalid JSON payload")
	}

	claims, err := parseClaims(raw)
	if err != nil {
		return nil, err
	}

	// Enforce expiry
	if time.Now().Unix() > claims.ExpiresAt {
		return nil, errors.New("token expired")
	}

	// Enforce subject matches this node
	if claims.Subject != nodeID {
		return nil, errors.New("token subject does not match node")
	}

	// Enforce scope
	if claims.Scope != "node:admin" {
		return nil, fmt.Errorf("insufficient scope: %s", claims.Scope)
	}

	return claims, nil
}

// ── Server-issued tokens (hosted tier) ───────────────────────────────────────

// ServerToken is an opaque HMAC-SHA256-based token issued by the hosted tier.
// Format: "sd1." + base64url(nodeID + ":" + expiry) + "." + HMAC
type ServerToken struct {
	NodeID    string
	ExpiresAt time.Time
}

// IssueServerToken creates an opaque token for a hosted-tier session.
// The secret is a per-deployment random key held only in server memory.
func IssueServerToken(nodeID string, secret []byte) (string, error) {
	exp := time.Now().UTC().Add(24 * time.Hour).Unix()
	payload := fmt.Sprintf("%s:%d", nodeID, exp)
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(payload))

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payloadB64))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return "sd1." + payloadB64 + "." + sig, nil
}

// ValidateServerToken verifies and decodes a server-issued opaque token.
func ValidateServerToken(token string, secret []byte, nodeID string) (*TokenClaims, error) {
	if !strings.HasPrefix(token, "sd1.") {
		return nil, errors.New("not a server-issued token")
	}
	parts := strings.Split(strings.TrimPrefix(token, "sd1."), ".")
	if len(parts) != 2 {
		return nil, errors.New("malformed server token")
	}

	payloadB64, sigB64 := parts[0], parts[1]

	// Verify HMAC
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payloadB64))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sigB64), []byte(expected)) {
		return nil, errors.New("invalid token signature")
	}

	// Decode payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, errors.New("malformed token payload")
	}

	var parsedNodeID string
	var exp int64
	if _, err := fmt.Sscanf(string(payloadBytes), "%s", &parsedNodeID); err != nil {
		return nil, errors.New("malformed token payload")
	}

	// Parse "nodeID:expiry" manually
	colonIdx := strings.LastIndex(string(payloadBytes), ":")
	if colonIdx < 0 {
		return nil, errors.New("malformed token payload")
	}
	parsedNodeID = string(payloadBytes[:colonIdx])
	if _, err := fmt.Sscanf(string(payloadBytes[colonIdx+1:]), "%d", &exp); err != nil {
		return nil, errors.New("malformed token expiry")
	}

	if time.Now().Unix() > exp {
		return nil, errors.New("token expired")
	}
	if parsedNodeID != nodeID {
		return nil, errors.New("token node mismatch")
	}

	return &TokenClaims{
		Subject:   parsedNodeID,
		Scope:     "node:admin",
		ExpiresAt: exp,
	}, nil
}

// GenerateSecret generates a cryptographically random 32-byte server secret.
// Call once at startup and keep in memory only — never persist to disk.
func GenerateSecret() ([]byte, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	return b, err
}

// ── Validator factory ─────────────────────────────────────────────────────────

// Validator returns a function that accepts a raw Bearer token string and
// returns true if it is valid for the given node. Accepts both token types.
// This is the function wired into the HTTP handlers.
func Validator(nodeID string, signingPubKey ed25519.PublicKey, serverSecret []byte) func(string) bool {
	return func(token string) bool {
		// Try server-issued first (faster, no crypto verify needed)
		if strings.HasPrefix(token, "sd1.") {
			_, err := ValidateServerToken(token, serverSecret, nodeID)
			return err == nil
		}
		// Fall back to self-signed JWT
		_, err := ValidateSelfSignedToken(token, signingPubKey, nodeID)
		return err == nil
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func parseClaims(raw map[string]any) (*TokenClaims, error) {
	sub, _ := raw["sub"].(string)
	scope, _ := raw["scope"].(string)
	iat, _ := raw["iat"].(float64)
	exp, _ := raw["exp"].(float64)

	if sub == "" || exp == 0 {
		return nil, errors.New("missing required claims")
	}

	return &TokenClaims{
		Subject:   sub,
		Scope:     scope,
		IssuedAt:  int64(iat),
		ExpiresAt: int64(exp),
	}, nil
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func mustB64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
