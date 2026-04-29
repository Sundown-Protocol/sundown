// Command yellowpages is the Sundown discovery server.
//
// It stores a mapping of node_id → URL + public key + handle.
// No content. No social graph. Fully stateless from the protocol's perspective.
//
// Usage:
//
//	yellowpages --db ./directory.db --addr :8081
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/sundown/sundown/internal/directory"
)

func main() {
	dbPath := flag.String("db", "./directory.db", "path to the SQLite database file")
	addr   := flag.String("addr", ":8081", "address to listen on")
	dev    := flag.Bool("dev", false, "allow http:// node URLs (development only)")
	flag.Parse()

	db, err := directory.Open(*dbPath)
	if err != nil {
		log.Fatalf("opening directory database: %v", err)
	}
	defer db.Close()

	count, _ := db.Count()
	if *dev { log.Printf("WARNING: running in dev mode — http:// URLs allowed") }
	log.Printf("Sundown yellow pages listening on %s (%d nodes registered)", *addr, count)

	// Purge stale entries every hour.
	go func() {
		for range time.Tick(time.Hour) {
			n, err := db.PurgeStale(72 * time.Hour)
			if err != nil {
				log.Printf("purge error: %v", err)
			} else if n > 0 {
				log.Printf("purged %d stale entries", n)
			}
		}
	}()

	mux := http.NewServeMux()

	// GET /directory?q=john&limit=10
	mux.HandleFunc("GET /directory", func(w http.ResponseWriter, r *http.Request) {
		handleSearch(w, r, db)
	})

	// POST /directory/register
	mux.HandleFunc("POST /directory/register", func(w http.ResponseWriter, r *http.Request) {
		handleRegister(w, r, db, *dev)
	})

	// GET /health — for load balancers and monitoring
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		count, _ := db.Count()
		writeJSON(w, http.StatusOK, map[string]any{
			"status":           "ok",
			"sd_version":       "1.0",
			"registered_nodes": count,
		})
	})

	if err := http.ListenAndServe(*addr, middleware(mux)); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

// handleSearch serves GET /directory?q=...&limit=...
// Returns matching nodes. Never returns content, connections, or private data.
func handleSearch(w http.ResponseWriter, r *http.Request, db *directory.DB) {
	q := r.URL.Query().Get("q")
	if q == "" {
		writeErr(w, http.StatusBadRequest, "q parameter is required")
		return
	}
	if len(q) < 2 {
		writeErr(w, http.StatusBadRequest, "q must be at least 2 characters")
		return
	}

	var limit int
	fmt.Sscanf(r.URL.Query().Get("limit"), "%d", &limit)

	entries, err := db.Search(q, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "search failed")
		return
	}

	type result struct {
		NodeID      string `json:"node_id"`
		Handle      string `json:"handle"`
		DisplayName string `json:"display_name"`
		NodeURL     string `json:"node_url"`
		PublicKey   string `json:"public_key"` // base64url
		LastSeenAt  string `json:"last_seen_at"`
	}

	results := make([]result, 0, len(entries))
	for _, e := range entries {
		results = append(results, result{
			NodeID:      e.NodeID,
			Handle:      e.Handle,
			DisplayName: e.DisplayName,
			NodeURL:     e.NodeURL,
			PublicKey:   b64(e.PublicKey),
			LastSeenAt:  e.LastSeenAt.Format(time.RFC3339),
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

// handleRegister serves POST /directory/register
//
// Request body:
//
//	{
//	  "node_id":      "sd:...",
//	  "handle":       "john",
//	  "display_name": "John Appleseed",
//	  "node_url":     "https://john.example.com",
//	  "public_key":   "base64url(X25519 pub)",
//	  "signing_key":  "base64url(Ed25519 pub)",
//	  "signature":    "base64url(Ed25519-Sign(node_id + node_url, ed25519_priv))"
//	}
//
// The signature proves ownership of the Ed25519 private key matching
// the declared signing_key. Without this, anyone could register a fake
// entry for any node_id. Defined in spec Section 10.1.
func handleRegister(w http.ResponseWriter, r *http.Request, db *directory.DB, devMode bool) {
	var req struct {
		NodeID      string `json:"node_id"`
		Handle      string `json:"handle"`
		DisplayName string `json:"display_name"`
		NodeURL     string `json:"node_url"`
		PublicKey   string `json:"public_key"`   // X25519 — stored for clients
		SigningKey   string `json:"signing_key"`  // Ed25519 — used only for verification
		Signature   string `json:"signature"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate required fields.
	if req.NodeID == "" || req.NodeURL == "" || req.PublicKey == "" ||
		req.SigningKey == "" || req.Signature == "" || req.Handle == "" {
		writeErr(w, http.StatusBadRequest, "node_id, handle, node_url, public_key, signing_key, and signature are required")
		return
	}

	// Enforce https-only node URLs (spec Section 11.4).
	// Dev mode allows http:// for local testing only.
	if !devMode && !strings.HasPrefix(req.NodeURL, "https://") {
		writeErr(w, http.StatusBadRequest, "node_url must use https://")
		return
	}

	// Handle must be lowercase alphanumeric + hyphens only.
	if !isValidHandle(req.Handle) {
		writeErr(w, http.StatusBadRequest, "handle must be lowercase alphanumeric and hyphens only")
		return
	}

	// Decode keys and signature.
	pubKeyBytes, err := b64decode(req.PublicKey)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "public_key must be base64url encoded")
		return
	}

	signingKeyBytes, err := b64decode(req.SigningKey)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "signing_key must be base64url encoded")
		return
	}
	if len(signingKeyBytes) != ed25519.PublicKeySize {
		writeErr(w, http.StatusBadRequest, "signing_key must be a 32-byte Ed25519 public key")
		return
	}

	sigBytes, err := b64decode(req.Signature)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "signature must be base64url encoded")
		return
	}

	// Verify the signature over node_id + node_url.
	// This is the proof of ownership: only the holder of the Ed25519 private
	// key can produce a valid signature over this message.
	// Defined in spec Section 10.1.
	message := []byte(req.NodeID + req.NodeURL)
	if !ed25519.Verify(ed25519.PublicKey(signingKeyBytes), message, sigBytes) {
		writeErr(w, http.StatusForbidden, "invalid signature — registration rejected")
		return
	}

	// Signature is valid. Upsert the entry.
	entry := &directory.Entry{
		NodeID:      req.NodeID,
		Handle:      req.Handle,
		DisplayName: req.DisplayName,
		NodeURL:     req.NodeURL,
		PublicKey:   pubKeyBytes,
	}

	if err := db.Upsert(entry); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not store registration")
		return
	}

	log.Printf("registered: %s (@%s) → %s", req.NodeID, req.Handle, req.NodeURL)
	writeJSON(w, http.StatusOK, map[string]string{"status": "registered"})
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func isValidHandle(h string) bool {
	if len(h) < 1 || len(h) > 32 {
		return false
	}
	for _, c := range h {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
			return false
		}
	}
	return true
}

func b64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func b64decode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s", r.Method, r.URL.Path, r.RemoteAddr)
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, SD-Client")
		w.Header().Set("SD-Server", "sundown-yellowpages/1.0 (Ontario)")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
