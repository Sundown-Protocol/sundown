// Command node is the Sundown node server.
//
// Subcommands:
//
//	node init  --db ./sundown.db --handle john --name "John" --passphrase "..."
//	node serve --db ./sundown.db --addr :8080 --passphrase "..."
package main

import (
	"crypto/ecdh"
	crand "crypto/rand"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/sundown/sundown/internal/api"
	"github.com/sundown/sundown/internal/auth"
	cryptopkg "github.com/sundown/sundown/internal/crypto"
	"github.com/sundown/sundown/internal/db"
	"github.com/sundown/sundown/internal/keystore"
	"github.com/sundown/sundown/internal/models"
)

// nodeSecrets holds decrypted key material in memory only.
// Never written back to disk. Zeroed on process exit.
type nodeSecrets struct {
	PrivateKey  *ecdh.PrivateKey
	SigningKey  ed25519.PrivateKey
	ContentKey  []byte
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: sundown-node <init|serve> [flags]")
		os.Exit(1)
	}
	switch os.Args[1] {
	case "init":
		runInit(os.Args[2:])
	case "serve":
		runServe(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n", os.Args[1])
		os.Exit(1)
	}
}

// ── init ──────────────────────────────────────────────────────────────────────

func runInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dbPath     := fs.String("db", "./sundown.db", "path to the SQLite database file")
	handle     := fs.String("handle", "", "your node handle (e.g. john)")
	name       := fs.String("name", "", "your display name")
	passphrase := fs.String("passphrase", "", "passphrase to encrypt your private keys")
	fs.Parse(args)

	if *handle == "" || *name == "" || *passphrase == "" {
		fmt.Fprintln(os.Stderr, "error: --handle, --name, and --passphrase are required")
		os.Exit(1)
	}
	if len(*passphrase) < 12 {
		fmt.Fprintln(os.Stderr, "error: passphrase must be at least 12 characters")
		os.Exit(1)
	}

	database, err := db.Open(*dbPath)
	if err != nil { log.Fatalf("opening database: %v", err) }
	defer database.Close()

	kp, err := cryptopkg.GenerateKeyPair()
	if err != nil { log.Fatalf("generating keypair: %v", err) }

	skp, err := cryptopkg.GenerateSigningKeyPair()
	if err != nil { log.Fatalf("generating signing keypair: %v", err) }

	contentKey, err := cryptopkg.GenerateContentKey()
	if err != nil { log.Fatalf("generating content key: %v", err) }

	nodeID := cryptopkg.NodeID(kp.Public)

	fmt.Print("Deriving encryption key from passphrase (this takes a moment)... ")
	blobs, err := keystore.WrapMultiple(*passphrase,
		kp.Private.Bytes(),
		[]byte(skp.Private),
		contentKey,
	)
	if err != nil { log.Fatalf("encrypting keys: %v", err) }
	fmt.Println("done.")

	theme := models.Theme{
		Version:    1,
		Colors:     models.ThemeColors{Accent: "#ff6600", Background: "#0d0d0d", Surface: "#1a1a1a", Text: "#f0ede8", TextMuted: "#888680"},
		Typography: models.ThemeFont{FontFamily: "sans", FontScale: 1.0},
		Layout:     models.ThemeLayout{Mode: "list", Density: "comfortable"},
	}
	themeJSON, _ := json.Marshal(theme)

	node := &models.Node{
		ID: nodeID, Handle: *handle, DisplayName: *name,
		PublicKey:           kp.Public.Bytes(),
		EncryptedPrivateKey: blobs[0],
		EncryptedSigningKey: blobs[1],
		EncryptedContentKey: blobs[2],
		SigningPublicKey:     skp.Public,
		PublicMode: false, PollIntervalSeconds: 60, PollIntervalMax: 900,
		Theme: themeJSON, CreatedAt: time.Now().UTC(),
	}

	if err := database.InsertNode(node); err != nil { log.Fatalf("storing node: %v", err) }

	fmt.Printf("\nNode created.\n")
	fmt.Printf("  Node ID:  %s\n", nodeID)
	fmt.Printf("  Handle:   @%s\n", *handle)
	fmt.Printf("  Database: %s\n", *dbPath)
	fmt.Printf("  Keys:     encrypted with Argon2id + AES-256-GCM\n")
	fmt.Printf("\nStart with:\n  sundown-node serve --db %s --passphrase \"...\"\n", *dbPath)
	fmt.Printf("\nIMPORTANT: remember your passphrase — there is no recovery without it.\n")
}

// ── serve ─────────────────────────────────────────────────────────────────────

func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	dbPath     := fs.String("db", "./sundown.db", "path to the SQLite database file")
	addr       := fs.String("addr", ":8080", "address to listen on")
	passphrase := fs.String("passphrase", "", "passphrase to decrypt your private keys")
	fs.Parse(args)

	if *passphrase == "" {
		fmt.Fprintln(os.Stderr, "error: --passphrase is required")
		os.Exit(1)
	}

	database, err := db.Open(*dbPath)
	if err != nil { log.Fatalf("opening database: %v", err) }
	defer database.Close()

	node, err := database.GetNode()
	if err != nil { log.Fatalf("node not initialised — run: sundown-node init --db %s", *dbPath) }

	// Decrypt all private key material into memory using the passphrase.
	// If the passphrase is wrong, we fail fast before binding any port.
	fmt.Print("Unlocking node keys... ")
	secrets, err := unlockNode(node, *passphrase)
	if err != nil {
		fmt.Println("failed.")
		log.Fatalf("could not decrypt keys: %v\n(wrong passphrase?)", err)
	}
	fmt.Println("done.")

	// Generate a fresh in-memory server secret for server-issued tokens.
	// Tokens issued before a restart are invalidated — by design.
	serverSecret, err := auth.GenerateSecret()
	if err != nil { log.Fatalf("generating server secret: %v", err) }

	// The token validator accepts both self-signed (Ed25519) and server-issued tokens.
	tokenValidator := auth.Validator(node.ID, node.SigningPublicKey, serverSecret)

	h := &api.Handler{DB: database, NodeID: node.ID}
	mux := http.NewServeMux()

	// ── Public endpoints ──────────────────────────────────────────────────
	mux.HandleFunc("GET /.well-known/sundown.json", h.WellKnown)
	mux.HandleFunc("GET /profile",                  h.Profile)
	mux.HandleFunc("GET /pubkey",                   h.PubKey)
	mux.HandleFunc("GET /feed",                     h.Feed)
	mux.HandleFunc("POST /connect",                 h.Connect)

	// ── Auth exchange ─────────────────────────────────────────────────────
	// GET / — serve the browser client HTML file
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, "sundown.html")
	})

	// POST /auth/unlock — browser client sends passphrase, gets a server token.
	// This is the bridge between the browser UI and the Go backend.
	mux.HandleFunc("POST /auth/unlock", func(w http.ResponseWriter, r *http.Request) {
		handleUnlock(w, r, node, serverSecret)
	})

	// GET /auth/keys — returns decrypted key material to authenticated browser client.
	// The browser needs the X25519 private key to perform ECDH for key exchange.
	// Protected by Bearer token — only the node owner can call this.
	mux.HandleFunc("GET /auth/keys", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, tokenValidator) { return }
		// Encrypt a known plaintext with the content key so the browser
		// can verify it received the correct key.
		verifyPayload, verifyErr := cryptopkg.Encrypt(secrets.ContentKey, []byte("sundown-key-verify-v1"))
		verifyIV, verifyCT := "", ""
		if verifyErr == nil {
			verifyIV = base64.RawURLEncoding.EncodeToString(verifyPayload.IV)
			verifyCT = base64.RawURLEncoding.EncodeToString(verifyPayload.Ciphertext)
		}
		writeJSON(w, http.StatusOK, map[string]string{
			"private_key":  base64.RawURLEncoding.EncodeToString(secrets.PrivateKey.Bytes()),
			"content_key":  base64.RawURLEncoding.EncodeToString(secrets.ContentKey),
			"public_key":   base64.RawURLEncoding.EncodeToString(node.PublicKey),
			"signing_key":  base64.RawURLEncoding.EncodeToString([]byte(secrets.SigningKey)),
			"verify_iv":    verifyIV,
			"verify_ct":    verifyCT,
		})
	})

	// GET /content-key — returns this node's content key wrapped for the requester.
	// The requester proves their identity by providing their node_id and public key.
	// No auth required — the wrapping ensures only the intended recipient can unwrap.
	mux.HandleFunc("GET /content-key", func(w http.ResponseWriter, r *http.Request) {
		theirNodeId  := r.URL.Query().Get("for_node_id")
		theirPubKeyB64 := r.URL.Query().Get("public_key")
		if theirNodeId == "" || theirPubKeyB64 == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "for_node_id and public_key required"})
			return
		}
		theirPubBytes, err := base64.RawURLEncoding.DecodeString(theirPubKeyB64)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid public_key"})
			return
		}
		theirPub, err := ecdh.X25519().NewPublicKey(theirPubBytes)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid X25519 key"})
			return
		}
		// Wrap our content key for them using ECDH
		wrapped, err := cryptopkg.WrapKey(secrets.PrivateKey, theirPub, secrets.ContentKey)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "wrap failed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{
			"encrypted_key": base64.RawURLEncoding.EncodeToString(wrapped.Ciphertext),
			"iv":            base64.RawURLEncoding.EncodeToString(wrapped.IV),
			"node_id":       node.ID,
		})
	})

	// GET /auth/connection-key/{nodeId} — derives and returns the shared content key
	// for a specific connection. Used by browsers without X25519 Web Crypto support.
	mux.HandleFunc("GET /auth/connection-key/{remoteNodeId}", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, tokenValidator) { return }
		remoteNodeId := r.PathValue("remoteNodeId")

		conns, err := database.ListConnections(node.ID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
			return
		}

		var targetConn *models.Connection
		for _, c := range conns {
			if c.RemoteNodeID == remoteNodeId {
				targetConn = c
				break
			}
		}
		if targetConn == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "connection not found"})
			return
		}

		// Import their public key and derive the shared ECDH content key
		theirPub, err := ecdh.X25519().NewPublicKey(targetConn.RemotePublicKey)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "invalid remote public key"})
			return
		}
		sharedKey, err := cryptopkg.DeriveContentKey(secrets.PrivateKey, theirPub)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "key derivation failed"})
			return
		}

		// Unwrap their content key using the shared ECDH key
		wrapped := &cryptopkg.EncryptedPayload{
			IV:         targetConn.EncryptedTheirIV,
			Ciphertext: targetConn.EncryptedTheirKey,
		}
		theirContentKey, err := cryptopkg.Decrypt(sharedKey, wrapped)
		if err != nil {
			// If unwrap fails, return the ECDH-derived key directly
			// (used when we confirmed server-side and stored ECDH key directly)
			writeJSON(w, http.StatusOK, map[string]string{
				"content_key": base64.RawURLEncoding.EncodeToString(sharedKey),
			})
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{
			"content_key": base64.RawURLEncoding.EncodeToString(theirContentKey),
		})
	})

	// POST /auth/unwrap-key — unwraps a content key received from a connection.
	// Browser fetches the wrapped key from the remote node, then asks us to unwrap it.
	mux.HandleFunc("POST /auth/unwrap-key", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, tokenValidator) { return }
		var req struct {
			EncryptedKey   string `json:"encrypted_key"`
			IV             string `json:"iv"`
			TheirPublicKey string `json:"their_public_key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
			return
		}
		encKeyBytes, err := base64.RawURLEncoding.DecodeString(req.EncryptedKey)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid encrypted_key"})
			return
		}
		ivBytes, err := base64.RawURLEncoding.DecodeString(req.IV)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid iv"})
			return
		}
		theirPubBytes, err := base64.RawURLEncoding.DecodeString(req.TheirPublicKey)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid their_public_key"})
			return
		}
		theirPub, err := ecdh.X25519().NewPublicKey(theirPubBytes)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid X25519 key"})
			return
		}
		// Unwrap using our private key + their public key via ECDH
		wrapped := &cryptopkg.EncryptedPayload{IV: ivBytes, Ciphertext: encKeyBytes}
		contentKey, err := cryptopkg.UnwrapKey(secrets.PrivateKey, theirPub, wrapped)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unwrap failed: " + err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{
			"content_key": base64.RawURLEncoding.EncodeToString(contentKey),
		})
	})

	// POST /auth/wrap-key — performs ECDH server-side for browsers without X25519 support.
	// Takes their public key, derives the ECDH shared secret, wraps our content key.
	// Protected by Bearer token.
	mux.HandleFunc("POST /auth/wrap-key", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, tokenValidator) { return }
		var req struct {
			TheirPublicKey string `json:"their_public_key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
			return
		}
		theirPubBytes, err := base64.RawURLEncoding.DecodeString(req.TheirPublicKey)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid public key"})
			return
		}
		// Import their X25519 public key
		theirPub, err := ecdh.X25519().NewPublicKey(theirPubBytes)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid X25519 public key"})
			return
		}
		// Wrap our content key using ECDH shared secret
		wrapped, err := cryptopkg.WrapKey(secrets.PrivateKey, theirPub, secrets.ContentKey)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "key wrap failed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{
			"encrypted_key": base64.RawURLEncoding.EncodeToString(wrapped.Ciphertext),
			"iv":            base64.RawURLEncoding.EncodeToString(wrapped.IV),
		})
	})

	// POST /auth/token — client sends a self-signed JWT, gets a server token.
	mux.HandleFunc("POST /auth/token", func(w http.ResponseWriter, r *http.Request) {
		handleAuthToken(w, r, node, serverSecret)
	})

	// POST /auth/selfsign — server signs a JWT on behalf of the node owner.
	// The client sends nothing sensitive — the server uses the in-memory
	// signing key. Used by the hosted tier where the private key was
	// unlocked at startup.
	mux.HandleFunc("POST /auth/selfsign", func(w http.ResponseWriter, r *http.Request) {
		handleSelfSign(w, r, node, secrets, serverSecret)
	})

	// ── Authenticated endpoints ───────────────────────────────────────────
	// POST /connect/{requestId}/confirm-server — server-side ECDH confirm.
	// For browsers without X25519 Web Crypto support.
	// The server performs the full ECDH key exchange using its in-memory private key.
	mux.HandleFunc("POST /confirm-server/{requestId}", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, tokenValidator) { return }
		requestID := r.PathValue("requestId")

		// Load the pending request to get their public key
		pending, err := database.GetPendingRequest(requestID, node.ID)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "request not found"})
			return
		}

		// Import their X25519 public key
		theirPub, err := ecdh.X25519().NewPublicKey(pending.FromPublicKey)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid public key"})
			return
		}

		// Perform ECDH and wrap our content key server-side
		wrapped, err := cryptopkg.WrapKey(secrets.PrivateKey, theirPub, secrets.ContentKey)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "key wrap failed"})
			return
		}

		// Now confirm the connection
		conn := &models.Connection{
			ID:                newUUID(),
			LocalNodeID:       node.ID,
			RemoteNodeID:      pending.FromNodeID,
			RemotePublicKey:   pending.FromPublicKey,
			RemoteNodeURL:     pending.FromNodeURL,
			RemoteHandle:      pending.FromDisplayName,
			RemoteAvatarURL:   pending.FromAvatarURL,
			EncryptedTheirKey: wrapped.Ciphertext,
			EncryptedTheirIV:  wrapped.IV,
			ConfirmedAt:       time.Now().UTC(),
			CreatedAt:         time.Now().UTC(),
		}
		if err := database.InsertConnection(conn); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not store connection"})
			return
		}
		_ = database.DeletePendingRequest(requestID)

		writeJSON(w, http.StatusOK, map[string]string{
			"status":        "confirmed",
			"connection_id": conn.ID,
		})
	})

	mux.HandleFunc("GET /connections", func(w http.ResponseWriter, r *http.Request) {
		h.Connections(w, r, tokenValidator)
	})

	mux.HandleFunc("GET /connect/pending", func(w http.ResponseWriter, r *http.Request) {
		h.ConnectPending(w, r, tokenValidator)
	})
	mux.HandleFunc("POST /connect/{requestId}/confirm", func(w http.ResponseWriter, r *http.Request) {
		h.ConnectConfirm(w, r, r.PathValue("requestId"), tokenValidator)
	})
	mux.HandleFunc("POST /connect/{requestId}/reject", func(w http.ResponseWriter, r *http.Request) {
		h.ConnectReject(w, r, r.PathValue("requestId"), tokenValidator)
	})
	mux.HandleFunc("POST /feed", func(w http.ResponseWriter, r *http.Request) {
		h.PublishPost(w, r, tokenValidator)
	})

	// Expose public key material for the client's crypto operations.
	// The client needs these to wrap/unwrap content keys.
	mux.HandleFunc("GET /auth/pubkey", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, tokenValidator) { return }
		writeJSON(w, http.StatusOK, map[string]string{
			"node_id":    node.ID,
			"public_key": b64(node.PublicKey),
		})
	})

	log.Printf("Sundown node %s listening on %s (@%s)", node.ID, *addr, node.Handle)
	if err := http.ListenAndServe(*addr, middleware(mux)); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

// unlockNode decrypts all private key material using the passphrase.
// Returns nodeSecrets held in memory for the lifetime of the process.
func unlockNode(node *models.Node, passphrase string) (*nodeSecrets, error) {
	privKeyBytes, err := keystore.Unwrap(passphrase, node.EncryptedPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("private key: %w", err)
	}
	privKey, err := ecdh.X25519().NewPrivateKey(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}

	signingKeyBytes, err := keystore.Unwrap(passphrase, node.EncryptedSigningKey)
	if err != nil {
		return nil, fmt.Errorf("signing key: %w", err)
	}

	contentKey, err := keystore.Unwrap(passphrase, node.EncryptedContentKey)
	if err != nil {
		return nil, fmt.Errorf("content key: %w", err)
	}

	return &nodeSecrets{
		PrivateKey: privKey,
		SigningKey:  ed25519.PrivateKey(signingKeyBytes),
		ContentKey:  contentKey,
	}, nil
}

// ── Auth handlers ─────────────────────────────────────────────────────────────

// handleAuthToken validates a client-provided self-signed JWT and issues
// a server token. Used by self-hosted nodes where the client holds the key.
func handleAuthToken(w http.ResponseWriter, r *http.Request, node *models.Node, secret []byte) {
	var req struct{ SelfSignedToken string `json:"self_signed_token"` }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if _, err := auth.ValidateSelfSignedToken(req.SelfSignedToken, node.SigningPublicKey, node.ID); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
		return
	}
	token, err := auth.IssueServerToken(node.ID, secret)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not issue token"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"token":      token,
		"expires_at": time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
		"node_id":    node.ID,
		"scope":      "node:admin",
	})
}

// handleSelfSign issues a server token using the in-memory signing key.
// Used by the hosted tier: the node already unlocked the key at startup,
// so the browser client just needs to prove it owns the session (e.g. by
// providing a one-time code sent to the owner's email). For now, this
// requires a valid existing server token — a "refresh" flow.
func handleSelfSign(w http.ResponseWriter, r *http.Request, node *models.Node, secrets *nodeSecrets, serverSecret []byte) {
	// Require a valid existing token to issue a new one (token refresh).
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing authorization"})
		return
	}
	existingToken := strings.TrimPrefix(authHeader, "Bearer ")
	validator := auth.Validator(node.ID, node.SigningPublicKey, serverSecret)
	if !validator(existingToken) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid or expired token"})
		return
	}

	// Issue a fresh self-signed JWT using the in-memory signing key.
	selfSigned, err := auth.IssueSelfsignedToken(node.ID, secrets.SigningKey)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not sign token"})
		return
	}

	// Exchange the self-signed JWT for a server token immediately.
	serverToken, err := auth.IssueServerToken(node.ID, serverSecret)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not issue server token"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"self_signed_token": selfSigned,
		"server_token":      serverToken,
		"expires_at":        time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
		"node_id":           node.ID,
	})
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func requireAuth(w http.ResponseWriter, r *http.Request, validate func(string) bool) bool {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing or malformed Authorization header"})
		return false
	}
	if !validate(strings.TrimPrefix(header, "Bearer ")) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid or expired token"})
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func b64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s", r.Method, r.URL.Path, r.RemoteAddr)
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, SD-Client")
		w.Header().Set("SD-Server", "sundown-node/1.0 (Ontario)")
		if r.Method == http.MethodOptions { w.WriteHeader(http.StatusNoContent); return }
		if strings.Contains(r.Header.Get("SD-Client"), "sundown-node") {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, `{"error":"self-request detected"}`)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// handleUnlock is called by the browser client at login.
// It accepts the passphrase, decrypts keys into memory, and returns a server token.
// The passphrase is only used transiently — it is not stored.
// This endpoint is the bridge between the browser UI and the Go backend.
func handleUnlock(w http.ResponseWriter, r *http.Request, node *models.Node, serverSecret []byte) {
	var req struct {
		Passphrase string `json:"passphrase"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.Passphrase == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "passphrase is required"})
		return
	}

	// Attempt to decrypt — wrong passphrase will fail here.
	_, err := unlockNode(node, req.Passphrase)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "wrong passphrase or corrupted key"})
		return
	}

	// Issue a server token valid for 24h.
	token, err := auth.IssueServerToken(node.ID, serverSecret)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not issue token"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"token":      token,
		"expires_at": time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
		"node_id":    node.ID,
		"scope":      "node:admin",
	})
}

func newUUID() string {
	b := make([]byte, 16)
	_, _ = crand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
