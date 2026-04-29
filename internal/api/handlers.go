// Package api implements the Sundown node HTTP API.
// Every handler corresponds to an endpoint defined in the protocol spec (Section 6).
package api

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sundown/sundown/internal/db"
	"github.com/sundown/sundown/internal/models"
)

// Handler holds shared dependencies for all API handlers.
type Handler struct {
	DB     *db.DB
	NodeID string // cached from DB at startup
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func readJSON(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}

func b64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func unb64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// errResponse is the standard error response shape.
type errResponse struct {
	Error string `json:"error"`
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errResponse{Error: msg})
}

// requireAuth checks the Authorization: Bearer header against the node's
// token validator. Returns false and writes a 401 if auth fails.
// Auth token validation is wired in by the server setup — this handler
// package stays decoupled from the token implementation.
func requireAuth(w http.ResponseWriter, r *http.Request, validate func(string) bool) bool {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		writeErr(w, http.StatusUnauthorized, "missing or malformed Authorization header")
		return false
	}
	token := strings.TrimPrefix(header, "Bearer ")
	if !validate(token) {
		writeErr(w, http.StatusUnauthorized, "invalid or expired token")
		return false
	}
	return true
}

// ── Identity endpoints ────────────────────────────────────────────────────────

// WellKnown handles GET /.well-known/sundown.json
// Returns the node descriptor. Always public, no auth.
func (h *Handler) WellKnown(w http.ResponseWriter, r *http.Request) {
	node, err := h.DB.GetNode()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "node not initialised")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"sd_version":            "1.0",
		"node_id":               node.ID,
		"display_name":          node.DisplayName,
		"public_key":            b64(node.PublicKey),
		"public_mode":           node.PublicMode,
		"poll_interval_seconds": node.PollIntervalSeconds,
		"poll_interval_max":     node.PollIntervalMax,
		"endpoints": map[string]string{
			"profile": "/profile",
			"feed":    "/feed",
			"connect": "/connect",
		},
	})
}

// Profile handles GET /profile
// Returns the public profile. Always public, no auth.
func (h *Handler) Profile(w http.ResponseWriter, r *http.Request) {
	node, err := h.DB.GetNode()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "node not initialised")
		return
	}

	resp := map[string]any{
		"node_id":      node.ID,
		"display_name": node.DisplayName,
		"avatar_url":   node.AvatarURL,
		"public_key":   b64(node.PublicKey),
		"public_mode":  node.PublicMode,
		"created_at":   node.CreatedAt.UTC().Format(time.RFC3339),
	}

	// Bio may be nil (not set) or encrypted bytes.
	if node.Bio != nil {
		resp["bio"] = b64(node.Bio) // clients with the content key decrypt this
	}

	// Theme is always plaintext JSON.
	if node.Theme != nil {
		var theme any
		if json.Unmarshal(node.Theme, &theme) == nil {
			resp["theme"] = theme
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

// PubKey handles GET /pubkey
// Returns the raw X25519 public key as base64url. Always public.
func (h *Handler) PubKey(w http.ResponseWriter, r *http.Request) {
	node, err := h.DB.GetNode()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "node not initialised")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"public_key": b64(node.PublicKey),
	})
}

// ── Connection endpoints ──────────────────────────────────────────────────────

// Connect handles POST /connect
// Accepts an inbound connection request. No auth required — anyone can knock.
func (h *Handler) Connect(w http.ResponseWriter, r *http.Request) {
	var req struct {
		FromNodeID      string `json:"from_node_id"`
		FromPublicKey   string `json:"from_public_key"`
		FromDisplayName string `json:"from_display_name"`
		FromAvatarURL   string `json:"from_avatar_url"`
		FromNodeURL     string `json:"from_node_url"`
		Intro           string `json:"intro"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.FromNodeID == "" || req.FromPublicKey == "" {
		writeErr(w, http.StatusBadRequest, "from_node_id and from_public_key are required")
		return
	}

	// Enforce intro length limit (spec: 500 chars).
	if len([]rune(req.Intro)) > 500 {
		writeErr(w, http.StatusBadRequest, "intro exceeds 500 characters")
		return
	}

	pubKeyBytes, err := unb64(req.FromPublicKey)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "from_public_key must be base64url encoded")
		return
	}

	pending := &models.PendingRequest{
		ID:              newUUID(),
		LocalNodeID:     h.NodeID,
		FromNodeID:      req.FromNodeID,
		FromPublicKey:   pubKeyBytes,
		FromDisplayName: req.FromDisplayName,
		FromAvatarURL:   req.FromAvatarURL,
		FromNodeURL:     req.FromNodeURL,
		Intro:           req.Intro,
		ReceivedAt:      time.Now().UTC(),
	}

	if err := h.DB.InsertPendingRequest(pending); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not store request")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{
		"request_id": pending.ID,
		"status":     "pending",
	})
}

// ConnectPending handles GET /connect/pending — requires auth.
func (h *Handler) ConnectPending(w http.ResponseWriter, r *http.Request, validate func(string) bool) {
	if !requireAuth(w, r, validate) {
		return
	}

	requests, err := h.DB.ListPendingRequests(h.NodeID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not fetch pending requests")
		return
	}

	type pendingItem struct {
		RequestID       string `json:"request_id"`
		FromNodeID      string `json:"from_node_id"`
		FromPublicKey   string `json:"from_public_key"`
		FromDisplayName string `json:"from_display_name"`
		FromAvatarURL   string `json:"from_avatar_url"`
		FromNodeURL     string `json:"from_node_url"`
		Intro           string `json:"intro"`
		ReceivedAt      string `json:"received_at"`
	}

	items := make([]pendingItem, 0, len(requests))
	for _, req := range requests {
		items = append(items, pendingItem{
			RequestID:       req.ID,
			FromNodeID:      req.FromNodeID,
			FromPublicKey:   b64(req.FromPublicKey),
			FromDisplayName: req.FromDisplayName,
			FromAvatarURL:   req.FromAvatarURL,
			FromNodeURL:     req.FromNodeURL,
			Intro:           req.Intro,
			ReceivedAt:      req.ReceivedAt.Format(time.RFC3339),
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{"pending": items})
}

// ConnectConfirm handles POST /connect/{requestId}/confirm — requires auth.
// The encrypted_content_key is our content key wrapped for the requester.
func (h *Handler) ConnectConfirm(w http.ResponseWriter, r *http.Request, requestID string, validate func(string) bool) {
	if !requireAuth(w, r, validate) {
		return
	}

	pending, err := h.DB.GetPendingRequest(requestID, h.NodeID)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "request not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "database error")
		return
	}

	var req struct {
		EncryptedContentKey string `json:"encrypted_content_key"`
		IV                  string `json:"iv"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}

	encKeyBytes, err := unb64(req.EncryptedContentKey)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "encrypted_content_key must be base64url encoded")
		return
	}
	ivBytes, err := unb64(req.IV)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "iv must be base64url encoded")
		return
	}

	conn := &models.Connection{
		ID:                newUUID(),
		LocalNodeID:       h.NodeID,
		RemoteNodeID:      pending.FromNodeID,
		RemotePublicKey:   pending.FromPublicKey,
		RemoteNodeURL:     pending.FromNodeURL,
		RemoteHandle:      pending.FromDisplayName,
		RemoteAvatarURL:   pending.FromAvatarURL,
		EncryptedTheirKey: encKeyBytes,
		EncryptedTheirIV:  ivBytes,
		ConfirmedAt:       time.Now().UTC(),
		CreatedAt:         time.Now().UTC(),
	}

	if err := h.DB.InsertConnection(conn); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not store connection")
		return
	}

	if err := h.DB.DeletePendingRequest(requestID); err != nil {
		// Non-fatal — the connection is stored, cleanup can be retried.
		// Log in production but don't fail the response.
		_ = err
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status":        "confirmed",
		"connection_id": conn.ID,
	})
}

// ConnectReject handles POST /connect/{requestId}/reject — requires auth.
// Silent by design: no information is sent to the requester.
func (h *Handler) ConnectReject(w http.ResponseWriter, r *http.Request, requestID string, validate func(string) bool) {
	if !requireAuth(w, r, validate) {
		return
	}

	// We don't return 404 even if the request doesn't exist — silent rejection.
	_ = h.DB.DeletePendingRequest(requestID)

	writeJSON(w, http.StatusOK, map[string]string{"status": "rejected"})
}

// ── Content endpoints ─────────────────────────────────────────────────────────

// Feed handles GET /feed
// Returns encrypted posts. Always public — ciphertext is safe to serve openly.
func (h *Handler) Feed(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	// Parse ?since= — default to zero time (all posts).
	var since time.Time
	if s := q.Get("since"); s != "" {
		parsed, err := time.Parse(time.RFC3339, s)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "since must be RFC3339 format")
			return
		}
		since = parsed
	}

	// Parse ?limit= — default 20, max 100.
	limit := 20
	if l := q.Get("limit"); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n < 1 {
			writeErr(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		limit = n
	}

	cursor := q.Get("cursor")

	posts, nextCursor, err := h.DB.ListPosts(h.NodeID, since, limit, cursor)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not fetch posts")
		return
	}

	type postItem struct {
		PostID    string `json:"post_id"`
		CreatedAt string `json:"created_at"`
		IV        string `json:"iv"`
		Ciphertext string `json:"ciphertext"`
	}

	items := make([]postItem, 0, len(posts))
	for _, p := range posts {
		items = append(items, postItem{
			PostID:     p.ID,
			CreatedAt:  p.CreatedAt.Format(time.RFC3339),
			IV:         b64(p.IV),
			Ciphertext: b64(p.Body),
		})
	}

	resp := map[string]any{"posts": items}
	if nextCursor != "" {
		resp["next_cursor"] = nextCursor
	} else {
		resp["next_cursor"] = nil
	}

	writeJSON(w, http.StatusOK, resp)
}

// PublishPost handles POST /feed — requires auth.
// The client sends already-encrypted content. The server stores only ciphertext.
func (h *Handler) PublishPost(w http.ResponseWriter, r *http.Request, validate func(string) bool) {
	if !requireAuth(w, r, validate) {
		return
	}

	var req struct {
		IV         string `json:"iv"`
		Ciphertext string `json:"ciphertext"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}

	ivBytes, err := unb64(req.IV)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "iv must be base64url encoded")
		return
	}
	cipherBytes, err := unb64(req.Ciphertext)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "ciphertext must be base64url encoded")
		return
	}

	post := &models.Post{
		ID:        newUUID(),
		NodeID:    h.NodeID,
		IV:        ivBytes,
		Body:      cipherBytes,
		CreatedAt: time.Now().UTC(),
	}

	if err := h.DB.InsertPost(post); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not store post")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{
		"post_id":    post.ID,
		"created_at": post.CreatedAt.Format(time.RFC3339),
	})
}

// Connections handles GET /connections — requires auth.
// Returns all confirmed connections for this node.
func (h *Handler) Connections(w http.ResponseWriter, r *http.Request, validate func(string) bool) {
	if !requireAuth(w, r, validate) {
		return
	}

	conns, err := h.DB.ListConnections(h.NodeID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not fetch connections")
		return
	}

	type connItem struct {
		ID               string `json:"id"`
		RemoteNodeID     string `json:"remote_node_id"`
		RemoteHandle     string `json:"remote_handle"`
		RemoteNodeURL    string `json:"remote_node_url"`
		RemotePublicKey  string `json:"remote_public_key"`
		EncryptedTheirKey string `json:"encrypted_their_key"`
		EncryptedTheirIV  string `json:"encrypted_their_iv"`
		ConfirmedAt      string `json:"confirmed_at"`
	}

	items := make([]connItem, 0, len(conns))
	for _, c := range conns {
		items = append(items, connItem{
			ID:               c.ID,
			RemoteNodeID:     c.RemoteNodeID,
			RemoteHandle:     c.RemoteHandle,
			RemoteNodeURL:    c.RemoteNodeURL,
			RemotePublicKey:  b64(c.RemotePublicKey),
			EncryptedTheirKey: b64(c.EncryptedTheirKey),
			EncryptedTheirIV:  b64(c.EncryptedTheirIV),
			ConfirmedAt:      c.ConfirmedAt.Format("2006-01-02T15:04:05Z"),
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{"connections": items})
}
