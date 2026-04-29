// Package db manages the SQLite database for a Sundown node.
// Each node is a single .db file — the entire social graph in one place.
package db

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3" // SQLite driver — registers itself via init()
	"github.com/sundown/sundown/internal/models"
)

// DB wraps the SQLite connection and provides typed query methods.
type DB struct {
	conn *sql.DB
}

// schema defines all tables. SQLite creates the file if it doesn't exist.
const schema = `
-- The node table holds exactly one row: this node's identity and keys.
CREATE TABLE IF NOT EXISTS node (
	id                    TEXT PRIMARY KEY,
	handle                TEXT NOT NULL UNIQUE,
	display_name          TEXT NOT NULL,
	avatar_url            TEXT NOT NULL DEFAULT '',
	bio                   BLOB,
	public_key            BLOB NOT NULL,
	encrypted_private_key BLOB NOT NULL,
	encrypted_content_key BLOB NOT NULL,
	encrypted_signing_key BLOB NOT NULL,
	signing_public_key    BLOB NOT NULL,
	public_mode           INTEGER NOT NULL DEFAULT 0,
	poll_interval_seconds INTEGER NOT NULL DEFAULT 60,
	poll_interval_max     INTEGER NOT NULL DEFAULT 900,
	theme                 BLOB,
	created_at            TEXT NOT NULL
);

-- Posts are always stored as ciphertext. The node never holds plaintext at rest.
CREATE TABLE IF NOT EXISTS posts (
	id         TEXT PRIMARY KEY,
	node_id    TEXT NOT NULL,
	iv         BLOB NOT NULL,
	body       BLOB NOT NULL,
	created_at TEXT NOT NULL,
	FOREIGN KEY (node_id) REFERENCES node(id)
);

-- Media blobs are stored on disk; this table holds references.
CREATE TABLE IF NOT EXISTS media (
	id      TEXT PRIMARY KEY,
	post_id TEXT NOT NULL,
	type    TEXT NOT NULL DEFAULT 'image',
	iv      BLOB NOT NULL,
	FOREIGN KEY (post_id) REFERENCES posts(id)
);

-- Confirmed mutual connections with other nodes.
CREATE TABLE IF NOT EXISTS connections (
	id                  TEXT PRIMARY KEY,
	local_node_id       TEXT NOT NULL,
	remote_node_id      TEXT NOT NULL UNIQUE,
	remote_public_key   BLOB NOT NULL,
	remote_node_url     TEXT NOT NULL,
	remote_handle       TEXT NOT NULL DEFAULT '',
	remote_avatar_url   TEXT NOT NULL DEFAULT '',
	encrypted_their_key BLOB NOT NULL,
	encrypted_their_iv  BLOB NOT NULL,
	confirmed_at        TEXT NOT NULL,
	created_at          TEXT NOT NULL,
	FOREIGN KEY (local_node_id) REFERENCES node(id)
);

-- Inbound connection requests awaiting the node owner's decision.
CREATE TABLE IF NOT EXISTS pending_requests (
	id               TEXT PRIMARY KEY,
	local_node_id    TEXT NOT NULL,
	from_node_id     TEXT NOT NULL,
	from_public_key  BLOB NOT NULL,
	from_display_name TEXT NOT NULL DEFAULT '',
	from_avatar_url  TEXT NOT NULL DEFAULT '',
	from_node_url    TEXT NOT NULL DEFAULT '',
	intro            TEXT NOT NULL DEFAULT '',
	received_at      TEXT NOT NULL,
	FOREIGN KEY (local_node_id) REFERENCES node(id)
);

-- Indexes for common query patterns.
CREATE INDEX IF NOT EXISTS idx_posts_node_created ON posts(node_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_connections_local   ON connections(local_node_id);
CREATE INDEX IF NOT EXISTS idx_pending_local       ON pending_requests(local_node_id);
`

// Open opens (or creates) the SQLite database at the given path and
// initialises the schema. Safe to call on an existing database.
func Open(path string) (*DB, error) {
	conn, err := sql.Open("sqlite3", path+"?_journal_mode=WAL&_foreign_keys=on")
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	// SQLite is not safe for concurrent writes from multiple goroutines
	// without WAL mode. Limit the pool to 1 writer.
	conn.SetMaxOpenConns(1)

	if _, err := conn.Exec(schema); err != nil {
		return nil, fmt.Errorf("initialising schema: %w", err)
	}

	return &DB{conn: conn}, nil
}

// Close closes the database connection.
func (db *DB) Close() error {
	return db.conn.Close()
}

// ── Node ─────────────────────────────────────────────────────────────────────

// InsertNode stores a newly created node. Called once during onboarding.
func (db *DB) InsertNode(n *models.Node) error {
	_, err := db.conn.Exec(`
		INSERT INTO node (
			id, handle, display_name, avatar_url, bio,
			public_key, encrypted_private_key, encrypted_content_key,
			encrypted_signing_key, signing_public_key,
			public_mode, poll_interval_seconds, poll_interval_max,
			theme, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		n.ID, n.Handle, n.DisplayName, n.AvatarURL, n.Bio,
		n.PublicKey, n.EncryptedPrivateKey, n.EncryptedContentKey,
		n.EncryptedSigningKey, n.SigningPublicKey,
		boolToInt(n.PublicMode), n.PollIntervalSeconds, n.PollIntervalMax,
		n.Theme, n.CreatedAt.UTC().Format(time.RFC3339),
	)
	return err
}

// GetNode retrieves the node row. Returns sql.ErrNoRows if not initialised.
func (db *DB) GetNode() (*models.Node, error) {
	row := db.conn.QueryRow(`SELECT
		id, handle, display_name, avatar_url, bio,
		public_key, encrypted_private_key, encrypted_content_key,
		encrypted_signing_key, signing_public_key,
		public_mode, poll_interval_seconds, poll_interval_max,
		theme, created_at
		FROM node LIMIT 1`)

	var n models.Node
	var publicMode int
	var createdAt string

	err := row.Scan(
		&n.ID, &n.Handle, &n.DisplayName, &n.AvatarURL, &n.Bio,
		&n.PublicKey, &n.EncryptedPrivateKey, &n.EncryptedContentKey,
		&n.EncryptedSigningKey, &n.SigningPublicKey,
		&publicMode, &n.PollIntervalSeconds, &n.PollIntervalMax,
		&n.Theme, &createdAt,
	)
	if err != nil {
		return nil, err
	}
	n.PublicMode = publicMode == 1
	n.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	return &n, nil
}

// UpdateTheme updates the node's theme JSON.
func (db *DB) UpdateTheme(nodeID string, theme []byte) error {
	_, err := db.conn.Exec(`UPDATE node SET theme = ? WHERE id = ?`, theme, nodeID)
	return err
}

// ── Posts ─────────────────────────────────────────────────────────────────────

// InsertPost stores a new encrypted post.
func (db *DB) InsertPost(p *models.Post) error {
	_, err := db.conn.Exec(`
		INSERT INTO posts (id, node_id, iv, body, created_at)
		VALUES (?, ?, ?, ?, ?)`,
		p.ID, p.NodeID, p.IV, p.Body,
		p.CreatedAt.UTC().Format(time.RFC3339),
	)
	return err
}

// ListPosts returns posts for a node, newest first, with optional since filter
// and cursor-based pagination. All content is ciphertext — no decryption here.
func (db *DB) ListPosts(nodeID string, since time.Time, limit int, cursor string) ([]*models.Post, string, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}

	var rows *sql.Rows
	var err error

	// cursor is the created_at of the last item on the previous page.
	if cursor != "" {
		rows, err = db.conn.Query(`
			SELECT id, node_id, iv, body, created_at FROM posts
			WHERE node_id = ? AND created_at > ? AND created_at < ?
			ORDER BY created_at DESC LIMIT ?`,
			nodeID, since.UTC().Format(time.RFC3339), cursor, limit+1,
		)
	} else {
		rows, err = db.conn.Query(`
			SELECT id, node_id, iv, body, created_at FROM posts
			WHERE node_id = ? AND created_at > ?
			ORDER BY created_at DESC LIMIT ?`,
			nodeID, since.UTC().Format(time.RFC3339), limit+1,
		)
	}
	if err != nil {
		return nil, "", fmt.Errorf("querying posts: %w", err)
	}
	defer rows.Close()

	var posts []*models.Post
	for rows.Next() {
		var p models.Post
		var createdAt string
		if err := rows.Scan(&p.ID, &p.NodeID, &p.IV, &p.Body, &createdAt); err != nil {
			return nil, "", err
		}
		p.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		posts = append(posts, &p)
	}

	// If we got limit+1 results, there is a next page.
	var nextCursor string
	if len(posts) > limit {
		nextCursor = posts[limit].CreatedAt.UTC().Format(time.RFC3339)
		posts = posts[:limit]
	}

	return posts, nextCursor, nil
}

// ── Connections ───────────────────────────────────────────────────────────────

// InsertConnection stores a confirmed connection.
func (db *DB) InsertConnection(c *models.Connection) error {
	_, err := db.conn.Exec(`
		INSERT INTO connections (
			id, local_node_id, remote_node_id, remote_public_key,
			remote_node_url, remote_handle, remote_avatar_url,
			encrypted_their_key, encrypted_their_iv,
			confirmed_at, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.LocalNodeID, c.RemoteNodeID, c.RemotePublicKey,
		c.RemoteNodeURL, c.RemoteHandle, c.RemoteAvatarURL,
		c.EncryptedTheirKey, c.EncryptedTheirIV,
		c.ConfirmedAt.UTC().Format(time.RFC3339),
		c.CreatedAt.UTC().Format(time.RFC3339),
	)
	return err
}

// ListConnections returns all confirmed connections for a node.
func (db *DB) ListConnections(nodeID string) ([]*models.Connection, error) {
	rows, err := db.conn.Query(`
		SELECT id, local_node_id, remote_node_id, remote_public_key,
		       remote_node_url, remote_handle, remote_avatar_url,
		       encrypted_their_key, encrypted_their_iv,
		       confirmed_at, created_at
		FROM connections WHERE local_node_id = ?`, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*models.Connection
	for rows.Next() {
		var c models.Connection
		var confirmedAt, createdAt string
		err := rows.Scan(
			&c.ID, &c.LocalNodeID, &c.RemoteNodeID, &c.RemotePublicKey,
			&c.RemoteNodeURL, &c.RemoteHandle, &c.RemoteAvatarURL,
			&c.EncryptedTheirKey, &c.EncryptedTheirIV,
			&confirmedAt, &createdAt,
		)
		if err != nil {
			return nil, err
		}
		c.ConfirmedAt, _ = time.Parse(time.RFC3339, confirmedAt)
		c.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		out = append(out, &c)
	}
	return out, nil
}

// DeleteConnection removes a connection. Used before calling UpdateContentKey
// to exclude a removed connection from the new key distribution.
func (db *DB) DeleteConnection(connectionID string) error {
	_, err := db.conn.Exec(`DELETE FROM connections WHERE id = ?`, connectionID)
	return err
}

// ── Pending requests ──────────────────────────────────────────────────────────

// InsertPendingRequest stores an inbound connection request.
func (db *DB) InsertPendingRequest(r *models.PendingRequest) error {
	_, err := db.conn.Exec(`
		INSERT INTO pending_requests (
			id, local_node_id, from_node_id, from_public_key,
			from_display_name, from_avatar_url, from_node_url,
			intro, received_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.LocalNodeID, r.FromNodeID, r.FromPublicKey,
		r.FromDisplayName, r.FromAvatarURL, r.FromNodeURL,
		r.Intro, r.ReceivedAt.UTC().Format(time.RFC3339),
	)
	return err
}

// ListPendingRequests returns all pending inbound requests for a node.
func (db *DB) ListPendingRequests(nodeID string) ([]*models.PendingRequest, error) {
	rows, err := db.conn.Query(`
		SELECT id, local_node_id, from_node_id, from_public_key,
		       from_display_name, from_avatar_url, from_node_url,
		       intro, received_at
		FROM pending_requests WHERE local_node_id = ? ORDER BY received_at DESC`,
		nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*models.PendingRequest
	for rows.Next() {
		var r models.PendingRequest
		var receivedAt string
		err := rows.Scan(
			&r.ID, &r.LocalNodeID, &r.FromNodeID, &r.FromPublicKey,
			&r.FromDisplayName, &r.FromAvatarURL, &r.FromNodeURL,
			&r.Intro, &receivedAt,
		)
		if err != nil {
			return nil, err
		}
		r.ReceivedAt, _ = time.Parse(time.RFC3339, receivedAt)
		out = append(out, &r)
	}
	return out, nil
}

// GetPendingRequest retrieves a specific pending request by ID.
func (db *DB) GetPendingRequest(requestID, nodeID string) (*models.PendingRequest, error) {
	row := db.conn.QueryRow(`
		SELECT id, local_node_id, from_node_id, from_public_key,
		       from_display_name, from_avatar_url, from_node_url,
		       intro, received_at
		FROM pending_requests WHERE id = ? AND local_node_id = ?`,
		requestID, nodeID)

	var r models.PendingRequest
	var receivedAt string
	err := row.Scan(
		&r.ID, &r.LocalNodeID, &r.FromNodeID, &r.FromPublicKey,
		&r.FromDisplayName, &r.FromAvatarURL, &r.FromNodeURL,
		&r.Intro, &receivedAt,
	)
	if err != nil {
		return nil, err
	}
	r.ReceivedAt, _ = time.Parse(time.RFC3339, receivedAt)
	return &r, nil
}

// DeletePendingRequest removes a pending request after it is confirmed or rejected.
func (db *DB) DeletePendingRequest(requestID string) error {
	_, err := db.conn.Exec(`DELETE FROM pending_requests WHERE id = ?`, requestID)
	return err
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
