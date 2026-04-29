// Package directory implements the yellow pages node database.
// A yellow pages node stores only: node_id → URL + public key + handle.
// No content. No social graph. No private data.
// Defined in spec Section 10.
package directory

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Entry is a single directory record — everything the yellow pages knows
// about a node. Intentionally minimal.
type Entry struct {
	NodeID      string    // "sd:..." — the node's cryptographic identity
	Handle      string    // local handle, e.g. "john"
	DisplayName string    // human-readable name
	NodeURL     string    // base URL of the node, e.g. "https://john.example.com"
	PublicKey   []byte    // raw X25519 public key bytes (for signature verification)
	RegisteredAt time.Time
	LastSeenAt   time.Time // updated on each heartbeat registration
}

// DB is the yellow pages SQLite database.
type DB struct {
	conn *sql.DB
}

const schema = `
-- One row per registered node. The yellow pages stores nothing else.
CREATE TABLE IF NOT EXISTS directory (
	node_id       TEXT PRIMARY KEY,
	handle        TEXT NOT NULL,
	display_name  TEXT NOT NULL DEFAULT '',
	node_url      TEXT NOT NULL,
	public_key    BLOB NOT NULL,
	registered_at TEXT NOT NULL,
	last_seen_at  TEXT NOT NULL
);

-- Index for handle-prefix search (the most common query pattern).
CREATE INDEX IF NOT EXISTS idx_handle ON directory(handle);
-- Index for expiry cleanup — entries not seen recently can be purged.
CREATE INDEX IF NOT EXISTS idx_last_seen ON directory(last_seen_at);
`

// Open opens (or creates) the yellow pages database at the given path.
func Open(path string) (*DB, error) {
	conn, err := sql.Open("sqlite3", path+"?_journal_mode=WAL&_foreign_keys=on")
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}
	conn.SetMaxOpenConns(1)
	if _, err := conn.Exec(schema); err != nil {
		return nil, fmt.Errorf("initialising schema: %w", err)
	}
	return &DB{conn: conn}, nil
}

// Close closes the database connection.
func (db *DB) Close() error { return db.conn.Close() }

// Upsert registers or updates a node entry. Safe to call on every heartbeat.
// If the node_id already exists, all fields are updated.
func (db *DB) Upsert(e *Entry) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := db.conn.Exec(`
		INSERT INTO directory
			(node_id, handle, display_name, node_url, public_key, registered_at, last_seen_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(node_id) DO UPDATE SET
			handle        = excluded.handle,
			display_name  = excluded.display_name,
			node_url      = excluded.node_url,
			public_key    = excluded.public_key,
			last_seen_at  = excluded.last_seen_at`,
		e.NodeID, e.Handle, e.DisplayName, e.NodeURL, e.PublicKey,
		now, now,
	)
	return err
}

// Search returns entries matching the query string against handle and
// display_name, up to limit results. Case-insensitive prefix match.
func (db *DB) Search(query string, limit int) ([]*Entry, error) {
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	// SQLite LIKE is case-insensitive for ASCII by default.
	pattern := query + "%"
	rows, err := db.conn.Query(`
		SELECT node_id, handle, display_name, node_url, public_key, registered_at, last_seen_at
		FROM directory
		WHERE handle LIKE ? OR display_name LIKE ?
		ORDER BY last_seen_at DESC
		LIMIT ?`,
		pattern, pattern, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("searching directory: %w", err)
	}
	defer rows.Close()

	var out []*Entry
	for rows.Next() {
		var e Entry
		var registeredAt, lastSeenAt string
		if err := rows.Scan(
			&e.NodeID, &e.Handle, &e.DisplayName, &e.NodeURL, &e.PublicKey,
			&registeredAt, &lastSeenAt,
		); err != nil {
			return nil, err
		}
		e.RegisteredAt, _ = time.Parse(time.RFC3339, registeredAt)
		e.LastSeenAt, _ = time.Parse(time.RFC3339, lastSeenAt)
		out = append(out, &e)
	}
	return out, nil
}

// GetByNodeID looks up a specific node by its ID. Used to check if a node
// is already registered before deciding insert vs update.
func (db *DB) GetByNodeID(nodeID string) (*Entry, error) {
	row := db.conn.QueryRow(`
		SELECT node_id, handle, display_name, node_url, public_key, registered_at, last_seen_at
		FROM directory WHERE node_id = ?`, nodeID)

	var e Entry
	var registeredAt, lastSeenAt string
	err := row.Scan(
		&e.NodeID, &e.Handle, &e.DisplayName, &e.NodeURL, &e.PublicKey,
		&registeredAt, &lastSeenAt,
	)
	if err != nil {
		return nil, err
	}
	e.RegisteredAt, _ = time.Parse(time.RFC3339, registeredAt)
	e.LastSeenAt, _ = time.Parse(time.RFC3339, lastSeenAt)
	return &e, nil
}

// PurgeStale removes entries that have not sent a heartbeat within the
// given duration. Called periodically to keep the directory fresh.
// Spec recommendation: expire entries not refreshed within 72 hours.
func (db *DB) PurgeStale(olderThan time.Duration) (int64, error) {
	cutoff := time.Now().UTC().Add(-olderThan).Format(time.RFC3339)
	result, err := db.conn.Exec(
		`DELETE FROM directory WHERE last_seen_at < ?`, cutoff,
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// Count returns the total number of registered nodes.
func (db *DB) Count() (int64, error) {
	var n int64
	err := db.conn.QueryRow(`SELECT COUNT(*) FROM directory`).Scan(&n)
	return n, err
}
