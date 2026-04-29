// Command register signs and submits a node registration to a yellow pages server.
// Used for testing and for the node's periodic heartbeat.
//
// Usage:
//
//	register --db ./sundown.db --yp http://localhost:9091 --node-url https://john.example.com
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/sundown/sundown/internal/db"
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func main() {
	dbPath  := flag.String("db", "./sundown.db", "node database")
	ypURL   := flag.String("yp", "http://localhost:9091", "yellow pages base URL")
	nodeURL := flag.String("node-url", "", "this node's public URL (e.g. https://john.example.com)")
	flag.Parse()

	if *nodeURL == "" {
		log.Fatal("--node-url is required")
	}

	database, err := db.Open(*dbPath)
	if err != nil { log.Fatalf("opening db: %v", err) }
	defer database.Close()

	node, err := database.GetNode()
	if err != nil { log.Fatalf("node not initialised: %v", err) }

	// Sign node_id + node_url with the Ed25519 signing key.
	// Spec Section 10.1: signature = Ed25519-Sign(node_id + node_url, ed25519_priv)
	message := []byte(node.ID + *nodeURL)
	// NOTE: signing key is stored unencrypted for now (passphrase encryption is TODO)
	signingKey := ed25519.PrivateKey(node.EncryptedSigningKey)
	sig := ed25519.Sign(signingKey, message)

	payload := map[string]string{
		"node_id":      node.ID,
		"handle":       node.Handle,
		"display_name": node.DisplayName,
		"node_url":     *nodeURL,
		"public_key":   b64(node.PublicKey),
		"signing_key":  b64([]byte(signingKey.Public().(ed25519.PublicKey))),
		"signature":    b64(sig),
	}

	body, _ := json.Marshal(payload)
	resp, err := http.Post(*ypURL+"/directory/register", "application/json", bytes.NewReader(body))
	if err != nil { log.Fatalf("HTTP request: %v", err) }
	defer resp.Body.Close()

	var result map[string]string
	json.NewDecoder(resp.Body).Decode(&result)

	if resp.StatusCode == http.StatusOK {
		fmt.Printf("Registered: %s (@%s) → %s\n", node.ID, node.Handle, *nodeURL)
	} else {
		fmt.Printf("Registration failed (%d): %s\n", resp.StatusCode, result["error"])
	}
}
