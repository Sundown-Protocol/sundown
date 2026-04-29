# Sundown

**A decentralised, encrypted social network protocol.**

Version 1.0 — *Ontario*

Sundown is an open protocol for a private social network where every participant runs their own node. Content is encrypted by default. Connection establishment is the moment of mutual cryptographic trust. No central authority owns the social graph, stores content, or can read private posts.

## How it works

- Every user runs their own **node** — a small HTTP server
- Content is encrypted with **AES-256-GCM** before leaving your browser
- Connecting to someone requires **mutual confirmation**
- Once connected, both sides derive a shared secret via **X25519 ECDH** — no key is ever transmitted
- A **yellow pages** server handles discovery — it stores nothing except your name and URL

## Stack

| Layer | Technology |
|---|---|
| Backend | Go 1.22 |
| Database | SQLite (one file per node) |
| Key agreement | X25519 (RFC 7748) |
| Key derivation | HKDF-SHA-256 (RFC 5869) |
| Symmetric encryption | AES-256-GCM |
| Signatures | Ed25519 (RFC 8032) |
| Key storage | Argon2id + AES-256-GCM |
| Frontend | Vanilla HTML/JS, Web Crypto API |

## Prerequisites

- Go 1.22 or later
- GCC (for the SQLite driver)
- Linux or WSL2 on Windows

```bash
sudo apt update
sudo apt install -y golang-go gcc libsqlite3-dev
```

## Installation

```bash
git clone https://github.com/Sundown-Protocol/sundown.git
cd sundown
go mod tidy
go build -o sundown-node     ./cmd/node/
go build -o sundown-yp       ./cmd/yellowpages/
go build -o sundown-register ./cmd/register/
```

## Quick start

```bash
# Start yellow pages
./sundown-yp --db ./directory.db --addr :8081 --dev

# Create and start your node
./sundown-node init --db ./mynode.db --handle alice --name "Alice" --passphrase "your-long-passphrase"
./sundown-node serve --db ./mynode.db --addr :8080 --passphrase "your-long-passphrase"

# Register with yellow pages
./sundown-register --db ./mynode.db --yp http://localhost:8081 --node-url http://localhost:8080 --passphrase "your-long-passphrase"
```

Open `http://localhost:8080` in your browser to access the UI.

## Protocol specification

The full normative protocol specification is in `sundown-protocol-ontario.docx`. It defines all cryptographic primitives, endpoint contracts, the connection handshake, and conformance requirements for third-party implementations.

## Security model

- Private keys encrypted at rest with Argon2id + AES-256-GCM
- Posts encrypted client-side — the server stores only ciphertext
- ECDH key exchange — no content key is ever transmitted
- Silent connection rejection — requester cannot distinguish rejection from pending

## License

MIT
