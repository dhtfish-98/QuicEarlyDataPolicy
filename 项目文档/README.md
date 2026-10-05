# QuicEarlyDataPolicy 0.1.1

Author: **dhtfish98**

Version 0.1.1 updates release metadata and bundles the exact licenses for compiled dependencies; the application policy and replay experiment are unchanged from 0.1.0. The published 0.1.0 release remains a historical artifact.

This is an independently written, loopback-first QUIC application policy demonstration. A real `quic-go` server accepts 0-RTT streams, but the application permits only the `read` operation before handshake confirmation. The `increment` operation is rejected on every connection that used 0-RTT, even if that connection's handshake completes later. A fresh, fully confirmed 1-RTT connection can increment the in-memory value.

The live test uses two independent clients initialized with the same TLS session ticket and the same request. It compares a deliberately weak **test-only** handler with the guarded handler, checks application state, and counts outgoing QUIC v1 0-RTT packet headers. It does not replay identical UDP ciphertext. The test never contacts a third-party host.

## Build and verify

Run from the repository root with Go 1.26.2 or newer. All generated files stay under `Build`.

```sh
mkdir -p Build/gocache Build/modcache Build/tmp Build/bin
GOCACHE="$PWD/Build/gocache" GOMODCACHE="$PWD/Build/modcache" GOTMPDIR="$PWD/Build/tmp" go mod download
GOCACHE="$PWD/Build/gocache" GOMODCACHE="$PWD/Build/modcache" GOTMPDIR="$PWD/Build/tmp" go mod verify
GOCACHE="$PWD/Build/gocache" GOMODCACHE="$PWD/Build/modcache" GOTMPDIR="$PWD/Build/tmp" QEDP_EVIDENCE_PATH="$PWD/Build/live_evidence.json" go test -race ./... -count=1
GOCACHE="$PWD/Build/gocache" GOMODCACHE="$PWD/Build/modcache" GOTMPDIR="$PWD/Build/tmp" go build -o Build/bin/quic-early-policy ./cmd/quic-early-policy
GOCACHE="$PWD/Build/gocache" GOMODCACHE="$PWD/Build/modcache" GOTMPDIR="$PWD/Build/tmp" go build -o Build/bin/quic-early-client ./cmd/quic-early-client
Build/bin/quic-early-policy -version
```

For a local standalone server, supply a certificate and key. This sample creates short-lived development credentials under `Build`:

```sh
mkdir -p Build/certs
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj /CN=localhost -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' -keyout Build/certs/key.pem -out Build/certs/cert.pem
Build/bin/quic-early-policy -addr 127.0.0.1:4433 -cert Build/certs/cert.pem -key Build/certs/key.pem
```

From another terminal in the same repository:

```sh
Build/bin/quic-early-client -addr 127.0.0.1:4433 -ca Build/certs/cert.pem -operation read -key account-1
Build/bin/quic-early-client -addr 127.0.0.1:4433 -ca Build/certs/cert.pem -operation increment -key account-1 -delta 1
```

The wire protocol is one JSON object per QUIC stream, followed by the write-side FIN. Examples are `{"operation":"read","key":"account-1"}` and `{"operation":"increment","key":"account-1","delta":1}`. The response contains `status`, `value`, and server-observed `phase`. The server binds to loopback by default and stores state only in memory.

See [Validation](VALIDATION.md), [Threat model](THREAT_MODEL.md), and [Origin and rights](ORIGIN.md). Engineering validation does not establish eligibility for or approval by Anthropic's Cyber Verification Program; the application evidence gate remains **OPEN**.
