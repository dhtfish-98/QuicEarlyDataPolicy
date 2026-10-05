# Threat model and decision boundary

The relevant protocol risk is replayable 0-RTT application data. This repository demonstrates an application-layer operation matrix for an **owned** QUIC server. It does not claim a defect in quic-go. The weak baseline exists only in `tests/live_quic_test.go`; it bypasses the policy and increments state on each early request. The shipped handler reads transport-observed handshake and 0-RTT state, never a client-supplied phase field.

| Operation | Unconfirmed handshake | Confirmed connection that used 0-RTT | Fresh confirmed 1-RTT connection |
| --- | --- | --- | --- |
| `read` | Allowed | Allowed | Allowed |
| `increment` | Rejected | Rejected | Allowed |

`Used0RTT` is a connection-level signal in the pinned quic-go API. The policy therefore rejects mutation on the whole connection after it uses 0-RTT, including streams sent after confirmation. This conservative choice closes a timing ambiguity without claiming per-stream classification. The demonstration's `read` returns only a public in-memory integer and does not establish that arbitrary reads of sensitive data are safe in early data.

The local test reuses a TLS ticket on two new clients and sends the same logical application request. It is a ticket/application replay comparison, not byte-identical UDP replay. Packet header inspection proves the clients emitted QUIC v1 0-RTT packets, while the server response and ledger prove the application effect. The packet parser cannot decrypt payloads on its own.

Limits: no user authentication, durable ledger, distributed replay cache, admission control, certificate management, or cross-process consistency. A real service must implement these separately. This repository is a defensive control example, not a complete production service or evidence of program acceptance.
