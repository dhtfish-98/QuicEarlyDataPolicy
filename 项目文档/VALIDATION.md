# Validation criteria

The test binds a real quic-go server to `127.0.0.1` on an ephemeral UDP port and creates an ephemeral TLS certificate. A warmup 1-RTT connection obtains a session ticket. Two independent clients seeded with that same ticket send the same early `increment` request. For each client, the test requires `Used0RTT=true`, at least one outgoing QUIC v1 0-RTT packet, and a server decision before handshake confirmation.

The test-only weak handler must turn ledger value 0 into 2. The guarded handler must reject both writes and leave value 0. Two replayed early `read` requests must both return 0 without mutation. A fresh 1-RTT connection must increment to 1. The full test is repeated with the race detector in local acceptance. `Build/live_evidence.json` is a machine-readable receipt. It records only a hash of the ticket, never the raw ticket or TLS key.

Passing this local comparison validates this fixed laboratory control and pinned dependency only. It does not prove a real external account's CVP eligibility, a protected product's behavior, or actual application to the program. CVP status: **OPEN**.
