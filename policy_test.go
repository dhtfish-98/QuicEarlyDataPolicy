package earlypolicy

import "testing"

func TestOperationMatrix(t *testing.T) {
	cases := []struct {
		name   string
		phase  Phase
		req    Request
		status string
		value  int
	}{
		{"early_read", Phase{Used0RTT: true}, Request{Operation: "read", Key: "ledger-1"}, "ok", 0},
		{"early_write", Phase{Used0RTT: true}, Request{Operation: "increment", Key: "ledger-1", Delta: 1}, "early_rejected", 0},
		{"unconfirmed_write", Phase{}, Request{Operation: "increment", Key: "ledger-1", Delta: 1}, "early_rejected", 0},
		{"resumed_after_handshake_write", Phase{HandshakeConfirmed: true, Used0RTT: true}, Request{Operation: "increment", Key: "ledger-1", Delta: 1}, "early_rejected", 0},
		{"fresh_after_handshake_write", Phase{HandshakeConfirmed: true}, Request{Operation: "increment", Key: "ledger-1", Delta: 1}, "ok", 1},
		{"read_after_write", Phase{HandshakeConfirmed: true}, Request{Operation: "read", Key: "ledger-1"}, "ok", 1},
		{"bad_delta", Phase{HandshakeConfirmed: true}, Request{Operation: "increment", Key: "ledger-1", Delta: 11}, "invalid_delta", 1},
		{"bad_key", Phase{HandshakeConfirmed: true}, Request{Operation: "increment", Key: "../ledger", Delta: 1}, "invalid_key", 0},
		{"unknown_operation", Phase{HandshakeConfirmed: true}, Request{Operation: "delete", Key: "ledger-1"}, "unknown_operation", 1},
	}
	ledger := NewLedger()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ledger.Decide(tc.req, tc.phase)
			if got.Status != tc.status || got.Value != tc.value {
				t.Fatalf("got %+v; want %s value %d", got, tc.status, tc.value)
			}
		})
	}
	if ledger.Value("ledger-1") != 1 {
		t.Fatal("invalid or early operation mutated state")
	}
}
