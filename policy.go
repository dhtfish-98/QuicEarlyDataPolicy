package earlypolicy

import (
	"sync"
)

// Request is the complete one-message application protocol used by this policy.
// Operation "read" is safe in early data. Operation "increment" changes state.
type Request struct {
	Operation string `json:"operation"`
	Key       string `json:"key"`
	Delta     int    `json:"delta,omitempty"`
}

// Phase comes from the QUIC connection, never from a client-supplied field.
type Phase struct {
	HandshakeConfirmed bool `json:"handshake_confirmed"`
	Used0RTT           bool `json:"used_0rtt"`
}

// Response records the application decision and the observed transport phase.
type Response struct {
	Status string `json:"status"`
	Value  int    `json:"value"`
	Phase  Phase  `json:"phase"`
}

// Ledger is a single-process demonstration store. It is not durable storage.
type Ledger struct {
	mu     sync.Mutex
	values map[string]int
}

func NewLedger() *Ledger {
	return &Ledger{values: make(map[string]int)}
}

func validKey(key string) bool {
	if len(key) == 0 || len(key) > 64 {
		return false
	}
	for _, b := range []byte(key) {
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-' || b == '_') {
			return false
		}
	}
	return true
}

// Decide applies the operation matrix atomically. A connection that accepted
// 0-RTT cannot mutate state even after its handshake later completes. This
// conservative rule avoids relying on a per-stream early-data marker.
func (l *Ledger) Decide(req Request, phase Phase) Response {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !validKey(req.Key) {
		return Response{Status: "invalid_key", Phase: phase}
	}
	value := l.values[req.Key]
	switch req.Operation {
	case "read":
		if req.Delta != 0 {
			return Response{Status: "invalid_read", Value: value, Phase: phase}
		}
		return Response{Status: "ok", Value: value, Phase: phase}
	case "increment":
		if req.Delta < 1 || req.Delta > 10 {
			return Response{Status: "invalid_delta", Value: value, Phase: phase}
		}
		if !phase.HandshakeConfirmed || phase.Used0RTT {
			return Response{Status: "early_rejected", Value: value, Phase: phase}
		}
		l.values[req.Key] = value + req.Delta
		return Response{Status: "ok", Value: value + req.Delta, Phase: phase}
	default:
		return Response{Status: "unknown_operation", Value: value, Phase: phase}
	}
}

func (l *Ledger) Value(key string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.values[key]
}
