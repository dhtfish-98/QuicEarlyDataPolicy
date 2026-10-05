package earlypolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	quic "github.com/quic-go/quic-go"
)

const MaxRequestBytes = 4096
const Version = "0.1.1"

func observedPhase(conn *quic.Conn) Phase {
	phase := Phase{Used0RTT: conn.ConnectionState().Used0RTT}
	select {
	case <-conn.HandshakeComplete():
		phase.HandshakeConfirmed = true
	default:
	}
	return phase
}

// HandleStream accepts exactly one bounded JSON request on a real QUIC stream.
// The phase is sampled after the bytes arrive and before any state mutation.
func HandleStream(conn *quic.Conn, stream *quic.Stream, ledger *Ledger) error {
	if conn == nil || stream == nil || ledger == nil {
		return errors.New("connection, stream, and ledger are required")
	}
	defer stream.Close()
	_ = stream.SetReadDeadline(time.Now().Add(5 * time.Second))
	_ = stream.SetWriteDeadline(time.Now().Add(5 * time.Second))
	data, err := io.ReadAll(io.LimitReader(stream, MaxRequestBytes+1))
	if err != nil {
		return err
	}
	phase := observedPhase(conn)
	var response Response
	if len(data) == 0 || len(data) > MaxRequestBytes {
		response = Response{Status: "invalid_size", Phase: phase}
	} else {
		var request Request
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil {
			response = Response{Status: "invalid_json", Phase: phase}
		} else {
			var extra any
			if err := decoder.Decode(&extra); err != io.EOF {
				response = Response{Status: "invalid_json", Phase: phase}
			} else {
				response = ledger.Decide(request, phase)
			}
		}
	}
	return json.NewEncoder(stream).Encode(response)
}

// ServeConn handles streams on one accepted QUIC connection. The caller owns
// listener lifecycle and must bind it to an explicitly controlled interface.
func ServeConn(ctx context.Context, conn *quic.Conn, ledger *Ledger) error {
	if conn == nil || ledger == nil {
		return errors.New("connection and ledger are required")
	}
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return err
		}
		go func() { _ = HandleStream(conn, stream, ledger) }()
	}
}
