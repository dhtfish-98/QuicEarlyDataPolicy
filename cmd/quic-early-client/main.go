package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	policy "github.com/dhtfish-98/QuicEarlyDataPolicy"
	quic "github.com/quic-go/quic-go"
)

func main() {
	address := flag.String("addr", "127.0.0.1:4433", "server UDP address")
	caPath := flag.String("ca", "", "trusted server certificate PEM path")
	operation := flag.String("operation", "read", "read or increment")
	key := flag.String("key", "account-1", "ledger key")
	delta := flag.Int("delta", 0, "increment amount")
	flag.Parse()
	if *caPath == "" {
		fmt.Fprintln(os.Stderr, "-ca is required")
		os.Exit(2)
	}
	certificate, err := os.ReadFile(*caPath)
	if err != nil {
		fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificate) {
		fatal(fmt.Errorf("-ca contains no certificates"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, *address, &tls.Config{
		RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS13, NextProtos: []string{"qedp/1"},
	}, &quic.Config{Versions: []quic.Version{quic.Version1}})
	if err != nil {
		fatal(err)
	}
	defer conn.CloseWithError(0, "")
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		fatal(err)
	}
	_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
	if err := json.NewEncoder(stream).Encode(policy.Request{Operation: *operation, Key: *key, Delta: *delta}); err != nil {
		fatal(err)
	}
	if err := stream.Close(); err != nil {
		fatal(err)
	}
	var result policy.Response
	if err := json.NewDecoder(stream).Decode(&result); err != nil {
		fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
