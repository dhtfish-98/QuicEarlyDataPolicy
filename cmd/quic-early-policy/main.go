package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	policy "github.com/dhtfish-98/QuicEarlyDataPolicy"
	quic "github.com/quic-go/quic-go"
)

func main() {
	address := flag.String("addr", "127.0.0.1:4433", "UDP listen address")
	certPath := flag.String("cert", "", "TLS certificate PEM path")
	keyPath := flag.String("key", "", "TLS private key PEM path")
	version := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *version {
		fmt.Println(policy.Version)
		return
	}
	if *certPath == "" || *keyPath == "" {
		fmt.Fprintln(os.Stderr, "-cert and -key are required")
		os.Exit(2)
	}
	pair, err := tls.LoadX509KeyPair(*certPath, *keyPath)
	if err != nil {
		log.Fatal(err)
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13, NextProtos: []string{"qedp/1"}}
	listener, err := quic.ListenAddrEarly(*address, tlsConfig, &quic.Config{Allow0RTT: true, Versions: []quic.Version{quic.Version1}})
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	ledger := policy.NewLedger()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Printf("QuicEarlyDataPolicy %s listening on %s", policy.Version, listener.Addr())
	for {
		conn, err := listener.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, context.Canceled) {
				return
			}
			log.Fatal(err)
		}
		go func() {
			defer conn.CloseWithError(0, "")
			if err := policy.ServeConn(ctx, conn, ledger); err != nil && ctx.Err() == nil {
				log.Printf("connection closed: %v", err)
			}
		}()
	}
}
