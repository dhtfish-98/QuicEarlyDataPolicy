package tests

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	policy "github.com/dhtfish-98/QuicEarlyDataPolicy"
	quic "github.com/quic-go/quic-go"
)

// The intentionally weak handler appears only in this test. It models an
// application that uses a TLS ticket but forgets to gate non-idempotent work.
func weakHandleStream(conn *quic.Conn, stream *quic.Stream, ledger *policy.Ledger) error {
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
	var request policy.Request
	if err := json.NewDecoder(stream).Decode(&request); err != nil {
		return err
	}
	phase := phaseOf(conn)
	// Deliberately lie about the phase to model an unsafe application handler.
	decision := ledger.Decide(request, policy.Phase{HandshakeConfirmed: true})
	decision.Phase = phase
	return json.NewEncoder(stream).Encode(decision)
}

func phaseOf(conn *quic.Conn) policy.Phase {
	p := policy.Phase{Used0RTT: conn.ConnectionState().Used0RTT}
	select {
	case <-conn.HandshakeComplete():
		p.HandshakeConfirmed = true
	default:
	}
	return p
}

type sessionCache struct {
	mu    sync.Mutex
	state *tls.ClientSessionState
	puts  chan struct{}
}

func (c *sessionCache) Get(string) (*tls.ClientSessionState, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state, c.state != nil
}

func (c *sessionCache) Put(_ string, s *tls.ClientSessionState) {
	c.mu.Lock()
	c.state = s
	c.mu.Unlock()
	if c.puts != nil {
		select {
		case c.puts <- struct{}{}:
		default:
		}
	}
}

func (c *sessionCache) snapshot() *tls.ClientSessionState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

type packetMonitor struct {
	net.PacketConn
	mu         sync.Mutex
	zeroRTTPkt int
	v1Packets  int
}

func (m *packetMonitor) WriteTo(b []byte, a net.Addr) (int, error) {
	m.mu.Lock()
	for _, typ := range v1LongHeaderTypes(b) {
		m.v1Packets++
		if typ == 1 {
			m.zeroRTTPkt++
		}
	}
	m.mu.Unlock()
	return m.PacketConn.WriteTo(b, a)
}

func (m *packetMonitor) counts() (int, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.zeroRTTPkt, m.v1Packets
}

func readVarint(b []byte, p *int) (uint64, bool) {
	if *p >= len(b) {
		return 0, false
	}
	n := 1 << ((b[*p] & 0xc0) >> 6)
	if *p+n > len(b) {
		return 0, false
	}
	v := uint64(b[*p] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(b[*p+i])
	}
	*p += n
	return v, true
}

// QUIC v1 long-header bits 0x30 identify Initial=0, 0-RTT=1,
// Handshake=2, Retry=3. This parser inspects packet headers only.
func v1LongHeaderTypes(b []byte) []byte {
	var out []byte
	for p := 0; p < len(b); {
		start := p
		if b[p]&0x80 == 0 || p+7 > len(b) || binary.BigEndian.Uint32(b[p+1:p+5]) != 1 {
			break
		}
		typ := (b[p] >> 4) & 3
		p += 5
		d := int(b[p])
		p++
		if d > 20 || p+d+1 > len(b) {
			break
		}
		p += d
		s := int(b[p])
		p++
		if s > 20 || p+s > len(b) {
			break
		}
		p += s
		if typ == 0 {
			tokenLen, ok := readVarint(b, &p)
			if !ok || tokenLen > uint64(len(b)-p) {
				break
			}
			p += int(tokenLen)
		}
		if typ == 3 {
			out = append(out, typ)
			break
		}
		length, ok := readVarint(b, &p)
		if !ok || length > uint64(len(b)-p) {
			break
		}
		out = append(out, typ)
		p += int(length)
		if p <= start {
			break
		}
	}
	return out
}

func certificate(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pair := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	pool := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool.AddCert(parsed)
	return &tls.Config{Certificates: []tls.Certificate{pair}, NextProtos: []string{"qedp-lab"}, MinVersion: tls.VersionTLS13}, pool
}

type exchange struct {
	Response          policy.Response `json:"response"`
	ClientUsed0RTT    bool            `json:"client_used_0rtt"`
	ZeroRTTPackets    int             `json:"zero_rtt_packets"`
	QUICv1LongPackets int             `json:"quic_v1_long_packets"`
}

func request(t *testing.T, ctx context.Context, addr net.Addr, pool *x509.CertPool, cache tls.ClientSessionCache, early bool, req any) exchange {
	t.Helper()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	mon := &packetMonitor{PacketConn: udp}
	tlsConfig := &tls.Config{RootCAs: pool, ServerName: "localhost", NextProtos: []string{"qedp-lab"}, ClientSessionCache: cache, MinVersion: tls.VersionTLS13}
	config := &quic.Config{Versions: []quic.Version{quic.Version1}}
	var conn *quic.Conn
	if early {
		conn, err = quic.DialEarly(ctx, mon, addr, tlsConfig, config)
	} else {
		conn, err = quic.Dial(ctx, mon, addr, tlsConfig, config)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
	if err := json.NewEncoder(stream).Encode(req); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	var resp policy.Response
	if err := json.NewDecoder(stream).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	zero, total := mon.counts()
	return exchange{Response: resp, ClientUsed0RTT: conn.ConnectionState().Used0RTT, ZeroRTTPackets: zero, QUICv1LongPackets: total}
}

type scenarioEvidence struct {
	Warmup         exchange   `json:"warmup"`
	TicketSHA256   string     `json:"ticket_sha256"`
	ReplayWrites   []exchange `json:"replay_writes"`
	ReplayReads    []exchange `json:"replay_reads,omitempty"`
	ForgedPhase    *exchange  `json:"forged_client_phase,omitempty"`
	FinalValue     int        `json:"final_value"`
	Fresh1RTTWrite *exchange  `json:"fresh_1rtt_write,omitempty"`
}

type liveEvidence struct {
	Schema         int              `json:"schema"`
	UpstreamCommit string           `json:"upstream_commit"`
	Weak           scenarioEvidence `json:"weak_test_only"`
	Guarded        scenarioEvidence `json:"guarded"`
}

func scenario(t *testing.T, weak bool) scenarioEvidence {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	serverTLS, pool := certificate(t)
	listener, err := quic.ListenAddrEarly("127.0.0.1:0", serverTLS, &quic.Config{Allow0RTT: true, Versions: []quic.Version{quic.Version1}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ledger := policy.NewLedger()
	serverErrors := make(chan error, 32)
	go func() {
		for {
			conn, err := listener.Accept(ctx)
			if err != nil {
				return
			}
			go func() {
				defer conn.CloseWithError(0, "")
				for {
					stream, err := conn.AcceptStream(ctx)
					if err != nil {
						return
					}
					go func() {
						var handleErr error
						if weak {
							handleErr = weakHandleStream(conn, stream, ledger)
						} else {
							handleErr = policy.HandleStream(conn, stream, ledger)
						}
						if handleErr != nil && !errors.Is(handleErr, io.EOF) {
							select {
							case serverErrors <- handleErr:
							default:
							}
						}
					}()
				}
			}()
		}
	}()
	cache := &sessionCache{puts: make(chan struct{}, 4)}
	out := scenarioEvidence{}
	out.Warmup = request(t, ctx, listener.Addr(), pool, cache, false, policy.Request{Operation: "read", Key: "account-1"})
	select {
	case <-cache.puts:
	case <-ctx.Done():
		t.Fatal("server did not deliver a resumable TLS ticket")
	}
	state := cache.snapshot()
	if state == nil {
		t.Fatal("empty TLS session state")
	}
	ticket, _, err := state.ResumptionState()
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(ticket)
	out.TicketSHA256 = hex.EncodeToString(hash[:])
	for i := 0; i < 2; i++ {
		// Both independent clients begin with the same saved ticket and the
		// same operation. The resulting UDP ciphertext is not byte-identical.
		clientCache := &sessionCache{state: state}
		ex := request(t, ctx, listener.Addr(), pool, clientCache, true, policy.Request{Operation: "increment", Key: "account-1", Delta: 1})
		out.ReplayWrites = append(out.ReplayWrites, ex)
		if !ex.ClientUsed0RTT || ex.ZeroRTTPackets == 0 || !ex.Response.Phase.Used0RTT || ex.Response.Phase.HandshakeConfirmed {
			t.Fatalf("write %d did not execute as live 0-RTT: %+v", i, ex)
		}
	}
	if weak {
		out.FinalValue = ledger.Value("account-1")
		if out.FinalValue != 2 || out.ReplayWrites[0].Response.Status != "ok" || out.ReplayWrites[1].Response.Status != "ok" {
			t.Fatalf("weak baseline did not show duplicate mutation: %+v", out)
		}
	} else {
		for i := 0; i < 2; i++ {
			clientCache := &sessionCache{state: state}
			ex := request(t, ctx, listener.Addr(), pool, clientCache, true, policy.Request{Operation: "read", Key: "account-1"})
			out.ReplayReads = append(out.ReplayReads, ex)
			if !ex.ClientUsed0RTT || ex.ZeroRTTPackets == 0 || ex.Response.Status != "ok" || ex.Response.Value != 0 || !ex.Response.Phase.Used0RTT {
				t.Fatalf("safe early read %d failed: %+v", i, ex)
			}
		}
		if ledger.Value("account-1") != 0 || out.ReplayWrites[0].Response.Status != "early_rejected" || out.ReplayWrites[1].Response.Status != "early_rejected" {
			t.Fatalf("guarded baseline mutated or misclassified: %+v", out)
		}
		forged := request(t, ctx, listener.Addr(), pool, &sessionCache{state: state}, true,
			map[string]any{"operation": "increment", "key": "account-1", "delta": 1, "phase": map[string]any{"handshake_confirmed": true}})
		out.ForgedPhase = &forged
		if !forged.ClientUsed0RTT || forged.ZeroRTTPackets == 0 || forged.Response.Status != "invalid_json" || ledger.Value("account-1") != 0 {
			t.Fatalf("client-supplied phase was not rejected: %+v", forged)
		}
		fresh := request(t, ctx, listener.Addr(), pool, nil, false, policy.Request{Operation: "increment", Key: "account-1", Delta: 1})
		out.Fresh1RTTWrite = &fresh
		out.FinalValue = ledger.Value("account-1")
		if fresh.Response.Status != "ok" || fresh.Response.Value != 1 || !fresh.Response.Phase.HandshakeConfirmed || fresh.Response.Phase.Used0RTT || out.FinalValue != 1 {
			t.Fatalf("fresh 1-RTT write failed: %+v", out)
		}
	}
	select {
	case err := <-serverErrors:
		t.Fatal(err)
	default:
	}
	return out
}

func TestLiveQUICReplayAndPolicy(t *testing.T) {
	evidence := liveEvidence{Schema: 1, UpstreamCommit: "431fe2e3946b8d75c6db436a6866a83a91a24a7d"}
	t.Run("weak_test_only", func(t *testing.T) { evidence.Weak = scenario(t, true) })
	t.Run("guarded", func(t *testing.T) { evidence.Guarded = scenario(t, false) })
	if t.Failed() {
		return
	}
	if path := os.Getenv("QEDP_EVIDENCE_PATH"); path != "" {
		b, err := json.MarshalIndent(evidence, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(b, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
}
