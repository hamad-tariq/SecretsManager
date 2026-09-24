package audit

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hamad-tariq/SecretsManager/internal/pki"
)

// collector is a minimal RFC 5425 syslog-over-TLS receiver.
type collector struct {
	t    *testing.T
	ln   net.Listener
	mu   sync.Mutex
	msgs []string // the audit JSON part of each message
	conn []net.Conn
}

func startCollector(t *testing.T, addr string, cfg *tls.Config) *collector {
	t.Helper()
	var ln net.Listener
	var err error
	for range 50 { // the port may take a moment to free up after a restart
		if ln, err = tls.Listen("tcp", addr, cfg); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	c := &collector{t: t, ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			c.mu.Lock()
			c.conn = append(c.conn, conn)
			c.mu.Unlock()
			go c.read(conn)
		}
	}()
	return c
}

func (c *collector) read(conn net.Conn) {
	r := bufio.NewReader(conn)
	for {
		lenStr, err := r.ReadString(' ')
		if err != nil {
			return
		}
		n, err := strconv.Atoi(strings.TrimSpace(lenStr))
		if err != nil {
			c.t.Errorf("bad frame length %q", lenStr)
			return
		}
		msg := make([]byte, n)
		if _, err := io.ReadFull(r, msg); err != nil {
			return
		}
		m := string(msg)
		if !strings.HasPrefix(m, "<110>1 ") || !strings.Contains(m, " node-1 smd - - - {") {
			c.t.Errorf("not an RFC 5424 audit message: %q", m)
		}
		_, body, _ := strings.Cut(m, " - - - ")
		c.mu.Lock()
		c.msgs = append(c.msgs, body)
		c.mu.Unlock()
	}
}

func (c *collector) stop() {
	_ = c.ln.Close()
	c.mu.Lock()
	for _, conn := range c.conn {
		_ = conn.Close()
	}
	c.mu.Unlock()
}

func (c *collector) received() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.msgs)
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(15 * time.Second); !cond(); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

func TestForwarding(t *testing.T) {
	root, _ := pki.NewRoot("root", time.Hour)
	roots := x509.NewCertPool()
	roots.AddCert(root.Cert)
	issue := func(id pki.Identity, hosts ...string) tls.Certificate {
		k, _ := pki.NewKey()
		c, _ := root.Issue(id, k.Public(), time.Hour, hosts...)
		return pki.TLSCertificate(c, k)
	}
	collectorTLS := pki.ServerTLS(issue(pki.Identity{Kind: pki.Node, Name: "collector"}, "127.0.0.1"), roots)
	addr := func() string { l, _ := net.Listen("tcp", "127.0.0.1:0"); defer l.Close(); return l.Addr().String() }()

	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := OpenFile(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	logN := func(n int) error {
		for i := range n {
			if err := l.Log(Entry{Operation: "kv.read", Path: fmt.Sprintf("kv/x/%d", i), Result: "ok"}); err != nil {
				return err
			}
		}
		return nil
	}
	if err := logN(20); err != nil { // written before forwarding starts: sent from the file
		t.Fatal(err)
	}

	col := startCollector(t, addr, collectorTLS)
	f := &Forwarder{Path: path, Addr: addr, TLS: pki.ClientTLS(issue(pki.Identity{Kind: pki.Node, Name: "node-1"}), roots),
		Hostname: "node-1", MaxLag: 3000, Log: slog.New(slog.DiscardHandler), maxBackoff: 200 * time.Millisecond}
	if err := f.Start(); err != nil {
		t.Fatal(err)
	}
	l.SetGate(f.Check)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done }) // before TempDir cleanup: Windows can't delete open files

	waitUntil(t, "20 forwarded", func() bool { return len(col.received()) == 20 && f.Lag() == 0 })

	// Collector down: entries pile up locally until the limit, then Log
	// refuses (the API turns that into a failed request).
	col.stop()
	var refused error
	for i := 0; i < 1000 && refused == nil; i++ {
		refused = logN(1)
		time.Sleep(time.Millisecond)
	}
	if refused == nil || !strings.Contains(refused.Error(), "not yet forwarded") {
		t.Fatalf("expected refusal once the backlog passed the limit, got %v (lag %d)", refused, f.Lag())
	}

	// Collector back: the backlog drains and logging works again.
	col2 := startCollector(t, addr, collectorTLS)
	defer col2.stop()
	waitUntil(t, "backlog drained", func() bool { return f.Lag() == 0 })
	if err := logN(5); err != nil {
		t.Fatalf("logging after recovery: %v", err)
	}
	waitUntil(t, "new entries forwarded", func() bool { return f.Lag() == 0 })

	// Everything the two collectors got, deduplicated by sequence number
	// (lines in flight when the first one died may be re-sent), forms the
	// complete, valid chain.
	bySeq := map[string]string{}
	for _, m := range append(col.received(), col2.received()...) {
		seq, _, _ := strings.Cut(strings.TrimPrefix(m, `{"seq":`), ",")
		bySeq[seq] = m
	}
	var lines []string
	for i := 1; i <= len(bySeq); i++ {
		lines = append(lines, bySeq[strconv.Itoa(i)])
	}
	head, err := Verify(strings.NewReader(strings.Join(lines, "\n") + "\n"))
	if err != nil || head != l.Head() {
		t.Fatalf("remote copy: head %+v (local %+v), %v", head, l.Head(), err)
	}

	// A restarted forwarder resumes from the saved offset.
	cancel()
	<-done
	f2 := &Forwarder{Path: path, Addr: addr, TLS: f.TLS, Hostname: "node-1", Log: f.Log}
	if err := f2.Start(); err != nil || f2.Lag() != 0 {
		t.Fatalf("resume: lag %d, %v", f2.Lag(), err)
	}
}

// If the local log is ever shorter than what was forwarded (truncated,
// replaced, restored from an old copy), forwarding from the saved offset
// would silently skip records: fail closed instead.
func TestForwarderRefusesShortenedLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, _ := OpenFile(path, nil)
	for range 3 {
		_ = l.Log(Entry{Operation: "kv.read", Result: "ok"})
	}
	_ = l.Close()
	st, _ := os.Stat(path)
	_ = os.WriteFile(path+".forwarded", []byte(strconv.FormatInt(st.Size(), 10)), 0o600)
	f := &Forwarder{Path: path, Addr: "127.0.0.1:1", Log: slog.New(slog.DiscardHandler)}
	if err := f.Start(); err != nil {
		t.Fatalf("consistent offset: %v", err)
	}

	_ = os.WriteFile(path, nil, 0o600) // the log is replaced by an empty one
	if err := f.Check(); err == nil {
		t.Fatal("Check allowed logging over a truncated log")
	}
	f2 := &Forwarder{Path: path, Addr: "127.0.0.1:1", Log: f.Log}
	if err := f2.Start(); err == nil || !strings.Contains(err.Error(), ".forwarded") {
		t.Fatalf("Start accepted an offset past the end: %v", err)
	}
	// A different, longer log that doesn't end a line at the offset is caught too.
	_ = os.WriteFile(path, []byte(strings.Repeat("x", int(st.Size())+10)), 0o600)
	if err := (&Forwarder{Path: path, Addr: "127.0.0.1:1", Log: f.Log}).Start(); err == nil {
		t.Fatal("replaced log accepted")
	}
}
