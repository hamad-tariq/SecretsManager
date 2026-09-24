package pki

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/url"
	"testing"
	"time"
)

type fixture struct {
	root, inter *CA
	roots       *x509.CertPool
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	root, err := NewRoot("sm root", 10*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	inter, err := root.NewIntermediate("sm intermediate", 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root.Cert)
	return fixture{root, inter, roots}
}

func (f fixture) leaf(t *testing.T, id Identity, dns ...string) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, _ := NewKey()
	cert, err := f.inter.Issue(id, key.Public(), 0, dns...)
	if err != nil {
		t.Fatal(err)
	}
	return TLSCertificate(cert, key, f.inter.Cert), cert
}

func (f fixture) verify(c *x509.Certificate, usage x509.ExtKeyUsage) error {
	inters := x509.NewCertPool()
	inters.AddCert(f.inter.Cert)
	_, err := c.Verify(x509.VerifyOptions{Roots: f.roots, Intermediates: inters, KeyUsages: []x509.ExtKeyUsage{usage}})
	return err
}

var orders = Identity{Service, "orders-api"}

func TestChainAndUsage(t *testing.T) {
	f := newFixture(t)
	_, svc := f.leaf(t, orders)
	_, node := f.leaf(t, Identity{Node, "node-1"}, "node-1.sm.internal", "127.0.0.1")
	if len(node.DNSNames) != 1 || len(node.IPAddresses) != 1 || node.VerifyHostname("127.0.0.1") != nil || node.VerifyHostname("node-1.sm.internal") != nil {
		t.Fatalf("node hosts: dns %v ip %v", node.DNSNames, node.IPAddresses)
	}

	if err := f.verify(svc, x509.ExtKeyUsageClientAuth); err != nil {
		t.Fatalf("service cert as client: %v", err)
	}
	// A service can serve TLS (e.g. a rotation hook) but can never pass a
	// hostname check, so it can't pose as a node.
	if err := f.verify(svc, x509.ExtKeyUsageServerAuth); err != nil {
		t.Fatalf("service cert as server: %v", err)
	}
	if len(svc.DNSNames)+len(svc.IPAddresses) != 0 || svc.VerifyHostname("127.0.0.1") == nil {
		t.Fatal("service certs must carry no host names")
	}
	if err := f.verify(node, x509.ExtKeyUsageServerAuth); err != nil {
		t.Fatalf("node cert as server: %v", err)
	}
	if err := f.verify(node, x509.ExtKeyUsageClientAuth); err != nil {
		t.Fatalf("node cert as client: %v", err)
	}

	// The intermediate may not create further CAs.
	sub, err := f.inter.NewIntermediate("rogue", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := NewKey()
	rogue, _ := sub.Issue(orders, key.Public(), 0)
	inters := x509.NewCertPool()
	inters.AddCert(f.inter.Cert)
	inters.AddCert(sub.Cert)
	if _, err := rogue.Verify(x509.VerifyOptions{Roots: f.roots, Intermediates: inters, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
		t.Fatal("leaf under a sub-intermediate verified")
	}
}

func TestTTL(t *testing.T) {
	f := newFixture(t)
	key, _ := NewKey()
	check := func(ttl, want time.Duration) {
		c, err := f.inter.Issue(orders, key.Public(), ttl)
		if err != nil {
			t.Fatal(err)
		}
		if got := c.NotAfter.Sub(c.NotBefore) - clockSkew; got < want-time.Minute || got > want+time.Minute {
			t.Errorf("ttl %v: lifetime %v, want %v", ttl, got, want)
		}
	}
	check(0, DefaultLeafTTL)
	check(time.Hour, time.Hour)
	check(30*24*time.Hour, MaxTTL[Service])
	adminKey, _ := NewKey()
	a, _ := f.inter.Issue(Identity{Admin, "bob"}, adminKey.Public(), 90*24*time.Hour)
	if got := a.NotAfter.Sub(a.NotBefore) - clockSkew; got > MaxTTL[Admin]+time.Minute {
		t.Errorf("admin lifetime %v exceeds %v", got, MaxTTL[Admin])
	}

	shortCA, _ := f.root.NewIntermediate("short", time.Hour)
	c, _ := shortCA.Issue(orders, key.Public(), 0)
	if c.NotAfter.After(shortCA.Cert.NotAfter) {
		t.Fatal("leaf outlives its CA")
	}
}

func TestIssueRejects(t *testing.T) {
	f := newFixture(t)
	key, _ := NewKey()
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)

	if _, err := f.inter.Issue(orders, key.Public(), 0, "evil.example"); err == nil {
		t.Error("service cert with DNS names accepted")
	}
	if _, err := f.inter.Issue(orders, edPub, 0); err == nil {
		t.Error("non-ECDSA key accepted")
	}
	for _, id := range []Identity{{"root", "x"}, {Service, ""}, {Service, "UPPER"}, {Service, "a/b"}, {Service, string(make([]byte, 64))}} {
		if _, err := f.inter.Issue(id, key.Public(), 0); err == nil {
			t.Errorf("invalid identity %+v accepted", id)
		}
	}
}

func TestIdentityFromCert(t *testing.T) {
	uri := func(s string) *url.URL { u, _ := url.Parse(s); return u }
	cases := map[string][]*url.URL{
		"no URI":        nil,
		"two URIs":      {orders.URI(), Identity{Admin, "bob"}.URI()},
		"wrong scheme":  {uri("https://sm/svc/orders-api")},
		"wrong domain":  {uri("spiffe://other/svc/orders-api")},
		"unknown kind":  {uri("spiffe://sm/root/x")},
		"extra segment": {uri("spiffe://sm/svc/orders-api/x")},
		"query":         {uri("spiffe://sm/svc/orders-api?x=1")},
		"userinfo":      {uri("spiffe://u@sm/svc/orders-api")},
	}
	for name, uris := range cases {
		if _, err := IdentityFromCert(&x509.Certificate{URIs: uris}); err != ErrNoIdentity {
			t.Errorf("%s: got %v", name, err)
		}
	}
	id, err := IdentityFromCert(&x509.Certificate{URIs: []*url.URL{orders.URI()}})
	if err != nil || id != orders {
		t.Fatalf("valid identity: %v %+v", err, id)
	}
	if orders.String() != "spiffe://sm/svc/orders-api" {
		t.Fatalf("String() = %s", orders)
	}
}

func TestIssueFromCSR(t *testing.T) {
	f := newFixture(t)
	key, _ := NewKey()

	// The CSR asks to be an admin; the server decides it is orders-api.
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{URIs: []*url.URL{Identity{Admin, "root"}.URI()}}, key)
	if err != nil {
		t.Fatal(err)
	}
	login := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	c, err := f.inter.IssueFromCSR(csr, orders, 0, login)
	if err != nil {
		t.Fatal(err)
	}
	if id, _ := IdentityFromCert(c); id != orders {
		t.Fatalf("issued identity %v", id)
	}
	if got := LoginTime(c); !got.Equal(login) {
		t.Fatalf("login time %v, want %v", got, login)
	}
	// Certificates without the extension (issued offline) report NotBefore.
	_, plainLeaf := f.leaf(t, orders)
	if !LoginTime(plainLeaf).Equal(plainLeaf.NotBefore) {
		t.Fatal("login time of a certificate without the extension")
	}

	plain, _ := NewCSR(key)
	if _, err := f.inter.IssueFromCSR(plain, orders, 0, login); err != nil {
		t.Fatal(err)
	}
	bad := append([]byte(nil), plain...)
	bad[len(bad)-1] ^= 0xFF // corrupt the signature
	if _, err := f.inter.IssueFromCSR(bad, orders, 0, login); err == nil {
		t.Error("CSR with bad signature accepted")
	}
	if _, err := f.inter.IssueFromCSR([]byte("junk"), orders, 0, login); err == nil {
		t.Error("garbage CSR accepted")
	}
}

// handshake runs an mTLS handshake over loopback TCP and returns the identity
// the server saw, or the first error. (Not net.Pipe: it is unbuffered, and a
// TLS 1.3 server's rejection alert would block forever.)
func handshake(server, client *tls.Config) (Identity, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return Identity{}, err
	}
	defer ln.Close()

	errc := make(chan error, 1)
	go func() {
		c, err := tls.Dial("tcp", ln.Addr().String(), client)
		if err == nil {
			c.Close()
		}
		errc <- err
	}()
	conn, err := ln.Accept()
	if err != nil {
		return Identity{}, err
	}
	defer conn.Close()
	s := tls.Server(conn, server)
	_ = s.SetDeadline(time.Now().Add(10 * time.Second))
	serr := s.Handshake()
	cerr := <-errc
	if serr != nil {
		return Identity{}, serr
	}
	if cerr != nil {
		return Identity{}, cerr
	}
	cs := s.ConnectionState()
	return PeerIdentity(&cs)
}

func TestMutualTLS(t *testing.T) {
	f := newFixture(t)
	nodeCert, _ := f.leaf(t, Identity{Node, "node-1"}, "node-1.sm.internal")
	svcCert, _ := f.leaf(t, orders)
	server := ServerTLS(nodeCert, f.roots)
	client := ClientTLS(svcCert, f.roots)
	client.ServerName = "node-1.sm.internal"

	id, err := handshake(server, client)
	if err != nil || id != orders {
		t.Fatalf("mTLS: %v, identity %v", err, id)
	}

	// Client certificate from a different CA.
	other := newFixture(t)
	foreign, _ := other.leaf(t, orders)
	c2 := ClientTLS(foreign, f.roots)
	c2.ServerName = "node-1.sm.internal"
	if _, err := handshake(server, c2); err == nil {
		t.Fatal("foreign client certificate accepted")
	}

	// No client certificate at all.
	c3 := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: f.roots, ServerName: "node-1.sm.internal"}
	if _, err := handshake(server, c3); err == nil {
		t.Fatal("handshake without client certificate accepted")
	}

	// Expired client certificate.
	key, _ := NewKey()
	tmpl := &x509.Certificate{SerialNumber: serial(), URIs: []*url.URL{orders.URI()},
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(-time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, f.inter.Cert, key.Public(), f.inter.Key)
	expired, _ := x509.ParseCertificate(der)
	c4 := ClientTLS(TLSCertificate(expired, key, f.inter.Cert), f.roots)
	c4.ServerName = "node-1.sm.internal"
	if _, err := handshake(server, c4); err == nil {
		t.Fatal("expired client certificate accepted")
	}

	// Service cert posing as a server.
	s2 := ServerTLS(svcCert, f.roots)
	if _, err := handshake(s2, ClientTLS(svcCert, f.roots)); err == nil {
		t.Fatal("service certificate accepted as server")
	}

	if _, err := PeerIdentity(nil); err != ErrNoIdentity {
		t.Fatal("nil connection state should have no identity")
	}
}

func TestPEMRoundTrip(t *testing.T) {
	f := newFixture(t)
	key, _ := NewKey()
	kp, err := EncodeKey(key)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := ParseKey(kp)
	if err != nil || !k2.Equal(key) {
		t.Fatalf("key round trip: %v", err)
	}
	c2, err := ParseCert(EncodeCert(f.root.Cert))
	if err != nil || !c2.Equal(f.root.Cert) {
		t.Fatalf("cert round trip: %v", err)
	}

	if _, err := ParseCert(kp); err == nil {
		t.Error("ParseCert accepted a key")
	}
	if _, err := ParseKey(EncodeCert(f.root.Cert)); err == nil {
		t.Error("ParseKey accepted a cert")
	}
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(edPriv)
	if _, err := ParseKey(pemBlock("PRIVATE KEY", der)); err == nil {
		t.Error("ParseKey accepted an Ed25519 key")
	}
	if _, err := ParseKey(pemBlock("PRIVATE KEY", []byte("junk"))); err == nil {
		t.Error("ParseKey accepted junk")
	}
}

func pemBlock(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func TestParseCerts(t *testing.T) {
	f := newFixture(t)
	_, leaf := f.leaf(t, orders)
	key, _ := NewKey()
	keyPEM, _ := EncodeKey(key)
	bundle := append(append(EncodeCert(leaf), keyPEM...), EncodeCert(f.inter.Cert)...)
	certs, err := ParseCerts(bundle) // non-certificate blocks are skipped
	if err != nil || len(certs) != 2 || !certs[0].Equal(leaf) || !certs[1].Equal(f.inter.Cert) {
		t.Fatalf("ParseCerts: %d certs, %v", len(certs), err)
	}
	if _, err := ParseCerts(keyPEM); err == nil {
		t.Error("key-only PEM accepted")
	}
	if _, err := ParseCerts(pemBlock("CERTIFICATE", []byte("junk"))); err == nil {
		t.Error("junk certificate accepted")
	}
}
