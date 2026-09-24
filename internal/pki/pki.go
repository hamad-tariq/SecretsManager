// Package pki is the internal certificate authority and the source of every
// identity in the system. An identity is the single URI SAN of a certificate:
//
//	spiffe://sm/svc/<name>    a service (API) reading secrets
//	spiffe://sm/admin/<name>  a human operator
//	spiffe://sm/node/<name>   a secrets-cluster node
//
// Hierarchy: offline root CA → intermediate CA (held by the cluster) → leaves.
// All keys are ECDSA P-256 (supported by every TLS stack we need, incl. Python).
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"
	"time"
)

const (
	TrustDomain = "sm"
	// DefaultLeafTTL is used when the caller asks for none.
	DefaultLeafTTL = 24 * time.Hour
	// clockSkew backdates NotBefore so slightly-behind clocks accept new certs.
	clockSkew = time.Minute
)

type Kind string

const (
	Service Kind = "svc"
	Admin   Kind = "admin"
	Node    Kind = "node"
)

// MaxTTL bounds how long a stolen certificate works, per kind. Services renew
// automatically (the agent, iteration 8), so theirs are short; admins and
// nodes are issued by hand, so theirs are longer.
var MaxTTL = map[Kind]time.Duration{
	Service: 72 * time.Hour,
	Admin:   30 * 24 * time.Hour,
	Node:    365 * 24 * time.Hour,
}

// Identity is who a certificate belongs to.
type Identity struct {
	Kind Kind
	Name string
}

func (id Identity) URI() *url.URL {
	return &url.URL{Scheme: "spiffe", Host: TrustDomain, Path: "/" + string(id.Kind) + "/" + id.Name}
}

func (id Identity) String() string { return id.URI().String() }

// Validate checks the kind and that the name is 1-63 chars of [a-z0-9-].
func (id Identity) Validate() error {
	switch id.Kind {
	case Service, Admin, Node:
	default:
		return fmt.Errorf("pki: unknown identity kind %q", id.Kind)
	}
	if len(id.Name) == 0 || len(id.Name) > 63 {
		return fmt.Errorf("pki: identity name must be 1-63 characters")
	}
	for _, c := range id.Name {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return fmt.Errorf("pki: invalid character %q in identity name", c)
		}
	}
	return nil
}

var ErrNoIdentity = errors.New("pki: certificate has no valid identity")

// IdentityFromCert extracts the identity from an already-verified certificate.
// It requires exactly one URI SAN in our trust domain.
func IdentityFromCert(c *x509.Certificate) (Identity, error) {
	if len(c.URIs) != 1 {
		return Identity{}, ErrNoIdentity
	}
	u := c.URIs[0]
	if u.Scheme != "spiffe" || u.Host != TrustDomain || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return Identity{}, ErrNoIdentity
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(parts) != 2 {
		return Identity{}, ErrNoIdentity
	}
	id := Identity{Kind: Kind(parts[0]), Name: parts[1]}
	if id.Validate() != nil {
		return Identity{}, ErrNoIdentity
	}
	return id, nil
}

// CA signs certificates.
type CA struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

// NewKey returns a fresh P-256 private key.
func NewKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128)) // only fails if crypto/rand fails
	return n
}

// NewRoot creates a self-signed root CA. Run it offline; the root key must
// never be stored on the cluster.
func NewRoot(name string, ttl time.Duration) (*CA, error) {
	key, err := NewKey()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	return selfSign(tmpl, key)
}

func selfSign(tmpl *x509.Certificate, key *ecdsa.PrivateKey) (*CA, error) {
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key}, nil
}

// NewIntermediate creates an intermediate CA signed by ca. It can sign leaves
// but not further CAs.
func (ca *CA) NewIntermediate(name string, ttl time.Duration) (*CA, error) {
	key, err := NewKey()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		Subject:               pkix.Name{CommonName: name},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := ca.sign(tmpl, key.Public(), ttl)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key}, nil
}

// sign fills validity and serial, capping NotAfter at the CA's own expiry.
func (ca *CA) sign(tmpl *x509.Certificate, pub crypto.PublicKey, ttl time.Duration) ([]byte, error) {
	now := time.Now()
	tmpl.SerialNumber = serial()
	tmpl.NotBefore = now.Add(-clockSkew)
	tmpl.NotAfter = now.Add(ttl)
	if tmpl.NotAfter.After(ca.Cert.NotAfter) {
		tmpl.NotAfter = ca.Cert.NotAfter
	}
	return x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, pub, ca.Key)
}

// Issue signs a leaf certificate for id. ttl 0 means DefaultLeafTTL; ttl is
// capped at MaxTTL for the identity's kind. Every certificate works as a TLS
// client and server (as SPIFFE X.509-SVIDs do); only node certificates carry
// host names (DNS names or IP addresses), so only nodes pass the hostname
// checks that clients of the API and cluster make. Peers of a service (e.g.
// the rotation hook) match its SPIFFE identity instead.
func (ca *CA) Issue(id Identity, pub crypto.PublicKey, ttl time.Duration, hosts ...string) (*x509.Certificate, error) {
	return ca.issue(id, pub, ttl, time.Time{}, hosts...)
}

func (ca *CA) issue(id Identity, pub crypto.PublicKey, ttl time.Duration, login time.Time, hosts ...string) (*x509.Certificate, error) {
	if err := id.Validate(); err != nil {
		return nil, err
	}
	if _, ok := pub.(*ecdsa.PublicKey); !ok {
		return nil, errors.New("pki: only ECDSA public keys are accepted")
	}
	if ttl <= 0 {
		ttl = DefaultLeafTTL
	}
	ttl = min(ttl, MaxTTL[id.Kind])

	tmpl := &x509.Certificate{
		Subject:     pkix.Name{CommonName: id.String()},
		URIs:        []*url.URL{id.URI()},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	if !login.IsZero() {
		v, err := asn1.Marshal(login.UTC().Truncate(time.Second))
		if err != nil {
			return nil, err
		}
		tmpl.ExtraExtensions = []pkix.Extension{{Id: oidLogin, Value: v}}
	}
	if id.Kind == Node {
		for _, h := range hosts {
			if ip := net.ParseIP(h); ip != nil {
				tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			} else {
				tmpl.DNSNames = append(tmpl.DNSNames, h)
			}
		}
	} else if len(hosts) > 0 {
		return nil, errors.New("pki: only node certificates may carry host names")
	}
	der, err := ca.sign(tmpl, pub, ttl)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// oidLogin is a private extension recording when the identity behind a
// certificate last proved itself with a full login (enrollment token or
// Kubernetes). Renewals copy it forward, so a renewal chain has a known age.
// The arc (2.25, "UUID-derived") needs no registration; only this CA writes
// and reads it.
var oidLogin = asn1.ObjectIdentifier{2, 25, 203141}

// LoginTime returns when c's identity last logged in fully: the extension if
// present, else the certificate's NotBefore.
func LoginTime(c *x509.Certificate) time.Time {
	for _, e := range c.Extensions {
		if e.Id.Equal(oidLogin) {
			var t time.Time
			if rest, err := asn1.Unmarshal(e.Value, &t); err == nil && len(rest) == 0 {
				return t
			}
		}
	}
	return c.NotBefore
}

// IssueFromCSR verifies a CSR's signature (proof the caller holds the key)
// and issues a certificate for id, recording login as its login time.
// Everything the CSR asks for other than its public key is ignored: the
// server alone decides the identity.
func (ca *CA) IssueFromCSR(csrDER []byte, id Identity, ttl time.Duration, login time.Time) (*x509.Certificate, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("pki: bad CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("pki: CSR signature invalid: %w", err)
	}
	return ca.issue(id, csr.PublicKey, ttl, login)
}

// NewCSR creates a certificate request for key (client side).
func NewCSR(key crypto.Signer) ([]byte, error) {
	return x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
}

// ServerTLS returns a TLS 1.3 server config that requires a client
// certificate chaining to clientCAs.
func ServerTLS(cert tls.Certificate, clientCAs *x509.CertPool) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
	}
}

// ClientTLS returns a TLS 1.3 client config presenting cert and trusting only roots.
func ClientTLS(cert tls.Certificate, roots *x509.CertPool) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		RootCAs:      roots,
	}
}

// TLSCertificate bundles a leaf, its key and the intermediate for a TLS handshake.
func TLSCertificate(leaf *x509.Certificate, key crypto.Signer, chain ...*x509.Certificate) tls.Certificate {
	c := tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key, Leaf: leaf}
	for _, ic := range chain {
		c.Certificate = append(c.Certificate, ic.Raw)
	}
	return c
}

// PeerIdentity returns the identity of the verified client on a TLS connection.
func PeerIdentity(cs *tls.ConnectionState) (Identity, error) {
	if cs == nil || len(cs.VerifiedChains) == 0 {
		return Identity{}, ErrNoIdentity
	}
	return IdentityFromCert(cs.VerifiedChains[0][0])
}

// EncodeCert and EncodeKey produce PEM; ParseCert and ParseKey read it back.
func EncodeCert(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func EncodeKey(k *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func ParseCert(pemBytes []byte) (*x509.Certificate, error) {
	b, _ := pem.Decode(pemBytes)
	if b == nil || b.Type != "CERTIFICATE" {
		return nil, errors.New("pki: no CERTIFICATE PEM block")
	}
	return x509.ParseCertificate(b.Bytes)
}

// ParseCerts reads every CERTIFICATE block (a leaf followed by its chain).
func ParseCerts(pemBytes []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var b *pem.Block
		b, pemBytes = pem.Decode(pemBytes)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("pki: no CERTIFICATE PEM block")
	}
	return out, nil
}

func ParseKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	b, _ := pem.Decode(pemBytes)
	if b == nil || b.Type != "PRIVATE KEY" {
		return nil, errors.New("pki: no PRIVATE KEY PEM block")
	}
	k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		return nil, err
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("pki: key is not ECDSA")
	}
	return ek, nil
}
