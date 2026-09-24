package api

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hamad-tariq/SecretsManager/internal/pki"
)

// clientCert is e.client, also returning the certificate (for its serial).
func (e *env) clientCert(id pki.Identity) (*http.Client, *x509.Certificate) {
	key, _ := pki.NewKey()
	c, err := e.ca.Issue(id, key.Public(), time.Hour)
	if err != nil {
		e.t.Fatal(err)
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: e.roots, Certificates: []tls.Certificate{pki.TLSCertificate(c, key)}}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}, c
}

func TestRevocation(t *testing.T) {
	e := newEnv(t)
	admin := e.ready()
	e.expect(admin, "PUT", "/v1/kv/prod/orders/db", map[string]string{"value": "x"}, 200)
	e.expect(admin, "PUT", "/v1/sys/policies/orders", `{"name":"orders","rules":[{"path":"kv/prod/orders/*","capabilities":["read"]}]}`, 200)
	e.expect(admin, "PUT", "/v1/sys/bindings/svc/orders-api", map[string]any{"policies": []string{"orders"}}, 200)
	svcA, certA := e.clientCert(orders)
	svcB, _ := e.clientCert(orders) // a second pod, its own certificate
	e.expect(svcA, "GET", "/v1/kv/prod/orders/db", nil, 200)

	// Only holders of update on sys/revocations may revoke.
	e.expect(svcA, "POST", "/v1/sys/revocations", map[string]string{"identity": "svc/billing-api"}, 403)
	e.expect(admin, "POST", "/v1/sys/revocations", map[string]string{"serial": "zz"}, 400)
	e.expect(admin, "POST", "/v1/sys/revocations", map[string]string{"serial": "1", "identity": "svc/x"}, 400)
	e.expect(admin, "POST", "/v1/sys/revocations", map[string]string{"identity": "admin/alice"}, 400) // the root admin

	// One certificate: that pod stops; the other keeps working. Colons and
	// upper case are accepted, as tools print serials that way.
	serial := certA.SerialNumber.Text(16)
	colons := strings.ToUpper(serial[:2] + ":" + serial[2:])
	e.expect(admin, "POST", "/v1/sys/revocations", map[string]any{"serial": colons, "reason": "pod compromised", "until": certA.NotAfter}, 200)
	if out := e.expect(svcA, "GET", "/v1/kv/prod/orders/db", nil, 401); out["error"] != "certificate revoked" {
		t.Fatalf("revoked cert: %v", out)
	}
	e.expect(svcB, "GET", "/v1/kv/prod/orders/db", nil, 200)

	// The whole identity: every certificate for it stops, whatever its policy.
	e.expect(admin, "POST", "/v1/sys/revocations", map[string]string{"identity": "spiffe://sm/svc/orders-api"}, 200)
	e.expect(svcB, "GET", "/v1/kv/prod/orders/db", nil, 401)
	list := e.expect(admin, "GET", "/v1/sys/revocations", nil, 200)
	if ids := list["identities"].(map[string]any); ids["spiffe://sm/svc/orders-api"] == nil {
		t.Fatalf("list: %v", list)
	}
	e.expect(admin, "DELETE", "/v1/sys/revocations?identity=svc/orders-api", nil, 200)
	e.expect(svcB, "GET", "/v1/kv/prod/orders/db", nil, 200)
	e.expect(svcA, "GET", "/v1/kv/prod/orders/db", nil, 401) // its serial is still revoked
	e.expect(admin, "DELETE", "/v1/sys/revocations?serial="+serial, nil, 200)
	e.expect(svcA, "GET", "/v1/kv/prod/orders/db", nil, 200)
	e.expect(admin, "DELETE", "/v1/sys/revocations", nil, 400)

	// Even the root admin's certificate can be revoked by serial; a fresh
	// certificate for the same admin still has root.
	rootOld, rootCert := e.clientCert(rootAdmin)
	e.expect(admin, "POST", "/v1/sys/revocations", map[string]string{"serial": rootCert.SerialNumber.Text(16)}, 200)
	e.expect(rootOld, "GET", "/v1/kv/prod/orders/db", nil, 401)
	e.expect(admin, "GET", "/v1/kv/prod/orders/db", nil, 200)

	// A revoked service identity can't get new certificates either.
	e.withIntermediate(admin)
	e.expect(admin, "POST", "/v1/sys/revocations", map[string]string{"identity": "svc/billing-api"}, 200)
	tok := e.expect(admin, "POST", "/v1/sys/enroll-tokens", map[string]string{"service": "billing-api"}, 200)["token"].(string)
	_, s := csr(t)
	e.expect(e.client(pki.Identity{}), "POST", "/v1/auth/enroll", map[string]string{"token": tok, "csr": s}, 403)
}

func TestRootAdminHandover(t *testing.T) {
	e := newEnv(t)
	alice := e.ready()
	bob := e.client(otherAdmin)
	e.expect(alice, "PUT", "/v1/kv/prod/db", map[string]string{"value": "x"}, 200)
	e.expect(bob, "GET", "/v1/kv/prod/db", nil, 403)

	// Shares are the authority, not the caller's certificate.
	one := []string{e.shares[0]}
	e.expect(bob, "POST", "/v1/sys/root-admin", map[string]any{"identity": "admin/bob", "shares": one}, 403)
	bad := []string{e.shares[0], strings.Repeat("A", len(e.shares[1]))}
	e.expect(bob, "POST", "/v1/sys/root-admin", map[string]any{"identity": "admin/bob", "shares": bad}, 403)
	e.expect(bob, "POST", "/v1/sys/root-admin", map[string]any{"identity": "svc/orders-api", "shares": e.shares[:2]}, 400)
	e.expect(e.client(orders), "POST", "/v1/sys/root-admin", map[string]any{"identity": "admin/bob", "shares": e.shares[:2]}, 403)

	e.expect(bob, "POST", "/v1/sys/root-admin", map[string]any{"identity": "admin/bob", "shares": e.shares[1:]}, 200)
	if out := e.expect(bob, "GET", "/v1/sys/root-admin", nil, 200); out["root_admin"] != "spiffe://sm/admin/bob" {
		t.Fatalf("root admin: %v", out)
	}
	e.expect(bob, "GET", "/v1/kv/prod/db", nil, 200)
	e.expect(alice, "GET", "/v1/kv/prod/db", nil, 403) // an ordinary admin now, without policies
	// The old root can now be revoked; the new one can't.
	e.expect(bob, "POST", "/v1/sys/revocations", map[string]string{"identity": "admin/alice"}, 200)
	e.expect(alice, "GET", "/v1/sys/root-admin", nil, 401)
	e.expect(bob, "POST", "/v1/sys/revocations", map[string]string{"identity": "admin/bob"}, 400)
	// And a revoked admin can't be made root.
	e.expect(bob, "POST", "/v1/sys/root-admin", map[string]any{"identity": "admin/alice", "shares": e.shares[:2]}, 400)
}

func TestRenewalLineageLimit(t *testing.T) {
	e := newEnv(t)
	admin := e.ready()
	inter := e.withIntermediate(admin)
	svcWithLogin := func(login time.Time) *http.Client {
		key, s := csr(t)
		der, _ := base64.StdEncoding.DecodeString(s)
		c, err := inter.IssueFromCSR(der, orders, time.Hour, login)
		if err != nil {
			t.Fatal(err)
		}
		cl, _ := e.certClient(t, string(append(pki.EncodeCert(c), pki.EncodeCert(inter.Cert)...)), key)
		return cl
	}
	login := time.Now().Add(-29 * 24 * time.Hour).UTC().Truncate(time.Second)
	key, s := csr(t)
	out := e.expect(svcWithLogin(login), "POST", "/v1/auth/renew", map[string]string{"csr": s}, 200)
	_, renewed := e.certClient(t, out["certificate"].(string), key)
	if got := pki.LoginTime(renewed); !got.Equal(login) {
		t.Fatalf("renewal must carry the login time forward: got %v, want %v", got, login)
	}
	_, s = csr(t)
	out = e.expect(svcWithLogin(time.Now().Add(-31*24*time.Hour)), "POST", "/v1/auth/renew", map[string]string{"csr": s}, 403)
	if !strings.Contains(out["error"].(string), "log in again") {
		t.Fatalf("refusal: %v", out)
	}
	// A full login (enrollment) starts a new lineage.
	tok := e.expect(admin, "POST", "/v1/sys/enroll-tokens", map[string]string{"service": "orders-api"}, 200)["token"].(string)
	key, s = csr(t)
	out = e.expect(e.client(pki.Identity{}), "POST", "/v1/auth/enroll", map[string]string{"token": tok, "csr": s}, 200)
	if _, fresh := e.certClient(t, out["certificate"].(string), key); time.Since(pki.LoginTime(fresh)) > time.Minute {
		t.Fatalf("enrollment login time %v", pki.LoginTime(fresh))
	}
}

// Revoking a certificate also revokes its renewals, including ones made
// before the revocation (a thief renews first), but not the identity's other
// logins.
func TestRevokeLineage(t *testing.T) {
	e := newEnv(t)
	admin := e.ready()
	inter := e.withIntermediate(admin)
	svcWithLogin := func(login time.Time) (*http.Client, *x509.Certificate) {
		key, s := csr(t)
		der, _ := base64.StdEncoding.DecodeString(s)
		c, err := inter.IssueFromCSR(der, orders, time.Hour, login)
		if err != nil {
			t.Fatal(err)
		}
		return e.certClient(t, string(append(pki.EncodeCert(c), pki.EncodeCert(inter.Cert)...)), key)
	}
	login := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	stolen, cert := svcWithLogin(login)
	key, s := csr(t)
	out := e.expect(stolen, "POST", "/v1/auth/renew", map[string]string{"csr": s}, 200)
	renewed, _ := e.certClient(t, out["certificate"].(string), key)
	other, _ := svcWithLogin(login.Add(time.Minute))

	e.expect(admin, "POST", "/v1/sys/revocations", map[string]any{"serial": cert.SerialNumber.Text(16),
		"identity": "svc/orders-api", "login": pki.LoginTime(cert)}, 200)
	e.expect(stolen, "GET", "/v1/kv/x", nil, 401)
	e.expect(renewed, "GET", "/v1/kv/x", nil, 401)
	e.expect(renewed, "POST", "/v1/auth/renew", map[string]string{"csr": s}, 401)
	e.expect(other, "GET", "/v1/kv/x", nil, 403) // not revoked: just no policy

	lineages := e.expect(admin, "GET", "/v1/sys/revocations", nil, 200)["lineages"].(map[string]any)
	for k := range lineages {
		e.expect(admin, "DELETE", "/v1/sys/revocations?lineage="+url.QueryEscape(k), nil, 200)
	}
	e.expect(renewed, "GET", "/v1/kv/x", nil, 403)
	e.expect(admin, "POST", "/v1/sys/revocations", map[string]any{"login": login}, 400)
}
