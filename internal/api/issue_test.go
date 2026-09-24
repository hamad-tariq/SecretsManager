package api

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hamad-tariq/SecretsManager/internal/pki"
)

type ecdsaKey = ecdsa.PrivateKey

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// withIntermediate uploads an intermediate CA signed by the test root.
func (e *env) withIntermediate(admin *http.Client) *pki.CA {
	inter, _ := e.ca.NewIntermediate("test intermediate", time.Hour)
	keyPEM, _ := pki.EncodeKey(inter.Key.(*ecdsaKey))
	e.expect(admin, "PUT", "/v1/sys/pki/intermediate", map[string]string{
		"cert_pem": string(pki.EncodeCert(inter.Cert)), "key_pem": string(keyPEM)}, 200)
	return inter
}

// csr returns a fresh key and its base64 CSR.
func csr(t *testing.T) (*ecdsaKey, string) {
	key, _ := pki.NewKey()
	der, err := pki.NewCSR(key)
	if err != nil {
		t.Fatal(err)
	}
	return key, b64(der)
}

// certClient builds a client from an issued chain.
func (e *env) certClient(t *testing.T, chainPEM string, key *ecdsaKey) (*http.Client, *x509.Certificate) {
	certs, err := pki.ParseCerts([]byte(chainPEM))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: e.roots,
		Certificates: []tls.Certificate{pki.TLSCertificate(certs[0], key, certs[1:]...)}}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}, certs[0]
}

func TestIntermediateUpload(t *testing.T) {
	e := newEnv(t)
	admin := e.ready()
	anon := e.client(pki.Identity{})
	_, s := csr(t)
	e.expect(anon, "POST", "/v1/auth/enroll", map[string]string{"token": "smt_x", "csr": s}, 401)

	// A leaf is not a CA; key must match; must chain to our root.
	leafKey, _ := pki.NewKey()
	leaf, _ := e.ca.Issue(pki.Identity{Kind: pki.Admin, Name: "x"}, leafKey.Public(), time.Hour)
	leafKeyPEM, _ := pki.EncodeKey(leafKey)
	e.expect(admin, "PUT", "/v1/sys/pki/intermediate", map[string]string{"cert_pem": string(pki.EncodeCert(leaf)), "key_pem": string(leafKeyPEM)}, 400)
	inter, _ := e.ca.NewIntermediate("i", time.Hour)
	e.expect(admin, "PUT", "/v1/sys/pki/intermediate", map[string]string{"cert_pem": string(pki.EncodeCert(inter.Cert)), "key_pem": string(leafKeyPEM)}, 400)
	foreign, _ := pki.NewRoot("foreign", time.Hour)
	fk, _ := pki.EncodeKey(foreign.Key.(*ecdsaKey))
	e.expect(admin, "PUT", "/v1/sys/pki/intermediate", map[string]string{"cert_pem": string(pki.EncodeCert(foreign.Cert)), "key_pem": string(fk)}, 400)
	e.expect(admin, "PUT", "/v1/sys/pki/intermediate", map[string]string{"cert_pem": "x", "key_pem": "y"}, 400)
	e.expect(e.client(orders), "PUT", "/v1/sys/pki/intermediate", map[string]string{}, 403)

	e.withIntermediate(admin)
}

func TestEnrollmentTokens(t *testing.T) {
	e := newEnv(t)
	admin := e.ready()
	e.withIntermediate(admin)
	anon := e.client(pki.Identity{})

	e.expect(e.client(orders), "POST", "/v1/sys/enroll-tokens", map[string]string{"service": "orders-api"}, 403)
	// Scoped per service: a team may enroll its own services, not others'.
	e.expect(admin, "PUT", "/v1/sys/policies/enroller", `{"name":"enroller","rules":[{"path":"sys/enroll-tokens/orders-worker","capabilities":["create"]}]}`, 200)
	e.expect(admin, "PUT", "/v1/sys/bindings/admin/bob", map[string]any{"policies": []string{"enroller"}}, 200)
	e.expect(e.client(otherAdmin), "POST", "/v1/sys/enroll-tokens", map[string]string{"service": "orders-worker"}, 200)
	e.expect(e.client(otherAdmin), "POST", "/v1/sys/enroll-tokens", map[string]string{"service": "billing-api"}, 403)
	e.expect(admin, "POST", "/v1/sys/enroll-tokens", map[string]string{"service": "Bad Name"}, 400)
	e.expect(admin, "POST", "/v1/sys/enroll-tokens", map[string]string{"service": "a", "ttl": "2h"}, 400)
	tok := e.expect(admin, "POST", "/v1/sys/enroll-tokens", map[string]string{"service": "orders-api"}, 200)["token"].(string)

	// A malformed CSR is rejected without burning the token.
	e.expect(anon, "POST", "/v1/auth/enroll", map[string]string{"token": tok, "csr": "!!"}, 400)
	e.expect(anon, "POST", "/v1/auth/enroll", map[string]string{"token": tok, "csr": b64([]byte("junk"))}, 400)

	key, s := csr(t)
	out := e.expect(anon, "POST", "/v1/auth/enroll", map[string]string{"token": tok, "csr": s}, 200)
	if out["identity"] != "spiffe://sm/svc/orders-api" {
		t.Fatalf("identity %v", out["identity"])
	}
	e.expect(anon, "POST", "/v1/auth/enroll", map[string]string{"token": tok, "csr": s}, 401) // single use

	// The issued certificate works against the API and has a service lifetime.
	svc, cert := e.certClient(t, out["certificate"].(string), key)
	if d := cert.NotAfter.Sub(cert.NotBefore); d > DefaultServiceTTL+2*time.Minute {
		t.Fatalf("lifetime %v", d)
	}
	e.expect(svc, "GET", "/v1/kv/anything", nil, 403) // authenticated, no policy yet

	// Expired token.
	short := e.expect(admin, "POST", "/v1/sys/enroll-tokens", map[string]string{"service": "a", "ttl": "1ms"}, 200)["token"].(string)
	time.Sleep(5 * time.Millisecond)
	e.expect(anon, "POST", "/v1/auth/enroll", map[string]string{"token": short, "csr": s}, 401)

	// Concurrent use of one token: exactly one wins.
	race := e.expect(admin, "POST", "/v1/sys/enroll-tokens", map[string]string{"service": "orders-api"}, 200)["token"].(string)
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for range 5 {
		wg.Go(func() {
			code, _ := e.do(anon, "POST", "/v1/auth/enroll", map[string]string{"token": race, "csr": s})
			mu.Lock()
			if code == 200 {
				wins++
			}
			mu.Unlock()
		})
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("token used %d times", wins)
	}
}

func TestRenew(t *testing.T) {
	e := newEnv(t)
	admin := e.ready()
	e.withIntermediate(admin)
	tok := e.expect(admin, "POST", "/v1/sys/enroll-tokens", map[string]string{"service": "orders-api"}, 200)["token"].(string)
	key, s := csr(t)
	out := e.expect(e.client(pki.Identity{}), "POST", "/v1/auth/enroll", map[string]string{"token": tok, "csr": s}, 200)
	svc, first := e.certClient(t, out["certificate"].(string), key)

	newKey, s2 := csr(t)
	renewed := e.expect(svc, "POST", "/v1/auth/renew", map[string]string{"csr": s2}, 200)
	_, second := e.certClient(t, renewed["certificate"].(string), newKey)
	if id, _ := pki.IdentityFromCert(second); id.String() != "spiffe://sm/svc/orders-api" || second.SerialNumber.Cmp(first.SerialNumber) == 0 {
		t.Fatalf("renewed %v serial %v", id, second.SerialNumber)
	}
	e.expect(admin, "POST", "/v1/auth/renew", map[string]string{"csr": s2}, 403)                    // admins don't renew here
	e.expect(e.client(pki.Identity{}), "POST", "/v1/auth/renew", map[string]string{"csr": s2}, 401) // no certificate
}

// fakeK8s answers TokenReviews: "good-<ns>-<sa>" tokens are valid for audience "sm".
// It also reports how many connections to it are open.
func fakeK8s(t *testing.T) (url, caPEM string, open func() int32) {
	var conns atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/apis/authentication.k8s.io/v1/tokenreviews" || r.Header.Get("Authorization") != "Bearer reviewer" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		var req struct {
			Spec struct {
				Token     string   `json:"token"`
				Audiences []string `json:"audiences"`
			} `json:"spec"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		st := map[string]any{"authenticated": false}
		switch req.Spec.Token {
		case "good-shop-orders":
			st = map[string]any{"authenticated": true, "audiences": []string{"sm"},
				"user": map[string]string{"username": "system:serviceaccount:shop:orders"}}
		case "good-shop-unmapped":
			st = map[string]any{"authenticated": true, "audiences": []string{"sm"},
				"user": map[string]string{"username": "system:serviceaccount:shop:unmapped"}}
		case "wrong-audience":
			st = map[string]any{"authenticated": true, "audiences": []string{"other"},
				"user": map[string]string{"username": "system:serviceaccount:shop:orders"}}
		case "human":
			st = map[string]any{"authenticated": true, "audiences": []string{"sm"},
				"user": map[string]string{"username": "alice@example.com"}}
		}
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": st})
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		switch s {
		case http.StateNew:
			conns.Add(1)
		case http.StateClosed, http.StateHijacked:
			conns.Add(-1)
		}
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.URL, string(pki.EncodeCert(srv.Certificate())), conns.Load
}

func TestKubernetesLogin(t *testing.T) {
	e := newEnv(t)
	admin := e.ready()
	e.withIntermediate(admin)
	anon := e.client(pki.Identity{})
	_, s := csr(t)

	e.expect(anon, "POST", "/v1/auth/kubernetes", map[string]string{"jwt": "good-shop-orders", "csr": s}, 401) // not configured

	url, ca, open := fakeK8s(t)
	cfg := map[string]any{"host": url, "ca_pem": ca, "reviewer_token": "reviewer", "audience": "sm",
		"roles": map[string]string{"shop/orders": "orders-api"}}
	e.expect(e.client(orders), "PUT", "/v1/sys/auth/kubernetes", cfg, 403)
	e.expect(admin, "PUT", "/v1/sys/auth/kubernetes", map[string]any{"host": "http://x", "audience": "sm"}, 400)
	bad := map[string]any{"host": url, "ca_pem": ca, "reviewer_token": "r", "audience": "sm", "roles": map[string]string{"noslash": "orders-api"}}
	e.expect(admin, "PUT", "/v1/sys/auth/kubernetes", bad, 400)
	e.expect(admin, "PUT", "/v1/sys/auth/kubernetes", cfg, 200)

	out := e.expect(anon, "POST", "/v1/auth/kubernetes", map[string]string{"jwt": "good-shop-orders", "csr": s}, 200)
	if out["identity"] != "spiffe://sm/svc/orders-api" {
		t.Fatalf("identity %v", out["identity"])
	}
	for _, jwt := range []string{"good-shop-unmapped", "wrong-audience", "human", "garbage"} {
		e.expect(anon, "POST", "/v1/auth/kubernetes", map[string]string{"jwt": jwt, "csr": s}, 401)
	}
	e.expect(anon, "POST", "/v1/auth/kubernetes", map[string]string{"csr": s}, 400)

	// Reviewer token rejected by the API server → login fails closed.
	cfg["reviewer_token"] = "wrong"
	e.expect(admin, "PUT", "/v1/sys/auth/kubernetes", cfg, 200)
	e.expect(anon, "POST", "/v1/auth/kubernetes", map[string]string{"jwt": "good-shop-orders", "csr": s}, 401)

	// Logins (anyone can try) must not leave connections to the API server open.
	for i := 0; open() != 0; i++ {
		if i == 100 {
			t.Fatalf("%d connections to the Kubernetes API left open", open())
		}
		time.Sleep(20 * time.Millisecond)
	}
}
