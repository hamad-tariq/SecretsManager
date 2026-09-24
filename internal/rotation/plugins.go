package rotation

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/hamad-tariq/SecretsManager/internal/pki"
)

// Plugin knows how to make and apply new values for one kind of target.
// Set and Test must be safe to repeat with the same value.
type Plugin interface {
	Validate(params map[string]string) error
	Create(ctx context.Context, t Target) ([]byte, error)
	Set(ctx context.Context, t Target, pending []byte) error
	Test(ctx context.Context, t Target, pending []byte) error
}

// Target is what a plugin gets to work with.
type Target struct {
	Path    string
	Params  map[string]string
	Current []byte                                // nil if the secret has no current value yet
	Lookup  func(path string) ([]byte, error)     // current value of another secret (e.g. admin credentials)
	TLS     *tls.Config                           // node certificate + root CA
	Revoked func(*x509.Certificate) (bool, error) // the revocation list; nil: none
}

var plugins = map[string]Plugin{
	"random":   random{},
	"http":     hook{},
	"postgres": sqlPlugin{dialect: postgresDialect{}},
	"mysql":    sqlPlugin{dialect: mysqlDialect{}},
}

// ---- random: a value nothing else needs to know about (API keys, HMAC keys) ----

type random struct{}

// length reads params["length"] (default 32, 16..1024).
func length(p map[string]string) (int, error) {
	v, ok := p["length"]
	if !ok {
		return 32, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 16 || n > 1024 {
		return 0, errors.New("rotation: length must be 16..1024")
	}
	return n, nil
}

func (random) Validate(p map[string]string) error {
	if _, err := length(p); err != nil {
		return err
	}
	switch p["format"] {
	case "", "alnum", "hex", "base64":
	default:
		return errors.New("rotation: format must be alnum, hex or base64")
	}
	return onlyParams(p, "length", "format")
}

func (random) Create(_ context.Context, t Target) ([]byte, error) {
	n, _ := length(t.Params)
	switch t.Params["format"] {
	case "hex":
		return []byte(hex.EncodeToString(randomBytes(n))), nil
	case "base64":
		return []byte(base64.StdEncoding.EncodeToString(randomBytes(n))), nil
	}
	return Alnum(n), nil
}

func (random) Set(context.Context, Target, []byte) error  { return nil }
func (random) Test(context.Context, Target, []byte) error { return nil }

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// Alnum returns n uniformly random letters and digits. Being plain
// alphanumeric, it's safe to embed in SQL and URLs without escaping.
func Alnum(n int) []byte {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	out := make([]byte, 0, n)
	for len(out) < n {
		for _, b := range randomBytes(n) {
			if int(b) < 256/len(chars)*len(chars) && len(out) < n { // reject to stay uniform
				out = append(out, chars[int(b)%len(chars)])
			}
		}
	}
	return out
}

func onlyParams(p map[string]string, allowed ...string) error {
	for k := range p {
		if !slices.Contains(allowed, k) {
			return fmt.Errorf("rotation: unknown parameter %q", k)
		}
	}
	return nil
}

// ---- http: your own service applies the value ----
//
// The leader POSTs {"step": "set"|"test", "path": ..., "value": ...} over
// mTLS (it presents its node certificate) to params["url"]. The service must
// present a certificate from this cluster's CA for exactly params["identity"]
// (e.g. svc/billing); host names aren't checked. Any 2xx is success.

type hook struct{}

func (hook) Validate(p map[string]string) error {
	u, err := url.Parse(p["url"])
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("rotation: url must be https://host[:port]/path")
	}
	if _, err := hookIdentity(p); err != nil {
		return err
	}
	if _, err := length(p); err != nil {
		return err
	}
	return onlyParams(p, "url", "identity", "length")
}

func hookIdentity(p map[string]string) (pki.Identity, error) {
	kind, name, _ := strings.Cut(p["identity"], "/")
	id := pki.Identity{Kind: pki.Kind(kind), Name: name}
	if err := id.Validate(); err != nil {
		return id, errors.New("rotation: identity must be kind/name, e.g. svc/billing")
	}
	return id, nil
}

func (hook) Create(_ context.Context, t Target) ([]byte, error) {
	n, _ := length(t.Params)
	return Alnum(n), nil
}

func (hook) Set(ctx context.Context, t Target, v []byte) error  { return callHook(ctx, t, StepSet, v) }
func (hook) Test(ctx context.Context, t Target, v []byte) error { return callHook(ctx, t, StepTest, v) }

func callHook(ctx context.Context, t Target, step string, value []byte) error {
	if t.TLS == nil {
		return errors.New("no TLS configuration for hooks")
	}
	want, err := hookIdentity(t.Params)
	if err != nil {
		return err
	}
	cfg := t.TLS.Clone()
	// Replaced by VerifyConnection below: chain to our root CA + exact SPIFFE
	// identity (service certificates carry no host names).
	cfg.InsecureSkipVerify = true // #nosec G402 -- verified in VerifyConnection
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("hook presented no certificate")
		}
		inter := x509.NewCertPool()
		for _, c := range cs.PeerCertificates[1:] {
			inter.AddCert(c)
		}
		if _, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: t.TLS.RootCAs, Intermediates: inter,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			return err
		}
		got, err := pki.IdentityFromCert(cs.PeerCertificates[0])
		if err != nil || got != want {
			return fmt.Errorf("hook identity is %v, want %v", got, want)
		}
		if t.Revoked != nil {
			revoked, err := t.Revoked(cs.PeerCertificates[0])
			if err != nil {
				return fmt.Errorf("checking revocation: %w", err)
			}
			if revoked {
				return fmt.Errorf("hook certificate for %v is revoked", got)
			}
		}
		return nil
	}
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg},
		// Never follow: a redirect to http:// would resend the value in clear.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()

	body, _ := json.Marshal(map[string]string{"step": step, "path": t.Path, "value": string(value)})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.Params["url"], bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("hook returned %s: %s", resp.Status, bytes.TrimSpace(msg))
	}
	return nil
}
