package api

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/hamad-tariq/SecretsManager/internal/pki"
	"github.com/hamad-tariq/SecretsManager/internal/policy"
	"github.com/hamad-tariq/SecretsManager/internal/storage"
)

// How services get certificates from the cluster (all return a short-lived
// service certificate for a CSR; the server alone decides the identity):
//
//	POST /v1/auth/enroll      single-use enrollment token (Docker hosts, VMs)
//	POST /v1/auth/kubernetes  projected service-account token, checked with
//	                          the cluster's own TokenReview API
//	POST /v1/auth/renew       current service certificate (mTLS) → fresh one
const (
	intermediatePath = "sys/pki/intermediate"
	enrollPrefix     = "sys/enroll/"
	k8sConfigPath    = "sys/auth/kubernetes"

	DefaultServiceTTL = 24 * time.Hour
	maxEnrollTTL      = time.Hour
)

var errUnauthenticated = errors.New("authentication failed")

// ---- intermediate CA ----

type intermediateRequest struct {
	CertPEM string `json:"cert_pem"` // intermediate certificate
	KeyPEM  string `json:"key_pem"`
}

// putIntermediate stores the issuing CA behind the barrier after checking it
// chains to the root the nodes trust and matches its key.
func (s *Server) putIntermediate(r *http.Request, _ *call) response {
	var req intermediateRequest
	if err := decode(r, &req); err != nil {
		return errResp(http.StatusBadRequest, err.Error())
	}
	cert, err := pki.ParseCert([]byte(req.CertPEM))
	if err != nil {
		return errResp(http.StatusBadRequest, err.Error())
	}
	key, err := pki.ParseKey([]byte(req.KeyPEM))
	if err != nil {
		return errResp(http.StatusBadRequest, err.Error())
	}
	if s.roots == nil { // never fall back to the system trust store
		return errResp(http.StatusInternalServerError, "server has no root CA configured")
	}
	if !cert.IsCA || !key.PublicKey.Equal(cert.PublicKey) {
		return errResp(http.StatusBadRequest, "certificate must be a CA matching the key")
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: s.roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return errResp(http.StatusBadRequest, "intermediate does not chain to the trusted root: "+err.Error())
	}
	v, _ := json.Marshal(req)
	if err := s.seal.Put(intermediatePath, v); err != nil {
		return s.fail(err)
	}
	return ok(map[string]string{"subject": cert.Subject.CommonName, "not_after": cert.NotAfter.Format(time.RFC3339)})
}

func (s *Server) issuer() (*pki.CA, error) {
	v, err := s.seal.Get(intermediatePath)
	if errors.Is(err, storage.ErrNotFound) {
		return nil, errors.New("no intermediate CA uploaded (smctl pki upload)")
	}
	if err != nil {
		return nil, err
	}
	var req intermediateRequest
	if err := json.Unmarshal(v, &req); err != nil {
		return nil, err
	}
	cert, err := pki.ParseCert([]byte(req.CertPEM))
	if err != nil {
		return nil, err
	}
	key, err := pki.ParseKey([]byte(req.KeyPEM))
	if err != nil {
		return nil, err
	}
	return &pki.CA{Cert: cert, Key: key}, nil
}

type certResponse struct {
	Identity    string `json:"identity"`
	Certificate string `json:"certificate"` // leaf then intermediate, PEM
	NotAfter    string `json:"not_after"`
}

// issueService signs a service certificate for a base64 DER CSR.
// issueService signs a certificate for the service; login is when its
// identity last logged in fully (now, for enrollment and Kubernetes; carried
// over from the presented certificate for renewals).
func (s *Server) issueService(name, csrB64 string, login time.Time) response {
	csr, err := base64.StdEncoding.DecodeString(csrB64)
	if err != nil {
		return errResp(http.StatusBadRequest, "csr must be base64 DER")
	}
	ca, err := s.issuer()
	if err != nil {
		return s.fail(err)
	}
	id := pki.Identity{Kind: pki.Service, Name: name}
	if revoked, err := s.isRevoked("", id.String(), time.Time{}); err != nil {
		return s.fail(err)
	} else if revoked {
		return errResp(http.StatusForbidden, "identity revoked")
	}
	cert, err := ca.IssueFromCSR(csr, id, DefaultServiceTTL, login)
	if err != nil {
		return errResp(http.StatusBadRequest, err.Error())
	}
	chain := append(pki.EncodeCert(cert), pki.EncodeCert(ca.Cert)...)
	return ok(certResponse{Identity: id.String(), Certificate: string(chain), NotAfter: cert.NotAfter.Format(time.RFC3339)})
}

// ---- enrollment tokens ----

type enrollRecord struct {
	Identity string    `json:"identity"` // service name
	Expires  time.Time `json:"expires"`
	Used     bool      `json:"used"`
}

func tokenKey(token string) string {
	h := sha256.Sum256([]byte(token))
	return enrollPrefix + hex.EncodeToString(h[:]) // only the hash is stored
}

// createEnrollToken needs "create" on sys/enroll-tokens/<service>: a token
// becomes that service's certificate, so it is scoped like one.
func (s *Server) createEnrollToken(r *http.Request, c *call) response {
	var req struct {
		Service string `json:"service"`
		TTL     string `json:"ttl,omitempty"`
	}
	if err := decode(r, &req); err != nil {
		return errResp(http.StatusBadRequest, err.Error())
	}
	if err := validName(req.Service); err != nil {
		return errResp(http.StatusBadRequest, "invalid service name")
	}
	if !s.allowed(c.id, "sys/enroll-tokens/"+req.Service, policy.Create) {
		return errResp(http.StatusForbidden, "permission denied")
	}
	ttl := 15 * time.Minute
	if req.TTL != "" {
		d, err := time.ParseDuration(req.TTL)
		if err != nil || d <= 0 || d > maxEnrollTTL {
			return errResp(http.StatusBadRequest, "ttl must be a duration up to 1h")
		}
		ttl = d
	}
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	token := "smt_" + base64.RawURLEncoding.EncodeToString(raw)
	rec := enrollRecord{Identity: req.Service, Expires: time.Now().Add(ttl).UTC()}
	v, _ := json.Marshal(rec)
	if err := s.seal.PutIf(tokenKey(token), v, nil); err != nil {
		return s.fail(err)
	}
	return ok(map[string]string{"token": token, "service": req.Service, "expires": rec.Expires.Format(time.RFC3339)})
}

// consumeToken marks a token used (check-and-set, so two concurrent uses
// can't both succeed) and returns its service name.
func (s *Server) consumeToken(token string) (string, error) {
	v, tok, err := s.seal.GetToken(tokenKey(token))
	if err != nil {
		return "", errUnauthenticated
	}
	var rec enrollRecord
	if json.Unmarshal(v, &rec) != nil || rec.Used || time.Now().After(rec.Expires) {
		return "", errUnauthenticated
	}
	rec.Used = true
	nv, _ := json.Marshal(rec)
	if err := s.seal.PutIf(tokenKey(token), nv, tok); err != nil {
		return "", errUnauthenticated
	}
	return rec.Identity, nil
}

type loginRequest struct {
	Token string `json:"token,omitempty"` // enrollment token
	JWT   string `json:"jwt,omitempty"`   // Kubernetes service-account token
	CSR   string `json:"csr"`             // base64 DER
}

func (s *Server) enroll(r *http.Request, c *call) response {
	var req loginRequest
	if err := decode(r, &req); err != nil {
		return errResp(http.StatusBadRequest, err.Error())
	}
	// Check the CSR first so a malformed request doesn't burn the token.
	if der, err := base64.StdEncoding.DecodeString(req.CSR); err != nil {
		return errResp(http.StatusBadRequest, "csr must be base64 DER")
	} else if csr, err := x509.ParseCertificateRequest(der); err != nil || csr.CheckSignature() != nil {
		return errResp(http.StatusBadRequest, "invalid CSR")
	}
	name, err := s.consumeToken(req.Token)
	if err != nil {
		return errResp(http.StatusUnauthorized, err.Error())
	}
	c.id = "enroll:" + name // for the audit record
	return s.issueService(name, req.CSR, time.Now())
}

// renew issues a fresh certificate for the service presenting a valid one.
func (s *Server) renew(r *http.Request, c *call) response {
	if c.kind != pki.Service {
		return errResp(http.StatusForbidden, "only service certificates renew here")
	}
	var req loginRequest
	if err := decode(r, &req); err != nil {
		return errResp(http.StatusBadRequest, err.Error())
	}
	name := strings.TrimPrefix(c.id, "spiffe://"+pki.TrustDomain+"/svc/")
	// A renewal chain can't run forever: past MaxLineage since the last full
	// login, the service must prove who it is again (a stolen certificate
	// dies with it).
	login := pki.LoginTime(r.TLS.VerifiedChains[0][0])
	if time.Since(login) > s.maxLineage {
		return errResp(http.StatusForbidden, "last login was more than "+s.maxLineage.String()+" ago; log in again (enrollment token or Kubernetes)")
	}
	return s.issueService(name, req.CSR, login)
}

// ---- Kubernetes ----

// k8sConfig says how to reach the cluster's TokenReview API and which
// service accounts map to which service identities.
type k8sConfig struct {
	Host          string            `json:"host"`           // https://kubernetes.example:6443
	CAPEM         string            `json:"ca_pem"`         // CA of the Kubernetes API server
	ReviewerToken string            `json:"reviewer_token"` // token allowed to create TokenReviews
	Audience      string            `json:"audience"`       // audience projected tokens must carry
	Roles         map[string]string `json:"roles"`          // "namespace/serviceaccount" → service name
}

func (s *Server) putK8sConfig(r *http.Request, _ *call) response {
	var cfg k8sConfig
	if err := decode(r, &cfg); err != nil {
		return errResp(http.StatusBadRequest, err.Error())
	}
	if !strings.HasPrefix(cfg.Host, "https://") || cfg.Audience == "" || cfg.ReviewerToken == "" || len(cfg.Roles) == 0 {
		return errResp(http.StatusBadRequest, "host (https), audience, reviewer_token and roles are required")
	}
	if !x509.NewCertPool().AppendCertsFromPEM([]byte(cfg.CAPEM)) {
		return errResp(http.StatusBadRequest, "ca_pem has no certificates")
	}
	for sa, name := range cfg.Roles {
		if ns, acct, ok := strings.Cut(sa, "/"); !ok || ns == "" || acct == "" || validName(name) != nil {
			return errResp(http.StatusBadRequest, "roles must map namespace/serviceaccount to a service name")
		}
	}
	v, _ := json.Marshal(cfg)
	if err := s.seal.Put(k8sConfigPath, v); err != nil {
		return s.fail(err)
	}
	return ok(map[string]int{"roles": len(cfg.Roles)})
}

func (s *Server) kubernetesLogin(r *http.Request, c *call) response {
	var req loginRequest
	if err := decode(r, &req); err != nil || req.JWT == "" {
		return errResp(http.StatusBadRequest, "jwt and csr are required")
	}
	v, err := s.seal.Get(k8sConfigPath)
	if errors.Is(err, storage.ErrNotFound) {
		return errResp(http.StatusUnauthorized, "kubernetes login is not configured")
	}
	if err != nil {
		return s.fail(err)
	}
	var cfg k8sConfig
	if err := json.Unmarshal(v, &cfg); err != nil {
		return s.fail(err)
	}
	sa, err := tokenReview(r, cfg, req.JWT)
	if err != nil {
		s.log.Warn("kubernetes login rejected", "err", err)
		return errResp(http.StatusUnauthorized, errUnauthenticated.Error())
	}
	name, ok := cfg.Roles[sa]
	if !ok {
		return errResp(http.StatusUnauthorized, errUnauthenticated.Error())
	}
	c.id = "k8s:" + sa
	return s.issueService(name, req.CSR, time.Now())
}

// tokenReview asks the Kubernetes API whether jwt is a live service-account
// token for our audience, and returns "namespace/serviceaccount".
func tokenReview(r *http.Request, cfg k8sConfig, jwt string) (string, error) {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(cfg.CAPEM))
	hc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}}
	// A transport per call (the config can change): close its idle connection,
	// or every login, even a rejected one, leaves one open.
	// ponytail: a TLS handshake per login; cache the client per config if logins are hot.
	defer hc.CloseIdleConnections()
	body, _ := json.Marshal(map[string]any{
		"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview",
		"spec": map[string]any{"token": jwt, "audiences": []string{cfg.Audience}},
	})
	req, err := http.NewRequestWithContext(r.Context(), "POST",
		strings.TrimSuffix(cfg.Host, "/")+"/apis/authentication.k8s.io/v1/tokenreviews", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.ReviewerToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("tokenreview: %s", resp.Status)
	}
	var out struct {
		Status struct {
			Authenticated bool     `json:"authenticated"`
			Audiences     []string `json:"audiences"`
			Error         string   `json:"error"`
			User          struct {
				Username string `json:"username"`
			} `json:"user"`
		} `json:"status"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return "", err
	}
	st := out.Status
	if !st.Authenticated {
		return "", fmt.Errorf("token not authenticated: %s", st.Error)
	}
	if !slices.Contains(st.Audiences, cfg.Audience) {
		return "", errors.New("token audience mismatch")
	}
	parts := strings.Split(st.User.Username, ":")
	if len(parts) != 4 || parts[0] != "system" || parts[1] != "serviceaccount" {
		return "", fmt.Errorf("not a service account: %q", st.User.Username)
	}
	return parts[2] + "/" + parts[3], nil
}
