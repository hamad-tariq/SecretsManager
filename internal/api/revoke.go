package api

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/hamad-tariq/SecretsManager/internal/barrier"
	"github.com/hamad-tariq/SecretsManager/internal/pki"
	"github.com/hamad-tariq/SecretsManager/internal/storage"
)

// Revocation: certificates (by serial) and whole identities that the API
// refuses before anything else, whatever their policies. One record, so each
// request costs one read, like the policy lookup.
//
// The cluster's own Raft and RPC traffic doesn't consult this list (it runs
// below the barrier); take a compromised node out with remove-node.
const (
	revocationsPath = "sys/revocations"
	rootAdminPath   = "sys/root-admin"

	// A revoked serial is kept until the longest certificate it could be
	// (a node's) would have expired, unless told when it expires.
	defaultRevokeFor = 366 * 24 * time.Hour
)

type revokedEntry struct {
	Reason string    `json:"reason,omitempty"`
	At     time.Time `json:"at"`
	By     string    `json:"by"`
	Until  time.Time `json:"until,omitzero"` // serials: dropped from the list after this
}

type revocations struct {
	Serials    map[string]revokedEntry `json:"serials"`    // lowercase hex, as in the audit log
	Identities map[string]revokedEntry `json:"identities"` // spiffe URIs
	// Lineages: a certificate and every renewal of it, before or after. A
	// renewal carries the login time forward, so identity@login names them
	// all; revoking only the serial would miss a copy already renewed.
	Lineages map[string]revokedEntry `json:"lineages,omitempty"`
}

func lineageKey(identity string, login time.Time) string {
	return identity + "@" + login.UTC().Format(time.RFC3339)
}

func (s *Server) loadRevocations() (*revocations, []byte, error) {
	raw, tok, err := s.seal.GetToken(revocationsPath)
	rv := &revocations{Serials: map[string]revokedEntry{}, Identities: map[string]revokedEntry{}, Lineages: map[string]revokedEntry{}}
	if errors.Is(err, storage.ErrNotFound) {
		return rv, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if err := json.Unmarshal(raw, rv); err != nil {
		return nil, nil, err
	}
	if rv.Serials == nil {
		rv.Serials = map[string]revokedEntry{}
	}
	if rv.Identities == nil {
		rv.Identities = map[string]revokedEntry{}
	}
	if rv.Lineages == nil {
		rv.Lineages = map[string]revokedEntry{}
	}
	return rv, tok, nil
}

// isRevoked reports whether a certificate (serial in lowercase hex), its
// lineage (identity + login time; zero login: not checked) or its identity
// is revoked.
func (s *Server) isRevoked(serial, identity string, login time.Time) (bool, error) {
	rv, _, err := s.loadRevocations()
	if err != nil {
		return false, err
	}
	_, bySerial := rv.Serials[serial]
	_, byID := rv.Identities[identity]
	_, byLineage := rv.Lineages[lineageKey(identity, login)]
	return (serial != "" && bySerial) || (identity != "" && byID) || (identity != "" && !login.IsZero() && byLineage), nil
}

// CertRevoked is isRevoked for a certificate; the rotation engine uses it for
// the services it calls.
func (s *Server) CertRevoked(c *x509.Certificate) (bool, error) {
	id, err := pki.IdentityFromCert(c)
	if err != nil {
		return false, err
	}
	return s.isRevoked(c.SerialNumber.Text(16), id.String(), pki.LoginTime(c))
}

// updateRevocations applies fn with check-and-set, dropping expired serials.
func (s *Server) updateRevocations(fn func(rv *revocations) error) (*revocations, error) {
	for range 5 {
		rv, tok, err := s.loadRevocations()
		if err != nil {
			return nil, err
		}
		if err := fn(rv); err != nil {
			return nil, err
		}
		now := time.Now()
		for _, m := range []map[string]revokedEntry{rv.Serials, rv.Lineages} {
			for k, e := range m {
				if !e.Until.IsZero() && now.After(e.Until) {
					delete(m, k)
				}
			}
		}
		v, _ := json.Marshal(rv)
		if err := s.seal.PutIf(revocationsPath, v, tok); !errors.Is(err, storage.ErrConflict) {
			return rv, err
		}
	}
	return nil, errors.New("revocation list busy, try again")
}

// normSerial accepts hex with or without colons or leading zeros.
func normSerial(s string) (string, bool) {
	n, ok := new(big.Int).SetString(strings.ReplaceAll(strings.ToLower(strings.TrimSpace(s)), ":", ""), 16)
	if !ok || n.Sign() <= 0 {
		return "", false
	}
	return n.Text(16), true
}

// normIdentity accepts "kind/name" or a full spiffe URI.
func normIdentity(s string) (string, bool) {
	s = strings.TrimPrefix(s, "spiffe://"+pki.TrustDomain+"/")
	kind, name, _ := strings.Cut(s, "/")
	id := pki.Identity{Kind: pki.Kind(kind), Name: name}
	if id.Validate() != nil {
		return "", false
	}
	return id.String(), true
}

type revokeRequest struct {
	Serial   string    `json:"serial,omitempty"`
	Identity string    `json:"identity,omitempty"`
	Reason   string    `json:"reason,omitempty"`
	Until    time.Time `json:"until,omitzero"` // the certificate's expiry, if known
	Login    time.Time `json:"login,omitzero"` // with identity: revoke that lineage, not the identity
}

func (s *Server) revoke(r *http.Request, c *call) response {
	var req revokeRequest
	if err := decode(r, &req); err != nil {
		return errResp(http.StatusBadRequest, err.Error())
	}
	if req.Login.IsZero() && (req.Serial == "") == (req.Identity == "") || !req.Login.IsZero() && req.Identity == "" {
		return errResp(http.StatusBadRequest, "give a serial, an identity, or identity and login (a certificate's whole lineage)")
	}
	now := time.Now().UTC()
	e := revokedEntry{Reason: req.Reason, At: now, By: c.id}
	rv, err := s.updateRevocations(func(rv *revocations) error {
		if req.Serial != "" {
			sn, valid := normSerial(req.Serial)
			if !valid {
				return errBadRevoke("serial must be the certificate's serial number in hex")
			}
			se := e
			se.Until = req.Until
			if se.Until.IsZero() {
				se.Until = now.Add(defaultRevokeFor)
			}
			rv.Serials[sn] = se
		}
		if req.Identity == "" {
			return nil
		}
		id, valid := normIdentity(req.Identity)
		if !valid {
			return errBadRevoke("identity must be kind/name, e.g. svc/orders-api")
		}
		if !req.Login.IsZero() {
			// Renewals stop at login + maxLineage; the last one lives at most a year past that.
			le := e
			le.Until = req.Login.Add(s.maxLineage + defaultRevokeFor)
			rv.Lineages[lineageKey(id, req.Login)] = le
			return nil
		}
		if root, err := s.rootAdmin(); err != nil {
			return err
		} else if id == root {
			return errBadRevoke("that is the root admin; hand root to another admin first (smctl operator root-admin)")
		}
		rv.Identities[id] = e
		return nil
	})
	var bad errBadRevoke
	if errors.As(err, &bad) {
		return errResp(http.StatusBadRequest, string(bad))
	}
	if err != nil {
		return s.fail(err)
	}
	return ok(rv)
}

type errBadRevoke string

func (e errBadRevoke) Error() string { return string(e) }

func (s *Server) listRevocations(*http.Request, *call) response {
	rv, _, err := s.loadRevocations()
	if err != nil {
		return s.fail(err)
	}
	return ok(rv)
}

// unrevoke reinstates a serial, identity or lineage: DELETE ?serial=..., ?identity=... or ?lineage=...
func (s *Server) unrevoke(r *http.Request, _ *call) response {
	q := r.URL.Query()
	rv, err := s.updateRevocations(func(rv *revocations) error {
		if sn, ok := normSerial(q.Get("serial")); ok {
			delete(rv.Serials, sn)
			return nil
		}
		if id, ok := normIdentity(q.Get("identity")); ok {
			delete(rv.Identities, id)
			return nil
		}
		if l := q.Get("lineage"); l != "" {
			if _, ok := rv.Lineages[l]; !ok {
				return errBadRevoke("no such lineage (see \"lineages\" in the list)")
			}
			delete(rv.Lineages, l)
			return nil
		}
		return errBadRevoke("give ?serial=HEX, ?identity=kind/name or ?lineage=KEY")
	})
	var bad errBadRevoke
	if errors.As(err, &bad) {
		return errResp(http.StatusBadRequest, string(bad))
	}
	if err != nil {
		return s.fail(err)
	}
	return ok(rv)
}

// ---- root admin ----

// rootAdmin is the identity with unrestricted access: the one named at init,
// unless share holders have since handed it to someone else.
func (s *Server) rootAdmin() (string, error) {
	v, err := s.seal.Get(rootAdminPath)
	if errors.Is(err, storage.ErrNotFound) {
		return s.seal.RootAdmin(), nil
	}
	if err != nil {
		return "", err
	}
	return string(v), nil
}

// setRootAdmin hands root to another admin. The authority is a threshold of
// unseal shares, not a certificate: someone who stole the root admin's
// certificate can't keep root, and can't take it without the share holders.
func (s *Server) setRootAdmin(r *http.Request, _ *call) response {
	var req struct {
		Identity string   `json:"identity"`
		Shares   []string `json:"shares"`
	}
	if err := decode(r, &req); err != nil {
		return errResp(http.StatusBadRequest, err.Error())
	}
	id, valid := normIdentity(req.Identity)
	if !valid || !strings.HasPrefix(id, "spiffe://"+pki.TrustDomain+"/admin/") {
		return errResp(http.StatusBadRequest, "identity must be an admin, e.g. admin/bob")
	}
	if err := s.seal.VerifyShares(req.Shares); errors.Is(err, barrier.ErrInvalidShares) || errors.Is(err, barrier.ErrBadShare) {
		return errResp(http.StatusForbidden, "the shares don't reconstruct the unseal key")
	} else if err != nil {
		return s.fail(err)
	}
	if revoked, err := s.isRevoked("", id, time.Time{}); err != nil {
		return s.fail(err)
	} else if revoked {
		return errResp(http.StatusBadRequest, "that identity is revoked")
	}
	if err := s.seal.Put(rootAdminPath, []byte(id)); err != nil {
		return s.fail(err)
	}
	return ok(map[string]string{"root_admin": id})
}

func (s *Server) getRootAdmin(*http.Request, *call) response {
	id, err := s.rootAdmin()
	if err != nil {
		return s.fail(err)
	}
	return ok(map[string]string{"root_admin": id})
}
