package api

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hamad-tariq/SecretsManager/internal/barrier"
	"github.com/hamad-tariq/SecretsManager/internal/cluster"
	"github.com/hamad-tariq/SecretsManager/internal/kv"
	"github.com/hamad-tariq/SecretsManager/internal/lease"
	"github.com/hamad-tariq/SecretsManager/internal/pki"
	"github.com/hamad-tariq/SecretsManager/internal/policy"
	"github.com/hamad-tariq/SecretsManager/internal/rotation"
	"github.com/hamad-tariq/SecretsManager/internal/secret"
	"github.com/hamad-tariq/SecretsManager/internal/snapshot"
	"github.com/hamad-tariq/SecretsManager/internal/storage"
)

// Storage keys (inside the barrier) for the API's own data.
const (
	policyPrefix  = "sys/policies/"
	bindingPrefix = "sys/bindings/"
	auditKeyPath  = "sys/audit-key"
)

func (s *Server) routes() map[string]route {
	fixed := func(p string, c policy.Capability) func(*http.Request) (string, policy.Capability, error) {
		return func(*http.Request) (string, policy.Capability, error) { return p, c, nil }
	}
	return map[string]route{
		"GET /v1/sys/health":  {op: "sys.health", auth: authNone, sealedOK: true, noAudit: true, handle: s.health},
		"GET /v1/sys/metrics": {op: "sys.metrics", auth: authPolicy, noAudit: true, perm: fixed("sys/metrics", policy.Read), handle: s.metricsText},

		"GET /v1/sys/snapshot":          {op: "sys.snapshot.save", auth: authPolicy, perm: fixed("sys/snapshot", policy.Read), handle: s.saveSnapshot},
		"POST /v1/sys/snapshot/restore": {op: "sys.snapshot.restore", auth: authAdmin, sealedOK: true, handle: s.restoreSnapshot},

		"GET /v1/sys/revocations":    {op: "sys.revocation.list", auth: authPolicy, perm: fixed("sys/revocations", policy.Read), handle: s.listRevocations},
		"POST /v1/sys/revocations":   {op: "sys.revocation.add", auth: authPolicy, perm: fixed("sys/revocations", policy.Update), handle: s.revoke},
		"DELETE /v1/sys/revocations": {op: "sys.revocation.remove", auth: authPolicy, perm: fixed("sys/revocations", policy.Delete), handle: s.unrevoke},
		"GET /v1/sys/root-admin":     {op: "sys.root-admin.read", auth: authPolicy, perm: fixed("sys/root-admin", policy.Read), handle: s.getRootAdmin},
		"POST /v1/sys/root-admin":    {op: "sys.root-admin.set", auth: authAdmin, handle: s.setRootAdmin},

		"GET /v1/sys/cluster":                 {op: "sys.cluster.read", auth: authPolicy, perm: fixed("sys/cluster", policy.Read), handle: s.clusterStatus},
		"DELETE /v1/sys/cluster/members/{id}": {op: "sys.cluster.remove", auth: authPolicy, perm: fixed("sys/cluster", policy.Update), handle: s.removeMember},
		"POST /v1/sys/cluster/step-down":      {op: "sys.cluster.step-down", auth: authPolicy, perm: fixed("sys/cluster", policy.Update), handle: s.stepDown},
		"POST /v1/sys/init":                   {op: "sys.init", auth: authAdmin, sealedOK: true, handle: s.init},
		// Unseal needs an admin certificate (any admin; one with no bindings
		// can do nothing else): anonymous callers could otherwise keep a node
		// sealed by feeding junk shares or taking the holders' share slots.
		"POST /v1/sys/unseal":  {op: "sys.unseal", auth: authAdmin, sealedOK: true, handle: s.unseal},
		"POST /v1/sys/seal":    {op: "sys.seal", auth: authPolicy, perm: fixed("sys/seal", policy.Update), handle: s.sealNow},
		"POST /v1/sys/rotate":  {op: "sys.rotate", auth: authPolicy, perm: fixed("sys/rotate", policy.Update), handle: s.rotate},
		"POST /v1/sys/rekey":   {op: "sys.rekey", auth: authPolicy, perm: fixed("sys/rekey", policy.Update), handle: s.rekey},
		"GET /v1/sys/policies": {op: "sys.policy.list", auth: authPolicy, perm: fixed("sys/policies", policy.List), handle: s.listPolicies},

		"GET /v1/sys/policies/{name}":    {op: "sys.policy.read", auth: authPolicy, perm: namePerm(policy.Read), handle: s.readPolicy},
		"PUT /v1/sys/policies/{name}":    {op: "sys.policy.write", auth: authPolicy, perm: namePerm(policy.Update), handle: s.writePolicy},
		"DELETE /v1/sys/policies/{name}": {op: "sys.policy.delete", auth: authPolicy, perm: namePerm(policy.Delete), handle: s.deletePolicy},

		"GET /v1/sys/bindings/{kind}/{name}":    {op: "sys.binding.read", auth: authPolicy, perm: bindingPerm(policy.Read), handle: s.readBinding},
		"PUT /v1/sys/bindings/{kind}/{name}":    {op: "sys.binding.write", auth: authPolicy, perm: bindingPerm(policy.Update), handle: s.writeBinding},
		"DELETE /v1/sys/bindings/{kind}/{name}": {op: "sys.binding.delete", auth: authPolicy, perm: bindingPerm(policy.Delete), handle: s.deleteBinding},

		"GET /v1/kv/{path...}":    {op: "kv.read", auth: authPolicy, perm: s.kvReadPerm, handle: s.kvRead},
		"PUT /v1/kv/{path...}":    {op: "kv.write", auth: authPolicy, perm: s.kvWritePerm, handle: s.kvWrite},
		"DELETE /v1/kv/{path...}": {op: "kv.delete", auth: authPolicy, perm: kvPerm(policy.Delete), handle: s.kvDelete},
		"POST /v1/kv/{path...}":   {op: "kv.undelete", auth: authPolicy, perm: kvPerm(policy.Update), handle: s.kvUndelete},

		"PUT /v1/sys/pki/intermediate": {op: "sys.pki.intermediate", auth: authPolicy, perm: fixed("sys/pki/intermediate", policy.Update), handle: s.putIntermediate},
		"POST /v1/sys/enroll-tokens":   {op: "sys.enroll.create", auth: authCert, handle: s.createEnrollToken}, // perm per service: in the handler
		"PUT /v1/sys/auth/kubernetes":  {op: "sys.auth.kubernetes", auth: authPolicy, perm: fixed("sys/auth/kubernetes", policy.Update), handle: s.putK8sConfig},
		"POST /v1/auth/enroll":         {op: "auth.enroll", auth: authNone, handle: s.enroll},
		"POST /v1/auth/kubernetes":     {op: "auth.kubernetes", auth: authNone, handle: s.kubernetesLogin},
		"POST /v1/auth/renew":          {op: "auth.renew", auth: authCert, handle: s.renew},

		"GET /v1/sys/rotation/{path...}":    {op: "sys.rotation.read", auth: authPolicy, perm: rotationPerm(policy.Read), handle: s.readRotation},
		"PUT /v1/sys/rotation/{path...}":    {op: "sys.rotation.write", auth: authPolicy, perm: rotationPerm(policy.Update), handle: s.writeRotation},
		"DELETE /v1/sys/rotation/{path...}": {op: "sys.rotation.delete", auth: authPolicy, perm: rotationPerm(policy.Delete), handle: s.deleteRotation},
		"POST /v1/sys/rotation/{path...}":   {op: "sys.rotation.trigger", auth: authPolicy, perm: rotationPerm(policy.Update), handle: s.triggerRotation},

		"GET /v1/sys/db-roles/{name}":    {op: "sys.dbrole.read", auth: authPolicy, perm: dbRolePerm(policy.Read), handle: s.readDBRole},
		"PUT /v1/sys/db-roles/{name}":    {op: "sys.dbrole.write", auth: authPolicy, perm: dbRolePerm(policy.Update), handle: s.writeDBRole},
		"DELETE /v1/sys/db-roles/{name}": {op: "sys.dbrole.delete", auth: authPolicy, perm: dbRolePerm(policy.Delete), handle: s.deleteDBRole},
		"POST /v1/db/creds/{name}":       {op: "db.creds", auth: authPolicy, perm: dbCredsPerm, handle: s.dbCreds},
		"POST /v1/leases/renew":          {op: "lease.renew", auth: authCert, handle: s.renewLease},
		"POST /v1/leases/revoke":         {op: "lease.revoke", auth: authCert, handle: s.revokeLease},

		"GET /v1/sys/leases/{prefix...}":                {op: "sys.lease.list", auth: authPolicy, perm: leasePerm(policy.List, false), handle: s.listLeases},
		"POST /v1/sys/leases/revoke-prefix/{prefix...}": {op: "sys.lease.revoke-prefix", auth: authPolicy, perm: leasePerm(policy.Update, true), handle: s.revokeLeasePrefix},
	}
}

// ---- sys ----

type healthResponse struct {
	barrier.Status
	Leader  bool `json:"leader"`
	Standby bool `json:"standby"`
}

// health is for load balancers: 200 leader, 429 unsealed standby (200 with
// ?standbyok, since standbys forward to the leader), 503 sealed, 501 not
// initialised.
func (s *Server) health(r *http.Request, _ *call) response {
	st, err := s.seal.Status()
	if err != nil {
		return s.fail(err)
	}
	leader := s.isLeader()
	status := http.StatusOK
	switch {
	case !st.Initialized:
		status = http.StatusNotImplemented
	case st.Sealed:
		status = http.StatusServiceUnavailable
	case !leader && !r.URL.Query().Has("standbyok"):
		status = http.StatusTooManyRequests
	}
	return response{status: status, body: healthResponse{Status: st, Leader: leader, Standby: !leader}}
}

func (s *Server) metricsText(*http.Request, *call) response {
	var b bytes.Buffer
	if err := s.metrics.Write(&b); err != nil {
		return s.fail(err)
	}
	return response{status: http.StatusOK, body: text(b.Bytes())}
}

// ---- snapshots and cluster membership ----

var errNoCluster = errors.New("not running as a cluster")

func (s *Server) saveSnapshot(*http.Request, *call) response {
	if s.cluster == nil {
		return errResp(http.StatusNotImplemented, errNoCluster.Error())
	}
	data, err := s.cluster.Dump()
	if err != nil {
		return s.fail(err)
	}
	return ok(snapshot.New(data, time.Now()))
}

// restoreSnapshot loads a snapshot into a new, empty cluster (like init, it
// needs an admin certificate and only works before initialisation). The
// cluster is then sealed; unseal it with the shares that were current when
// the snapshot was taken.
func (s *Server) restoreSnapshot(r *http.Request, _ *call) response {
	if s.cluster == nil {
		return errResp(http.StatusNotImplemented, errNoCluster.Error())
	}
	if st, err := s.seal.Status(); err != nil {
		return s.fail(err)
	} else if st.Initialized {
		return errResp(http.StatusConflict, "the cluster is already initialised; restore into a new, empty cluster")
	}
	f, err := snapshot.Read(io.LimitReader(r.Body, 64<<20))
	if err != nil {
		return errResp(http.StatusBadRequest, err.Error())
	}
	if err := s.cluster.Restore(f.Data); errors.Is(err, cluster.ErrNotEmpty) {
		return errResp(http.StatusConflict, err.Error())
	} else if err != nil {
		return s.fail(err)
	}
	st, err := s.seal.Status()
	if err != nil {
		return s.fail(err)
	}
	return ok(map[string]any{"restored_keys": len(f.Data), "snapshot_created": f.Created, "status": st})
}

func (s *Server) clusterStatus(*http.Request, *call) response {
	if s.cluster == nil {
		return errResp(http.StatusNotImplemented, errNoCluster.Error())
	}
	voters, err := s.cluster.Voters()
	if err != nil {
		return s.fail(err)
	}
	return ok(map[string]any{"leader": s.cluster.Leader(), "voters": voters, "members": s.cluster.Members()})
}

// removeMember takes a dead node out of the cluster, so quorum is counted
// over the nodes that remain.
func (s *Server) removeMember(r *http.Request, _ *call) response {
	if s.cluster == nil {
		return errResp(http.StatusNotImplemented, errNoCluster.Error())
	}
	id := r.PathValue("id")
	if (pki.Identity{Kind: pki.Node, Name: id}).Validate() != nil {
		return errResp(http.StatusBadRequest, "invalid node id")
	}
	if err := s.cluster.Remove(id); err != nil {
		return s.fail(err)
	}
	return ok(map[string]string{"removed": id})
}

// stepDown hands leadership to another node (before upgrading the leader).
func (s *Server) stepDown(*http.Request, *call) response {
	if s.cluster == nil {
		return errResp(http.StatusNotImplemented, errNoCluster.Error())
	}
	if err := s.cluster.StepDown(); err != nil {
		return s.fail(err)
	}
	return ok(map[string]string{"leader": s.cluster.Leader()})
}

type initRequest struct {
	Shares     int      `json:"shares"`
	Threshold  int      `json:"threshold"`
	Recipients []string `json:"recipients,omitempty"`
}

type sharesResponse struct {
	Shares  []string `json:"shares"`
	Warning string   `json:"warning,omitempty"`
}

// init: the admin who calls it becomes the root admin.
func (s *Server) init(r *http.Request, c *call) response {
	var req initRequest
	if err := decode(r, &req); err != nil {
		return errResp(http.StatusBadRequest, err.Error())
	}
	shares, err := s.seal.Init(req.Shares, req.Threshold, req.Recipients, c.id)
	if errors.Is(err, barrier.ErrAlreadyInitialized) {
		return errResp(http.StatusConflict, err.Error())
	}
	if err != nil {
		return errResp(http.StatusBadRequest, err.Error())
	}
	return ok(sharesResponse{Shares: shares})
}

func (s *Server) unseal(r *http.Request, _ *call) response {
	var req struct {
		Share string `json:"share"`
	}
	if err := decode(r, &req); err != nil {
		return errResp(http.StatusBadRequest, err.Error())
	}
	st, err := s.seal.Unseal(req.Share)
	switch {
	case errors.Is(err, barrier.ErrNotInitialized):
		return errResp(http.StatusBadRequest, err.Error())
	case errors.Is(err, barrier.ErrBadShare), errors.Is(err, barrier.ErrDuplicate), errors.Is(err, barrier.ErrInvalidShares):
		return errResp(http.StatusBadRequest, err.Error())
	case err != nil:
		return s.fail(err)
	}
	if !st.Sealed {
		if err := s.loadAuditKey(); err != nil {
			return s.fail(err)
		}
	}
	return ok(st)
}

// loadAuditKey fetches (creating on first unseal) the cluster-wide HMAC key
// for audit fingerprints, so every node's log fingerprints values alike.
func (s *Server) loadAuditKey() error {
	for range 3 {
		v, err := s.seal.Get(auditKeyPath)
		if err == nil {
			s.audit.SetHMACKey(v)
			return nil
		}
		if !errors.Is(err, storage.ErrNotFound) {
			return err
		}
		key := make([]byte, 32)
		_, _ = rand.Read(key)
		if err := s.seal.PutIf(auditKeyPath, key, nil); err != nil && !errors.Is(err, storage.ErrConflict) {
			return err
		}
	}
	return errors.New("api: could not establish audit key")
}

func (s *Server) sealNow(*http.Request, *call) response {
	s.seal.Seal()
	return ok(map[string]bool{"sealed": true})
}

func (s *Server) rotate(*http.Request, *call) response {
	term, err := s.seal.Rotate()
	if err != nil {
		return s.fail(err)
	}
	return ok(map[string]uint32{"term": term})
}

func (s *Server) rekey(r *http.Request, _ *call) response {
	var req struct {
		Shares     []string `json:"shares"`
		NewShares  int      `json:"new_shares"`
		Threshold  int      `json:"threshold"`
		Recipients []string `json:"recipients,omitempty"`
	}
	if err := decode(r, &req); err != nil {
		return errResp(http.StatusBadRequest, err.Error())
	}
	shares, err := s.seal.Rekey(req.Shares, req.NewShares, req.Threshold, req.Recipients)
	switch {
	case errors.Is(err, barrier.ErrRekeyUnknown):
		// Never withhold shares that might be the only way in.
		return ok(sharesResponse{Shares: shares, Warning: err.Error()})
	case errors.Is(err, barrier.ErrInvalidShares), errors.Is(err, barrier.ErrBadShare):
		return errResp(http.StatusBadRequest, err.Error())
	case err != nil:
		return s.fail(err)
	}
	return ok(sharesResponse{Shares: shares})
}

// ---- policies and bindings ----

func validName(name string) error {
	return (pki.Identity{Kind: pki.Service, Name: name}).Validate() // same rules: [a-z0-9-], 1-63
}

func namePerm(c policy.Capability) func(*http.Request) (string, policy.Capability, error) {
	return func(r *http.Request) (string, policy.Capability, error) {
		name := r.PathValue("name")
		if err := validName(name); err != nil {
			return "", "", fmt.Errorf("invalid policy name")
		}
		return "sys/policies/" + name, c, nil
	}
}

func (s *Server) listPolicies(*http.Request, *call) response {
	keys, err := s.seal.List(policyPrefix)
	if err != nil {
		return s.fail(err)
	}
	names := make([]string, 0, len(keys))
	for _, k := range keys {
		names = append(names, strings.TrimPrefix(k, policyPrefix))
	}
	return ok(map[string][]string{"policies": names})
}

func (s *Server) readPolicy(r *http.Request, _ *call) response {
	v, err := s.seal.Get(policyPrefix + r.PathValue("name"))
	if errors.Is(err, storage.ErrNotFound) {
		return errResp(http.StatusNotFound, "not found")
	}
	if err != nil {
		return s.fail(err)
	}
	return ok(json.RawMessage(v))
}

func (s *Server) writePolicy(r *http.Request, _ *call) response {
	body, err := readAll(r)
	if err != nil {
		return errResp(http.StatusBadRequest, err.Error())
	}
	p, err := policy.Parse(body)
	if err != nil {
		return errResp(http.StatusBadRequest, err.Error())
	}
	if p.Name != r.PathValue("name") {
		return errResp(http.StatusBadRequest, "policy name must match the URL")
	}
	if err := s.seal.Put(policyPrefix+p.Name, body); err != nil {
		return s.fail(err)
	}
	return ok(map[string]string{"name": p.Name})
}

func (s *Server) deletePolicy(r *http.Request, _ *call) response {
	if err := s.seal.Delete(policyPrefix + r.PathValue("name")); err != nil {
		return s.fail(err)
	}
	return ok(nil)
}

// bindingPerm checks a binding URL (kind/name) and maps it to its policy path.
func bindingPerm(c policy.Capability) func(*http.Request) (string, policy.Capability, error) {
	return func(r *http.Request) (string, policy.Capability, error) {
		id := pki.Identity{Kind: pki.Kind(r.PathValue("kind")), Name: r.PathValue("name")}
		if err := id.Validate(); err != nil {
			return "", "", err
		}
		return "sys/bindings/" + string(id.Kind) + "/" + id.Name, c, nil
	}
}

type binding struct {
	Policies []string `json:"policies"`
}

func bindingKey(r *http.Request) string {
	return bindingPrefix + r.PathValue("kind") + "/" + r.PathValue("name")
}

func (s *Server) readBinding(r *http.Request, _ *call) response {
	v, err := s.seal.Get(bindingKey(r))
	if errors.Is(err, storage.ErrNotFound) {
		return errResp(http.StatusNotFound, "not found")
	}
	if err != nil {
		return s.fail(err)
	}
	return ok(json.RawMessage(v))
}

func (s *Server) writeBinding(r *http.Request, _ *call) response {
	var b binding
	if err := decode(r, &b); err != nil {
		return errResp(http.StatusBadRequest, err.Error())
	}
	for _, p := range b.Policies {
		if validName(p) != nil {
			return errResp(http.StatusBadRequest, "invalid policy name "+strconv.Quote(p))
		}
	}
	v, _ := json.Marshal(b)
	if err := s.seal.Put(bindingKey(r), v); err != nil {
		return s.fail(err)
	}
	return ok(b)
}

func (s *Server) deleteBinding(r *http.Request, _ *call) response {
	if err := s.seal.Delete(bindingKey(r)); err != nil {
		return s.fail(err)
	}
	return ok(nil)
}

// policiesFor loads the policies bound to an identity URI. A binding that
// names a missing policy grants nothing for that name.
//
// ponytail: 1 + N storage reads per request (each a linearizable read on the
// leader). Cache with invalidation if policy checks show up in latency.
func (s *Server) policiesFor(identity string) ([]*policy.Policy, error) {
	kindName := strings.TrimPrefix(identity, "spiffe://"+pki.TrustDomain+"/")
	v, err := s.seal.Get(bindingPrefix + kindName)
	if errors.Is(err, storage.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var b binding
	if err := json.Unmarshal(v, &b); err != nil {
		return nil, err
	}
	var out []*policy.Policy
	for _, name := range b.Policies {
		raw, err := s.seal.Get(policyPrefix + name)
		if errors.Is(err, storage.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		p, err := policy.Parse(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// ---- kv ----

// kvPath validates the {path...} part and returns it with its policy path.
func kvPath(r *http.Request, allowPrefix bool) (string, string, error) {
	p := r.PathValue("path")
	if allowPrefix {
		p = strings.TrimSuffix(p, "/")
		if p == "" {
			return "", "kv", nil
		}
	}
	if err := policy.ValidPath(p); err != nil {
		return "", "", err
	}
	return p, "kv/" + p, nil
}

func kvPerm(c policy.Capability) func(*http.Request) (string, policy.Capability, error) {
	return func(r *http.Request) (string, policy.Capability, error) {
		_, pp, err := kvPath(r, false)
		return pp, c, err
	}
}

func (s *Server) kvReadPerm(r *http.Request) (string, policy.Capability, error) {
	if r.URL.Query().Has("list") {
		_, pp, err := kvPath(r, true)
		return pp, policy.List, err
	}
	_, pp, err := kvPath(r, false)
	return pp, policy.Read, err
}

// kvWritePerm needs "create" for a new secret and "update" for an existing
// one, soft-deleted included (writing revives it with its old versions).
// kvWrite re-checks at write time.
func (s *Server) kvWritePerm(r *http.Request) (string, policy.Capability, error) {
	p, pp, err := kvPath(r, false)
	if err != nil {
		return "", "", err
	}
	if _, err := s.kv.Metadata(p); errors.Is(err, kv.ErrNotFound) {
		return pp, policy.Create, nil
	}
	return pp, policy.Update, nil
}

type secretResponse struct {
	Path    string    `json:"path"`
	Value   string    `json:"value"`
	Version int       `json:"version"`
	Created time.Time `json:"created"`
}

func (s *Server) kvRead(r *http.Request, _ *call) response {
	q := r.URL.Query()
	if q.Has("list") {
		p, _, _ := kvPath(r, true)
		if p != "" {
			p += "/"
		}
		keys, err := s.kv.List(p)
		if err != nil {
			return s.fail(err)
		}
		return ok(map[string][]string{"keys": keys})
	}
	p, _, _ := kvPath(r, false)
	if q.Has("metadata") {
		m, err := s.kv.Metadata(p)
		if err != nil {
			return s.fail(err)
		}
		return ok(m)
	}
	version := 0
	if v := q.Get("version"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return errResp(http.StatusBadRequest, "version must be a positive integer")
		}
		version = n
	}
	sec, err := s.kv.Get(p, version, q.Get("label"))
	if err != nil {
		return s.fail(err)
	}
	return response{
		status:    http.StatusOK,
		body:      secretResponse{Path: p, Value: string(sec.Value), Version: sec.Version, Created: sec.Created},
		sensitive: map[string]secret.Secret{"value": secret.New(sec.Value)},
	}
}

func (s *Server) kvWrite(r *http.Request, c *call) response {
	var req struct {
		Value *string `json:"value"`
		CAS   *int    `json:"cas,omitempty"`
	}
	if err := decode(r, &req); err != nil || req.Value == nil || req.CAS != nil && *req.CAS < 0 {
		return errResp(http.StatusBadRequest, `body must be {"value": "...", "cas": optional version}`)
	}
	cas := -1
	if req.CAS != nil {
		cas = *req.CAS
	}
	p, pp, _ := kvPath(r, false)
	if !s.allowed(c.id, pp, policy.Update) {
		// Allowed in as "create": only if it still doesn't exist, even if
		// someone else wrote it since the check.
		cas = kv.MustNotExist
	}
	v, err := s.kv.Put(p, []byte(*req.Value), cas)
	if err != nil {
		return s.fail(err)
	}
	return response{status: http.StatusOK, body: map[string]int{"version": v},
		sensitive: map[string]secret.Secret{"value": secret.New([]byte(*req.Value))}}
}

func (s *Server) kvDelete(r *http.Request, _ *call) response {
	p, _, _ := kvPath(r, false)
	var err error
	if r.URL.Query().Has("destroy") {
		err = s.kv.Destroy(p)
	} else {
		err = s.kv.Delete(p)
	}
	if err != nil {
		return s.fail(err)
	}
	return ok(nil)
}

func (s *Server) kvUndelete(r *http.Request, _ *call) response {
	if r.URL.Query().Get("op") != "undelete" {
		return errResp(http.StatusBadRequest, "unsupported operation; use ?op=undelete")
	}
	p, _, _ := kvPath(r, false)
	if err := s.kv.Undelete(p); err != nil {
		return s.fail(err)
	}
	return ok(nil)
}

// ---- rotation ----

func rotationPerm(c policy.Capability) func(*http.Request) (string, policy.Capability, error) {
	return func(r *http.Request) (string, policy.Capability, error) {
		p, _, err := kvPath(r, false)
		return "sys/rotation/" + p, c, err
	}
}

func (s *Server) readRotation(r *http.Request, _ *call) response {
	p, _, _ := kvPath(r, false)
	rec, err := rotation.Get(s.seal.Barrier, p)
	if err != nil {
		return s.fail(err)
	}
	return ok(rec)
}

// mayUseAdmin: settings that make the server use the credentials at a kv path
// (rotation's and db roles' "admin") need read on that path. Otherwise anyone
// who may configure them could point the server at any secret.
func (s *Server) mayUseAdmin(c *call, path string) *response {
	if path != "" && !s.allowed(c.id, "kv/"+path, policy.Read) {
		r := errResp(http.StatusForbidden, "admin: you need read on kv/"+path+" to use it")
		return &r
	}
	return nil
}

func (s *Server) writeRotation(r *http.Request, c *call) response {
	var st rotation.Settings
	if err := decode(r, &st); err != nil {
		return errResp(http.StatusBadRequest, err.Error())
	}
	if err := st.Validate(); err != nil {
		return errResp(http.StatusBadRequest, err.Error())
	}
	if deny := s.mayUseAdmin(c, st.Params["admin"]); deny != nil {
		return *deny
	}
	p, _, _ := kvPath(r, false)
	rec, err := rotation.Configure(s.seal.Barrier, p, st, time.Now())
	if err != nil {
		return s.fail(err)
	}
	return ok(rec)
}

func (s *Server) deleteRotation(r *http.Request, _ *call) response {
	p, _, _ := kvPath(r, false)
	if err := rotation.Remove(s.seal.Barrier, p); err != nil {
		return s.fail(err)
	}
	return ok(nil)
}

// triggerRotation: POST ?op=rotate makes a rotation due now.
func (s *Server) triggerRotation(r *http.Request, _ *call) response {
	if r.URL.Query().Get("op") != "rotate" {
		return errResp(http.StatusBadRequest, "unsupported operation; use ?op=rotate")
	}
	p, _, _ := kvPath(r, false)
	rec, err := rotation.Trigger(s.seal.Barrier, p, time.Now())
	if err != nil {
		return s.fail(err)
	}
	return ok(rec)
}

// ---- dynamic database credentials and leases ----

func dbRolePerm(c policy.Capability) func(*http.Request) (string, policy.Capability, error) {
	return func(r *http.Request) (string, policy.Capability, error) {
		if validName(r.PathValue("name")) != nil {
			return "", "", errors.New("invalid role name")
		}
		return "sys/db-roles/" + r.PathValue("name"), c, nil
	}
}

func (s *Server) readDBRole(r *http.Request, _ *call) response {
	role, err := s.leases.Role(r.PathValue("name"))
	if err != nil {
		return s.fail(err)
	}
	return ok(role)
}

func (s *Server) writeDBRole(r *http.Request, c *call) response {
	var role lease.Role
	if err := decode(r, &role); err != nil {
		return errResp(http.StatusBadRequest, err.Error())
	}
	if err := role.Validate(); err != nil {
		return errResp(http.StatusBadRequest, err.Error())
	}
	if deny := s.mayUseAdmin(c, role.Admin); deny != nil {
		return *deny
	}
	if err := s.leases.PutRole(r.PathValue("name"), role); err != nil {
		return s.fail(err)
	}
	return ok(role)
}

func (s *Server) deleteDBRole(r *http.Request, _ *call) response {
	if err := s.leases.DeleteRole(r.PathValue("name")); err != nil {
		return s.fail(err)
	}
	return ok(nil)
}

// dbCredsPerm: getting credentials for role x needs "read" on db/creds/x.
func dbCredsPerm(r *http.Request) (string, policy.Capability, error) {
	if validName(r.PathValue("name")) != nil {
		return "", "", errors.New("invalid role name")
	}
	return "db/creds/" + r.PathValue("name"), policy.Read, nil
}

// optionalBody decodes a JSON body if there is one.
func optionalBody(r *http.Request, v any) error {
	if r.ContentLength == 0 {
		return nil
	}
	return decode(r, v)
}

func parseTTL(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 {
		return 0, errors.New("ttl must be a duration like 30m")
	}
	return d, nil
}

func (s *Server) dbCreds(r *http.Request, c *call) response {
	var req struct {
		TTL string `json:"ttl"`
	}
	if err := optionalBody(r, &req); err != nil {
		return errResp(http.StatusBadRequest, err.Error())
	}
	ttl, err := parseTTL(req.TTL)
	if err != nil {
		return errResp(http.StatusBadRequest, err.Error())
	}
	creds, err := s.leases.Issue(r.Context(), r.PathValue("name"), c.id, ttl)
	if err != nil {
		return s.fail(err)
	}
	return response{status: http.StatusOK, body: creds,
		sensitive: map[string]secret.Secret{"password": secret.New([]byte(creds.Password))}}
}

type leaseRequest struct {
	LeaseID   string `json:"lease_id"`
	Increment string `json:"increment,omitempty"`
}

// renewLease and revokeLease: only the identity that got the lease.
func (s *Server) renewLease(r *http.Request, c *call) response {
	var req leaseRequest
	if err := decode(r, &req); err != nil || req.LeaseID == "" {
		return errResp(http.StatusBadRequest, `body must be {"lease_id": "...", "increment": optional duration}`)
	}
	inc, err := parseTTL(req.Increment)
	if err != nil {
		return errResp(http.StatusBadRequest, err.Error())
	}
	l, err := s.leases.Renew(req.LeaseID, c.id, inc)
	if err != nil {
		return s.fail(err)
	}
	return ok(l)
}

func (s *Server) revokeLease(r *http.Request, c *call) response {
	var req leaseRequest
	if err := decode(r, &req); err != nil || req.LeaseID == "" {
		return errResp(http.StatusBadRequest, `body must be {"lease_id": "..."}`)
	}
	if err := s.leases.Revoke(r.Context(), req.LeaseID, c.id); err != nil {
		return s.fail(err)
	}
	return ok(nil)
}

// leasePerm maps a lease ID prefix to sys/leases/<prefix>.
func leasePerm(c policy.Capability, required bool) func(*http.Request) (string, policy.Capability, error) {
	return func(r *http.Request) (string, policy.Capability, error) {
		p := strings.TrimSuffix(r.PathValue("prefix"), "/")
		if p == "" {
			if required {
				return "", "", errors.New("a lease ID prefix is required, e.g. db/orders-rw")
			}
			return "sys/leases", c, nil
		}
		if err := policy.ValidPath(p); err != nil {
			return "", "", err
		}
		return "sys/leases/" + p, c, nil
	}
}

func (s *Server) listLeases(r *http.Request, _ *call) response {
	leases, err := s.leases.List(r.PathValue("prefix"))
	if err != nil {
		return s.fail(err)
	}
	return ok(map[string]any{"leases": leases})
}

// revokeLeasePrefix revokes synchronously: when it returns 200, the users are
// dropped and their sessions killed.
func (s *Server) revokeLeasePrefix(r *http.Request, _ *call) response {
	n, err := s.leases.RevokePrefix(r.Context(), r.PathValue("prefix"))
	if err != nil {
		s.log.Error("revoke-prefix", "prefix", r.PathValue("prefix"), "revoked", n, "err", err)
		return errResp(http.StatusBadGateway, fmt.Sprintf("revoked %d; the rest could not be dropped yet and will be retried", n))
	}
	return ok(map[string]int{"revoked": n})
}

func readAll(r *http.Request) ([]byte, error) {
	var raw json.RawMessage
	if err := json.NewDecoder(http.MaxBytesReader(nil, r.Body, maxBody)).Decode(&raw); err != nil {
		return nil, errors.New("invalid JSON body")
	}
	return raw, nil
}
