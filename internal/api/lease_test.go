package api

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/hamad-tariq/SecretsManager/internal/lease"
)

// memDB is a stand-in database for the API tests (the real ones are
// exercised in internal/lease).
type memDB struct {
	mu    sync.Mutex
	users map[string]bool
	down  bool
}

func (d *memDB) Create(_ context.Context, _ string, u lease.User) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.users[u.Name] = true
	return nil
}

func (d *memDB) Drop(_ context.Context, _ string, u lease.User) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.down {
		return errors.New("connection refused")
	}
	delete(d.users, u.Name)
	return nil
}

func (d *memDB) n() int { d.mu.Lock(); defer d.mu.Unlock(); return len(d.users) }

func TestDynamicCredentialRoutes(t *testing.T) {
	db := &memDB{users: map[string]bool{}}
	lease.Databases["mem"] = db
	t.Cleanup(func() { delete(lease.Databases, "mem") })

	e := newEnv(t)
	admin := e.ready()
	svc, other := e.client(orders), e.client(billing)

	e.expect(admin, "PUT", "/v1/kv/db/admin", map[string]string{"value": "admin-dsn"}, 200)
	role := map[string]any{"plugin": "mem", "admin": "db/admin", "grants": []string{"GRANT SELECT ON orders TO {{name}}"}, "default_ttl": "30m"}
	e.expect(admin, "PUT", "/v1/sys/db-roles/orders-rw", map[string]any{"plugin": "oracle", "admin": "db/admin"}, 400)
	e.expect(admin, "PUT", "/v1/sys/db-roles/Bad_Name", role, 400)
	e.expect(admin, "PUT", "/v1/sys/db-roles/orders-rw", role, 200)
	if got := e.expect(admin, "GET", "/v1/sys/db-roles/orders-rw", nil, 200); got["default_ttl"] != "30m" {
		t.Fatalf("role: %v", got)
	}

	// Policy: orders-api may get credentials for orders-rw only.
	e.expect(svc, "POST", "/v1/db/creds/orders-rw", nil, 403)
	pol := `{"name":"orders-db","rules":[{"path":"db/creds/orders-rw","capabilities":["read"]}]}`
	e.expect(admin, "PUT", "/v1/sys/policies/orders-db", pol, 200)
	e.expect(admin, "PUT", "/v1/sys/bindings/svc/orders-api", map[string]any{"policies": []string{"orders-db"}}, 200)
	e.expect(svc, "POST", "/v1/db/creds/other-role", nil, 403)

	creds := e.expect(svc, "POST", "/v1/db/creds/orders-rw", nil, 200)
	id, _ := creds["lease_id"].(string)
	if !strings.HasPrefix(id, "db/orders-rw/") || len(creds["password"].(string)) != 32 || db.n() != 1 {
		t.Fatalf("creds %v", creds)
	}
	e.expect(svc, "POST", "/v1/db/creds/orders-rw", map[string]string{"ttl": "soon"}, 400)
	e.expect(svc, "POST", "/v1/db/creds/orders-rw", map[string]string{"ttl": "5m"}, 200)

	// Renew and revoke: the owner only.
	e.expect(other, "POST", "/v1/leases/renew", map[string]string{"lease_id": id}, 403)
	e.expect(svc, "POST", "/v1/leases/renew", map[string]string{"lease_id": id, "increment": "10m"}, 200)
	e.expect(svc, "POST", "/v1/leases/renew", map[string]string{}, 400)
	e.expect(other, "POST", "/v1/leases/revoke", map[string]string{"lease_id": id}, 403)
	e.expect(svc, "POST", "/v1/leases/revoke", map[string]string{"lease_id": id}, 200)
	e.expect(svc, "POST", "/v1/leases/revoke", map[string]string{"lease_id": id}, 404)
	if db.n() != 1 {
		t.Fatalf("revoke left %d users, want 1", db.n())
	}

	// Operators list and revoke by prefix; services can't.
	for range 3 {
		e.expect(svc, "POST", "/v1/db/creds/orders-rw", nil, 200)
	}
	e.expect(svc, "GET", "/v1/sys/leases/db", nil, 403)
	if got := e.expect(admin, "GET", "/v1/sys/leases/db/orders-rw", nil, 200); len(got["leases"].([]any)) != 4 {
		t.Fatalf("list: %v", got)
	}
	e.expect(svc, "POST", "/v1/sys/leases/revoke-prefix/db/orders-rw", nil, 403)
	e.expect(admin, "POST", "/v1/sys/leases/revoke-prefix/", nil, 400) // no revoke-everything by accident

	db.down = true
	e.expect(admin, "POST", "/v1/sys/leases/revoke-prefix/db/orders-rw", nil, 502)
	db.down = false
	if got := e.expect(admin, "POST", "/v1/sys/leases/revoke-prefix/db/orders-rw", nil, 200); got["revoked"] != float64(4) || db.n() != 0 {
		t.Fatalf("revoke-prefix: %v, %d users left", got, db.n())
	}

	e.expect(admin, "DELETE", "/v1/sys/db-roles/orders-rw", nil, 200)
	e.expect(svc, "POST", "/v1/db/creds/orders-rw", nil, 404)
}

// Settings that make the server use credentials at a kv path need read on
// that path: otherwise "configure rotation" would mean "read any secret".
func TestAdminPathNeedsRead(t *testing.T) {
	e := newEnv(t)
	admin := e.ready()
	e.expect(admin, "PUT", "/v1/sys/policies/dba", `{"name":"dba","rules":[{"path":"sys/rotation/*","capabilities":["create","update","read"]},{"path":"sys/db-roles/*","capabilities":["create","update","read"]}]}`, 200)
	e.expect(admin, "PUT", "/v1/sys/bindings/admin/bob", map[string]any{"policies": []string{"dba"}}, 200)
	bob := e.client(otherAdmin)
	rot := map[string]any{"interval": "720h", "plugin": "postgres", "params": map[string]string{"admin": "db/admin", "users": "app_a,app_b"}}
	role := map[string]any{"plugin": "postgres", "admin": "db/admin", "grants": []string{"GRANT SELECT ON t TO {{name}}"}}
	e.expect(bob, "PUT", "/v1/sys/rotation/db/app", rot, 403)
	e.expect(bob, "PUT", "/v1/sys/db-roles/app", role, 403)

	e.expect(admin, "PUT", "/v1/sys/policies/dba", `{"name":"dba","rules":[{"path":"sys/rotation/*","capabilities":["create","update","read"]},{"path":"sys/db-roles/*","capabilities":["create","update","read"]},{"path":"kv/db/admin","capabilities":["read"]}]}`, 200)
	e.expect(bob, "PUT", "/v1/sys/rotation/db/app", rot, 200)
	e.expect(bob, "PUT", "/v1/sys/db-roles/app", role, 200)
}
