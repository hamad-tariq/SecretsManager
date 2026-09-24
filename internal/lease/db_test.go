package lease

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"log"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"

	"github.com/hamad-tariq/SecretsManager/internal/audit"
	"github.com/hamad-tariq/SecretsManager/internal/kv"
)

// Integration tests against real databases, run when these are set (same
// throwaway containers as internal/rotation/sql_test.go):
//
//	SM_TEST_POSTGRES=postgres://postgres:adminpw@127.0.0.1:55432/postgres
//	SM_TEST_MYSQL='root:adminpw@tcp(127.0.0.1:53306)/'

// session is an open connection held by a "pod".
type session interface {
	query(ctx context.Context) error
}

type dbUnderTest struct {
	plugin  string
	admin   string
	grants  []string
	badSQL  string // a grant that fails
	connect func(ctx context.Context, user, pw string) (session, error)
	count   func(ctx context.Context) (int, error) // v_ users in the database
	// validUntil reports the database's own expiry for a user (PostgreSQL only).
	validUntil func(ctx context.Context, user string) (time.Time, error)
}

func TestPostgresDynamicCredentials(t *testing.T) {
	admin := os.Getenv("SM_TEST_POSTGRES")
	if admin == "" {
		t.Skip("SM_TEST_POSTGRES not set")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, "CREATE TABLE IF NOT EXISTS sm_orders (id int)"); err != nil {
		t.Fatal(err)
	}
	cfg, _ := pgx.ParseConfig(admin)
	exercise(t, dbUnderTest{
		plugin: "postgres", admin: admin,
		grants: []string{"GRANT SELECT ON sm_orders TO {{name}}"},
		badSQL: "GRANT SELECT ON no_such_table TO {{name}}",
		connect: func(ctx context.Context, user, pw string) (session, error) {
			c := cfg.Copy()
			c.User, c.Password = user, pw
			pc, err := pgx.ConnectConfig(ctx, c)
			if err != nil {
				return nil, err
			}
			t.Cleanup(func() { _ = pc.Close(context.Background()) })
			return pgSession{pc}, nil
		},
		count: func(ctx context.Context) (n int, err error) {
			err = conn.QueryRow(ctx, "SELECT count(*) FROM pg_roles WHERE rolname LIKE 'v\\_%'").Scan(&n)
			return n, err
		},
		validUntil: func(ctx context.Context, user string) (t time.Time, err error) {
			err = conn.QueryRow(ctx, "SELECT rolvaliduntil FROM pg_roles WHERE rolname = $1", user).Scan(&t)
			return t, err
		},
	})
}

type pgSession struct{ c *pgx.Conn }

func (s pgSession) query(ctx context.Context) error {
	_, err := s.c.Exec(ctx, "SELECT count(*) FROM sm_orders")
	return err
}

func TestMySQLDynamicCredentials(t *testing.T) {
	admin := os.Getenv("SM_TEST_MYSQL")
	if admin == "" {
		t.Skip("SM_TEST_MYSQL not set")
	}
	ctx := context.Background()
	adb, err := openMySQL(admin)
	if err != nil {
		t.Fatal(err)
	}
	defer adb.Close()
	for _, q := range []string{"CREATE DATABASE IF NOT EXISTS smtest", "CREATE TABLE IF NOT EXISTS smtest.orders (id int)"} {
		if _, err := adb.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	_ = mysql.SetLogger(log.New(io.Discard, "", 0)) // killed sessions log "unexpected EOF": that's the point
	base, _ := mysql.ParseDSN(admin)
	exercise(t, dbUnderTest{
		plugin: "mysql", admin: admin,
		grants: []string{"GRANT SELECT ON smtest.* TO {{name}}"},
		badSQL: "GRANT SELECT ON no_such_db.no_such_table TO {{name}} WITH NONSENSE",
		connect: func(ctx context.Context, user, pw string) (session, error) {
			c := base.Clone()
			c.User, c.Passwd = user, pw
			conn, _ := mysql.NewConnector(c)
			db := sql.OpenDB(conn)
			t.Cleanup(func() { _ = db.Close() })
			held, err := db.Conn(ctx) // one pinned connection = one session
			if err != nil {
				return nil, err
			}
			return mysqlSession{held}, held.PingContext(ctx)
		},
		count: func(ctx context.Context) (n int, err error) {
			err = adb.QueryRowContext(ctx, "SELECT count(*) FROM mysql.user WHERE user LIKE 'v\\_%'").Scan(&n)
			return n, err
		},
	})
}

type mysqlSession struct{ c *sql.Conn }

func (s mysqlSession) query(ctx context.Context) error {
	_, err := s.c.ExecContext(ctx, "SELECT count(*) FROM smtest.orders")
	return err
}

func exercise(t *testing.T, d dbUnderTest) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	s := newSeal(t)
	clk := &clock{t: time.Now()}
	m := New(Config{Backend: s.Barrier, Sealed: s.Sealed, Leader: always, Audit: audit.New(io.Discard, nil, audit.Head{}),
		Log: slog.New(slog.DiscardHandler)})
	m.now = clk.now
	if _, err := kv.New(s.Barrier).Put("db/admin", []byte(d.admin), -1); err != nil {
		t.Fatal(err)
	}
	if err := m.PutRole("orders-rw", Role{Plugin: d.plugin, Admin: "db/admin", Grants: d.grants}); err != nil {
		t.Fatal(err)
	}
	if err := m.PutRole("broken", Role{Plugin: d.plugin, Admin: "db/admin", Grants: append(d.grants, d.badSQL)}); err != nil {
		t.Fatal(err)
	}
	before, err := d.count(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// A failing grant leaves neither a user nor a lease.
	if _, err := m.Issue(ctx, "broken", svc, 0); !errors.Is(err, ErrDatabase) {
		t.Fatalf("broken grant: %v", err)
	}
	if n, _ := d.count(ctx); n != before {
		t.Fatalf("failed create left a user (%d -> %d)", before, n)
	}

	// Three pods each hold two open sessions.
	var sessions []session
	for range 3 {
		c, err := m.Issue(ctx, "orders-rw", svc, 0)
		if err != nil {
			t.Fatal(err)
		}
		if d.validUntil != nil { // the database itself refuses the login after max TTL
			if vu, err := d.validUntil(ctx, c.Username); err != nil || !vu.Equal(c.MaxExpires.Truncate(time.Second)) {
				t.Fatalf("VALID UNTIL %v, want %v (%v)", vu, c.MaxExpires, err)
			}
		}
		for range 2 {
			sess, err := d.connect(ctx, c.Username, c.Password)
			if err != nil {
				t.Fatalf("login with issued credentials: %v", err)
			}
			if err := sess.query(ctx); err != nil {
				t.Fatalf("grant not applied: %v", err)
			}
			sessions = append(sessions, sess)
		}
	}

	// Exit criterion: revoke-by-prefix ends every session within 30 s.
	start := time.Now()
	n, err := m.RevokePrefix(ctx, "db/orders-rw/")
	if err != nil || n != 3 {
		t.Fatalf("revoke-prefix: %d %v", n, err)
	}
	for i, sess := range sessions {
		for sess.query(ctx) == nil {
			if time.Since(start) > 30*time.Second {
				t.Fatalf("session %d still alive 30 s after revocation", i)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	t.Logf("revoke-prefix: 3 users and 6 sessions gone in %s", time.Since(start).Round(time.Millisecond))
	if n, _ := d.count(ctx); n != before {
		t.Fatalf("users left after revoke (%d -> %d)", before, n)
	}

	// Expiry: the leader's tick drops the user once the TTL passes.
	c, err := m.Issue(ctx, "orders-rw", svc, 0)
	if err != nil {
		t.Fatal(err)
	}
	clk.add(DefaultTTL)
	m.Tick(ctx)
	if _, err := d.connect(ctx, c.Username, c.Password); err == nil {
		t.Fatal("expired credentials still log in")
	}
	if n, _ := d.count(ctx); n != before {
		t.Fatalf("expired user not dropped (%d -> %d)", before, n)
	}
	if l, _ := m.List(""); len(l) != 0 {
		t.Fatalf("leases left: %+v", l)
	}
}
