package rotation

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"

	"github.com/hamad-tariq/SecretsManager/internal/kv"
)

// Integration tests against real databases, run when these are set:
//
//	SM_TEST_POSTGRES=postgres://postgres:adminpw@127.0.0.1:55432/postgres
//	SM_TEST_MYSQL='root:adminpw@tcp(127.0.0.1:53306)/'
//
// e.g. with throwaway containers:
//
//	docker run -d --rm --name sm-test-pg -e POSTGRES_PASSWORD=adminpw -p 127.0.0.1:55432:5432 postgres:17-alpine
//	docker run -d --rm --name sm-test-mysql -e MYSQL_ROOT_PASSWORD=adminpw -p 127.0.0.1:53306:3306 mysql:8.4

func TestPostgresRotation(t *testing.T) {
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
	for _, u := range []string{"sm_app_a", "sm_app_b"} {
		for _, q := range []string{"DROP ROLE IF EXISTS " + u, "CREATE ROLE " + u + " LOGIN"} {
			if _, err := conn.Exec(ctx, q); err != nil {
				t.Fatal(err)
			}
		}
	}
	rotateAgainst(t, "postgres", admin, postgresDialect{}, map[string]string{})

	// Only a SCRAM verifier was sent, never the password.
	var stored string
	if err := conn.QueryRow(ctx, "SELECT rolpassword FROM pg_authid WHERE rolname = 'sm_app_a'").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stored, "SCRAM-SHA-256$4096:") {
		t.Fatalf("stored password %q", stored)
	}
}

func TestMySQLRotation(t *testing.T) {
	admin := os.Getenv("SM_TEST_MYSQL")
	if admin == "" {
		t.Skip("SM_TEST_MYSQL not set")
	}
	cfg, err := mysql.ParseDSN(admin)
	if err != nil {
		t.Fatal(err)
	}
	cfg.MultiStatements = true
	conn, _ := mysql.NewConnector(cfg)
	db := sql.OpenDB(conn)
	defer db.Close()
	for _, u := range []string{"sm_app_a", "sm_app_b"} {
		if _, err := db.Exec("DROP USER IF EXISTS '" + u + "'@'%'; CREATE USER '" + u + "'@'%' IDENTIFIED BY 'initialPassword1'"); err != nil {
			t.Fatal(err)
		}
	}
	rotateAgainst(t, "mysql", admin, mysqlDialect{}, map[string]string{"host": "%"})
}

// rotateAgainst runs four rotations and checks, after each, that both the
// current and the previous credential log in (dual validity) and that the
// user alternates.
func rotateAgainst(t *testing.T, plugin, admin string, d dialect, extra map[string]string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	s := newSeal(t)
	store := kv.New(s.Barrier)
	if _, err := store.Put("db/admin", []byte(admin), -1); err != nil {
		t.Fatal(err)
	}
	params := map[string]string{"admin": "db/admin", "users": "sm_app_a,sm_app_b"}
	for k, v := range extra {
		params[k] = v
	}
	clk := &clock{t: time.Now()}
	if _, err := Configure(s.Barrier, "db/app", Settings{Interval: "1h", Plugin: plugin, Params: params}, clk.now()); err != nil {
		t.Fatal(err)
	}
	e := newEngine(s, always, clk)
	cred := func(label string) credential {
		sec, err := store.Get("db/app", 0, label)
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		var c credential
		_ = json.Unmarshal(sec.Value, &c)
		return c
	}
	var last string
	for i := range 4 {
		if i > 0 {
			if _, err := Trigger(s.Barrier, "db/app", clk.now()); err != nil {
				t.Fatal(err)
			}
		}
		e.Tick(ctx)
		if r, _ := Get(s.Barrier, "db/app"); r.Step != "" || r.LastError != "" {
			t.Fatalf("rotation %d did not complete: %+v", i, r)
		}
		cur := cred("")
		if cur.Username == last {
			t.Fatalf("rotation %d reused user %s", i, cur.Username)
		}
		last = cur.Username
		if err := d.login(ctx, admin, cur.Username, cur.Password); err != nil {
			t.Fatalf("rotation %d: current credential: %v", i, err)
		}
		if i > 0 {
			prev := cred(kv.LabelPrevious)
			if err := d.login(ctx, admin, prev.Username, prev.Password); err != nil {
				t.Fatalf("rotation %d: previous credential stopped working: %v", i, err)
			}
			if err := d.login(ctx, admin, cur.Username, prev.Password); err == nil {
				t.Fatal("login with the wrong password succeeded")
			}
		}
	}
}

func TestScrubRemovesConnectionString(t *testing.T) {
	for _, dsn := range []string{"postgres://admin:hunter22@db:5432/app", "admin:hunter22@tcp(db:3306)/"} {
		err := Scrub(fmt.Errorf("cannot parse `%s`: bad; auth failed for hunter22", dsn), dsn) // whole string, then password alone
		if strings.Contains(err.Error(), "hunter22") || strings.Contains(err.Error(), dsn) {
			t.Fatalf("%s: %v", dsn, err)
		}
	}
	if Scrub(nil, "x") != nil {
		t.Fatal("nil error changed")
	}
}

func TestScrubRemovesNonDSNSecret(t *testing.T) {
	// A kv path that holds some other secret: the parse error quotes it whole.
	if err := Scrub(fmt.Errorf("cannot parse `tok_9f8e7d`: invalid"), "tok_9f8e7d"); strings.Contains(err.Error(), "tok_9f8e7d") {
		t.Fatal(err)
	}
}
