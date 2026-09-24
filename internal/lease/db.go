package lease

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"

	"github.com/hamad-tariq/SecretsManager/internal/rotation"
)

// User is a database user to create or drop.
type User struct {
	Name, Password, Host string
	ValidUntil           time.Time // PostgreSQL: the login stops working then even if a drop fails
	Grants               []string
}

// Database creates and drops users. Drop must kill the user's open sessions,
// and must succeed if the user doesn't exist.
type Database interface {
	Create(ctx context.Context, admin string, u User) error
	Drop(ctx context.Context, admin string, u User) error
}

var Databases = map[string]Database{"postgres": postgres{}, "mysql": mysqlDB{}}

// Generated names and passwords are the only values spliced into SQL
// (besides the operator's grant statements); check them anyway.
var (
	userRe  = regexp.MustCompile(`^v_[a-z0-9_]{1,30}$`)
	alnumRe = regexp.MustCompile(`^[A-Za-z0-9]*$`)
)

func check(u User) error {
	if !userRe.MatchString(u.Name) || !alnumRe.MatchString(u.Password) || u.Host != "" && !hostRe.MatchString(u.Host) {
		return errors.New("lease: refusing unexpected user name, password or host")
	}
	return nil
}

// ---- PostgreSQL ----

type postgres struct{}

func (postgres) Create(ctx context.Context, admin string, u User) error {
	if err := check(u); err != nil {
		return err
	}
	conn, err := pgx.Connect(ctx, admin)
	if err != nil {
		return err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	verifier, err := rotation.SCRAMVerifier(u.Password) // never the plaintext: statement logs
	if err != nil {
		return err
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }() // no-op after Commit
	ident := pgx.Identifier{u.Name}.Sanitize()
	stmts := []string{fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD '%s' VALID UNTIL '%s'",
		ident, verifier, u.ValidUntil.UTC().Format(time.RFC3339))}
	for _, g := range u.Grants {
		stmts = append(stmts, strings.ReplaceAll(g, "{{name}}", ident))
	}
	for _, s := range stmts {
		if _, err := tx.Exec(ctx, s); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// Drop: block new logins, end every session, hand anything the user created
// to the admin, drop it.
func (postgres) Drop(ctx context.Context, admin string, u User) error {
	if err := check(u); err != nil {
		return err
	}
	conn, err := pgx.Connect(ctx, admin)
	if err != nil {
		return err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	var exists bool
	if err := conn.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)", u.Name).Scan(&exists); err != nil || !exists {
		return err
	}
	ident := pgx.Identifier{u.Name}.Sanitize()
	for _, s := range []string{
		"ALTER ROLE " + ident + " NOLOGIN",
		"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '" + u.Name + "'",
		"REASSIGN OWNED BY " + ident + " TO CURRENT_USER",
		"DROP OWNED BY " + ident,
		"DROP ROLE " + ident,
	} {
		if _, err := conn.Exec(ctx, s); err != nil {
			return err
		}
	}
	return nil
}

// ---- MySQL ----

type mysqlDB struct{}

func openMySQL(dsn string) (*sql.DB, error) {
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		return nil, err
	}
	conn, err := mysql.NewConnector(cfg)
	if err != nil {
		return nil, err
	}
	return sql.OpenDB(conn), nil
}

func account(u User) string {
	host := u.Host
	if host == "" {
		host = "%"
	}
	return "'" + u.Name + "'@'" + host + "'"
}

// Create: MySQL DDL can't be rolled back, so a failed grant drops the user.
func (d mysqlDB) Create(ctx context.Context, admin string, u User) error {
	if err := check(u); err != nil {
		return err
	}
	db, err := openMySQL(admin)
	if err != nil {
		return err
	}
	defer db.Close()
	acct := account(u)
	stmts := []string{"CREATE USER " + acct + " IDENTIFIED BY '" + u.Password + "'"} // masked in MySQL's logs
	for _, g := range u.Grants {
		stmts = append(stmts, strings.ReplaceAll(g, "{{name}}", acct))
	}
	for _, s := range stmts {
		if _, err := db.ExecContext(ctx, s); err != nil {
			if derr := d.Drop(context.WithoutCancel(ctx), admin, u); derr != nil {
				return errors.Join(err, derr)
			}
			return err
		}
	}
	return nil
}

// Drop: dropping a MySQL user doesn't end its sessions, so drop first (no new
// logins) and then kill what's left.
func (mysqlDB) Drop(ctx context.Context, admin string, u User) error {
	if err := check(u); err != nil {
		return err
	}
	db, err := openMySQL(admin)
	if err != nil {
		return err
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, "DROP USER IF EXISTS "+account(u)); err != nil {
		return err
	}
	rows, err := db.QueryContext(ctx, "SELECT ID FROM information_schema.PROCESSLIST WHERE USER = ?", u.Name)
	if err != nil {
		return err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	_ = rows.Close()
	for _, id := range ids {
		// A session may end on its own in between: "Unknown thread id" is fine.
		if _, err := db.ExecContext(ctx, fmt.Sprintf("KILL %d", id)); err != nil && !strings.Contains(err.Error(), "Unknown thread") {
			return err
		}
	}
	return rows.Err()
}
