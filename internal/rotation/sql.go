package rotation

import (
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"

	"github.com/hamad-tariq/SecretsManager/internal/policy"
)

// Database password rotation (PostgreSQL, MySQL).
//
// Parameters:
//
//	admin   kv path of a secret holding the admin connection string
//	        (postgres://admin:pw@db:5432/app, or admin:pw@tcp(db:3306)/ for MySQL);
//	        that user needs the right to change the users' passwords
//	users   "app_a,app_b" (two alternating users, recommended) or one user
//	host    MySQL account host, default "%"
//	length  password length, default 32
//
// The rotated secret's value is {"username": ..., "password": ...}. With two
// users each rotation changes the password of the user NOT currently in use,
// then switches to it, so clients still holding the previous credential keep
// working until the next rotation. With one user, clients fail from the set
// step until they pick up the new value.

type credential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

var (
	userRe  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,31}$`)
	hostRe  = regexp.MustCompile(`^[A-Za-z0-9_.%:-]{1,255}$`)
	alnumRe = regexp.MustCompile(`^[A-Za-z0-9]+$`)
)

type dialect interface {
	setPassword(ctx context.Context, admin, user, host, password string) error
	login(ctx context.Context, admin, user, password string) error
}

type sqlPlugin struct{ dialect dialect }

func (p sqlPlugin) Validate(params map[string]string) error {
	if err := policy.ValidPath(params["admin"]); err != nil {
		return errors.New("rotation: admin must be the kv path of the admin connection string")
	}
	users := strings.Split(params["users"], ",")
	if len(users) > 2 {
		return errors.New("rotation: users must be one user or two alternating users")
	}
	for _, u := range users {
		if !userRe.MatchString(u) {
			return fmt.Errorf("rotation: invalid user name %q", u)
		}
	}
	allowed := []string{"admin", "users", "length"}
	if _, ok := p.dialect.(mysqlDialect); ok {
		allowed = append(allowed, "host")
		if h, ok := params["host"]; ok && !hostRe.MatchString(h) {
			return fmt.Errorf("rotation: invalid host %q", h)
		}
	}
	if _, err := length(params); err != nil {
		return err
	}
	return onlyParams(params, allowed...)
}

// Create picks the user not currently in use and a fresh password.
func (sqlPlugin) Create(_ context.Context, t Target) ([]byte, error) {
	users := strings.Split(t.Params["users"], ",")
	var cur credential
	_ = json.Unmarshal(t.Current, &cur) // no or unreadable current value: start with the first user
	next := users[0]
	for i, u := range users {
		if u == cur.Username {
			next = users[(i+1)%len(users)]
		}
	}
	n, _ := length(t.Params)
	return json.Marshal(credential{Username: next, Password: string(Alnum(n))})
}

func (p sqlPlugin) Set(ctx context.Context, t Target, pending []byte) error {
	c, admin, err := p.prepare(t, pending)
	if err != nil {
		return err
	}
	host := t.Params["host"]
	if host == "" {
		host = "%"
	}
	return Scrub(p.dialect.setPassword(ctx, admin, c.Username, host, c.Password), admin)
}

func (p sqlPlugin) Test(ctx context.Context, t Target, pending []byte) error {
	c, admin, err := p.prepare(t, pending)
	if err != nil {
		return err
	}
	return Scrub(p.dialect.login(ctx, admin, c.Username, c.Password), admin)
}

// Scrub removes a connection string, and the password in it, from a driver
// error before it is logged or stored (as last_error): some parse errors
// quote the whole string they were given.
func Scrub(err error, dsn string) error {
	if err == nil || dsn == "" {
		return err
	}
	msg := strings.ReplaceAll(err.Error(), dsn, "[admin connection string]")
	pw := ""
	if c, perr := pgx.ParseConfig(dsn); perr == nil {
		pw = c.Password
	} else if c, merr := mysql.ParseDSN(dsn); merr == nil {
		pw = c.Passwd
	}
	if len(pw) >= 4 { // shorter would redact unrelated text; such a password is the real problem
		msg = strings.ReplaceAll(msg, pw, "[password]")
	}
	if msg == err.Error() {
		return err
	}
	return errors.New(msg)
}

// prepare decodes and re-checks the pending credential (it gets embedded in
// SQL, so it must still look like what Create made) and loads the admin
// connection string.
func (sqlPlugin) prepare(t Target, pending []byte) (credential, string, error) {
	var c credential
	if err := json.Unmarshal(pending, &c); err != nil || !userRe.MatchString(c.Username) || !alnumRe.MatchString(c.Password) {
		return c, "", errors.New("pending value is not a credential this plugin created")
	}
	if !strings.Contains(","+t.Params["users"]+",", ","+c.Username+",") {
		return c, "", fmt.Errorf("user %q is not in the configured users", c.Username)
	}
	admin, err := t.Lookup(t.Params["admin"])
	if err != nil {
		return c, "", fmt.Errorf("admin credentials %s: %w", t.Params["admin"], err)
	}
	return c, string(admin), nil
}

// ---- PostgreSQL ----

type postgresDialect struct{}

// setPassword sends a SCRAM-SHA-256 verifier, not the password, so it can't
// leak through statement logging (what psql's \password does too).
func (postgresDialect) setPassword(ctx context.Context, admin, user, _, password string) error {
	conn, err := pgx.Connect(ctx, admin)
	if err != nil {
		return err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	verifier, err := SCRAMVerifier(password)
	if err != nil {
		return err
	}
	_, err = conn.Exec(ctx, "ALTER ROLE "+pgx.Identifier{user}.Sanitize()+" WITH PASSWORD '"+verifier+"'")
	return err
}

func (postgresDialect) login(ctx context.Context, admin, user, password string) error {
	cfg, err := pgx.ParseConfig(admin)
	if err != nil {
		return err
	}
	cfg.User, cfg.Password = user, password // fallbacks (e.g. sslmode=prefer's plaintext retry) share these
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	return conn.Ping(ctx)
}

// SCRAMVerifier builds the stored form of a SCRAM-SHA-256 password (RFC 7677):
// SCRAM-SHA-256$<iterations>:<salt>$<StoredKey>:<ServerKey>.
func SCRAMVerifier(password string) (string, error) {
	const iterations = 4096 // PostgreSQL's default
	salt := randomBytes(16)
	salted, err := pbkdf2.Key(sha256.New, password, salt, iterations, sha256.Size)
	if err != nil {
		return "", err
	}
	mac := func(key []byte, msg string) []byte {
		h := hmac.New(sha256.New, key)
		h.Write([]byte(msg))
		return h.Sum(nil)
	}
	stored := sha256.Sum256(mac(salted, "Client Key"))
	b64 := base64.StdEncoding.EncodeToString
	return fmt.Sprintf("SCRAM-SHA-256$%d:%s$%s:%s", iterations, b64(salt), b64(stored[:]), b64(mac(salted, "Server Key"))), nil
}

// ---- MySQL ----

type mysqlDialect struct{}

func (mysqlDialect) open(dsn string, override func(*mysql.Config)) (*sql.DB, error) {
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		return nil, err
	}
	if override != nil {
		override(cfg)
	}
	conn, err := mysql.NewConnector(cfg)
	if err != nil {
		return nil, err
	}
	return sql.OpenDB(conn), nil
}

// setPassword: MySQL masks IDENTIFIED BY values in its logs. user, host and
// password are regexp-checked, so quoting them is safe.
func (d mysqlDialect) setPassword(ctx context.Context, admin, user, host, password string) error {
	db, err := d.open(admin, nil)
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = db.ExecContext(ctx, fmt.Sprintf("ALTER USER '%s'@'%s' IDENTIFIED BY '%s'", user, host, password))
	return err
}

func (d mysqlDialect) login(ctx context.Context, admin, user, password string) error {
	db, err := d.open(admin, func(c *mysql.Config) { c.User, c.Passwd = user, password })
	if err != nil {
		return err
	}
	defer db.Close()
	return db.PingContext(ctx)
}
