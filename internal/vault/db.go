package vault

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"strings"

	sqlite3 "github.com/mutecomm/go-sqlcipher/v4"
)

// ErrWrongKey is returned when a database file exists but cannot be read with
// the key supplied.
var ErrWrongKey = errors.New("vault: database cannot be opened with this key")

// Options adjusts how OpenDB opens a database.
type Options struct {
	// ReadOnly opens the file without write access and never creates it.
	ReadOnly bool
	// Lazy skips the open-time check, so a file that does not exist yet is
	// tolerated; queries fail until it appears. Wrong-key and missing-cipher
	// errors then surface on first use instead of from OpenDB.
	Lazy bool
}

// OpenDB opens (creating if needed) the SQLCipher database at path under the
// subkey that key derives for name. The key reaches the driver through a
// connector that builds its connection string per connection, so it is never
// held by database/sql as a registered data source name.
func OpenDB(path string, key Key, name string, opts Options) (*sql.DB, error) {
	if key.IsZero() {
		return nil, errors.New("vault: refusing to open a database without a key")
	}
	c := &connector{
		path:     path,
		key:      key.DBKey(name),
		readOnly: opts.ReadOnly,
		drv:      &sqlite3.SQLiteDriver{},
	}
	db := sql.OpenDB(c)
	if opts.Lazy {
		return db, nil
	}
	if err := verify(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("open %s database: %w", name, c.scrub(err))
	}
	return db, nil
}

// verify proves the handle is a SQLCipher database readable with its key. A
// build without the cipher would silently write plaintext, so that is fatal.
func verify(db *sql.DB) error {
	var cipherVersion sql.NullString
	if err := db.QueryRow(`PRAGMA cipher_version`).Scan(&cipherVersion); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("vault: this build has no SQLCipher support; refusing to store data unencrypted")
		}
		return classify(err)
	}
	if cipherVersion.String == "" {
		return errors.New("vault: this build has no SQLCipher support; refusing to store data unencrypted")
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM sqlite_master`).Scan(&n); err != nil {
		return classify(err)
	}
	return nil
}

func classify(err error) error {
	var se sqlite3.Error
	if errors.As(err, &se) && se.Code == sqlite3.ErrNotADB {
		return ErrWrongKey
	}
	return err
}

type connector struct {
	path     string
	key      [32]byte
	readOnly bool
	drv      *sqlite3.SQLiteDriver
}

func (c *connector) Connect(context.Context) (driver.Conn, error) {
	conn, err := c.drv.Open(c.dsn())
	if err != nil {
		return nil, c.scrub(classify(err))
	}
	return conn, nil
}

func (c *connector) Driver() driver.Driver { return c.drv }

// dsn builds the driver connection string. The key pragma is applied by the
// driver before any other statement touches the file.
func (c *connector) dsn() string {
	var b strings.Builder
	b.WriteString("file:")
	b.WriteString(escapeURIPath(c.path))
	b.WriteString("?_pragma_key=x'")
	b.WriteString(hexString(c.key[:]))
	b.WriteString("'&_pragma_cipher_page_size=4096&_foreign_keys=on&_busy_timeout=5000")
	if c.readOnly {
		b.WriteString("&mode=ro")
	} else {
		b.WriteString("&_journal_mode=WAL")
	}
	return b.String()
}

// scrub guarantees an error never carries the key, whatever the driver put in it.
func (c *connector) scrub(err error) error {
	if err == nil {
		return nil
	}
	keyHex := hexString(c.key[:])
	msg := err.Error()
	if !strings.Contains(msg, keyHex) && !strings.Contains(msg, "_pragma_key") {
		return err
	}
	if errors.Is(err, ErrWrongKey) {
		return ErrWrongKey
	}
	return errors.New("vault: database error (details withheld: they contained key material)")
}

// escapeURIPath escapes the characters that would end the path part of an
// SQLite URI filename.
func escapeURIPath(p string) string {
	return strings.NewReplacer("%", "%25", "?", "%3f", "#", "%23").Replace(p)
}
