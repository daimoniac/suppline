package statestore

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
)

type dbDialect string

const (
	dialectSQLite   dbDialect = "sqlite"
	dialectPostgres dbDialect = "postgres"
)

func rewritePlaceholders(query string) string {
	var b strings.Builder
	b.Grow(len(query) + 8)
	n := 0
	for i := 0; i < len(query); i++ {
		if query[i] == '?' {
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
			continue
		}
		b.WriteByte(query[i])
	}
	return b.String()
}

func identitySQL(query string) string { return query }

// DB wraps database/sql and rewrites ? placeholders for Postgres.
type DB struct {
	*sql.DB
	rewrite func(string) string
	dialect dbDialect
}

func wrapDB(db *sql.DB, dialect dbDialect) *DB {
	rewrite := identitySQL
	if dialect == dialectPostgres {
		rewrite = rewritePlaceholders
	}
	return &DB{DB: db, rewrite: rewrite, dialect: dialect}
}

func (d *DB) Exec(query string, args ...any) (sql.Result, error) {
	return d.DB.Exec(d.rewrite(query), args...)
}

func (d *DB) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return d.DB.ExecContext(ctx, d.rewrite(query), args...)
}

func (d *DB) Query(query string, args ...any) (*sql.Rows, error) {
	return d.DB.Query(d.rewrite(query), args...)
}

func (d *DB) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return d.DB.QueryContext(ctx, d.rewrite(query), args...)
}

func (d *DB) QueryRow(query string, args ...any) *sql.Row {
	return d.DB.QueryRow(d.rewrite(query), args...)
}

func (d *DB) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return d.DB.QueryRowContext(ctx, d.rewrite(query), args...)
}

func (d *DB) PrepareContext(ctx context.Context, query string) (*sql.Stmt, error) {
	return d.DB.PrepareContext(ctx, d.rewrite(query))
}

func (d *DB) BeginTx(ctx context.Context, opts *sql.TxOptions) (*Tx, error) {
	tx, err := d.DB.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &Tx{Tx: tx, rewrite: d.rewrite}, nil
}

// Tx wraps sql.Tx with the same placeholder rewrite as DB.
type Tx struct {
	*sql.Tx
	rewrite func(string) string
}

func (t *Tx) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return t.Tx.ExecContext(ctx, t.rewrite(query), args...)
}

func (t *Tx) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return t.Tx.QueryContext(ctx, t.rewrite(query), args...)
}

func (t *Tx) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return t.Tx.QueryRowContext(ctx, t.rewrite(query), args...)
}

func (t *Tx) PrepareContext(ctx context.Context, query string) (*sql.Stmt, error) {
	return t.Tx.PrepareContext(ctx, t.rewrite(query))
}

func (s *SQLiteStore) boolTrue() string {
	if s.db != nil && s.db.dialect == dialectPostgres {
		return "TRUE"
	}
	return "1"
}

func (s *SQLiteStore) boolFalse() string {
	if s.db != nil && s.db.dialect == dialectPostgres {
		return "FALSE"
	}
	return "0"
}

func (s *SQLiteStore) insertReturningID(ctx context.Context, exec interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, query string, args ...any) (int64, error) {
	if s.db != nil && s.db.dialect == dialectPostgres {
		query = strings.TrimRight(query, " \t\n;") + " RETURNING id"
		var id int64
		if err := exec.QueryRowContext(ctx, query, args...).Scan(&id); err != nil {
			return 0, err
		}
		return id, nil
	}
	result, err := exec.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}
