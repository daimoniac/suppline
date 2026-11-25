package errors

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// A PostgreSQL switchover or restart cuts connections mid-query. Those
// errors must be retried, not treated as a permanent failure that drops a
// finished scan.
func TestDatabaseConnectionLossIsTransient(t *testing.T) {
	pg := func(code string) error { return fmt.Errorf("record scan: %w", &pgconn.PgError{Code: code}) }
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"connection failure (08006)", pg("08006"), true},
		{"admin shutdown (57P01)", pg("57P01"), true},
		{"crash shutdown (57P02)", pg("57P02"), true},
		{"cannot connect now (57P03)", pg("57P03"), true},
		{"write to a demoted primary (25006)", pg("25006"), true},
		{"serialization failure (40001)", pg("40001"), true},
		{"deadlock (40P01)", pg("40P01"), true},
		{"unique violation (23505)", pg("23505"), false},
		{"syntax error (42601)", pg("42601"), false},
		{"connect error", fmt.Errorf("query: %w", &pgconn.ConnectError{}), true},
		{"bad connection", fmt.Errorf("query: %w", driver.ErrBadConn), true},
		{"connection done", fmt.Errorf("query: %w", sql.ErrConnDone), true},
		{"unexpected EOF", fmt.Errorf("read: %w", io.ErrUnexpectedEOF), true},
		{"network error", fmt.Errorf("query: %w", &net.OpError{Op: "read", Err: errors.New("connection reset by peer")}), true},
		{"plain error", errors.New("something else"), false},
		{"explicit permanent wins", NewPermanent(pg("57P01")), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsTransient(tc.err); got != tc.want {
				t.Fatalf("IsTransient(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
