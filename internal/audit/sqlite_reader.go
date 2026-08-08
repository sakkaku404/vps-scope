package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

const (
	sqliteQueryTimeout     = 10 * time.Second
	sqliteSessionTimeout   = 20 * time.Second
	maxSQLiteDatabaseBytes = 1 << 30
	maxSQLiteRows          = 10_000
	maxSQLiteColumns       = 64
	maxSQLiteCellBytes     = 1 << 20
	maxSQLiteResultBytes   = 8 << 20
)

type sqliteSession struct {
	ctx    context.Context
	cancel context.CancelFunc
	file   *os.File
	anchor *os.File
	db     *sql.DB
	tx     *sql.Tx
}

// querySQLite opens panel databases in SQLite read-only mode. The driver is
// statically linked into the single VPS Scope binary, so audited hosts do not
// need the sqlite3 command. Queries are fixed by the program and select only
// non-secret metadata.
func querySQLite(database, query string) ([][]string, error) {
	return querySQLiteContext(context.Background(), database, query)
}

func querySQLiteContext(ctx context.Context, database, query string) ([][]string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	queryCtx, cancel := context.WithTimeout(ctx, sqliteQueryTimeout)
	defer cancel()
	session, err := openSQLiteSessionContext(queryCtx, database)
	if err != nil {
		return nil, err
	}
	defer session.Close()
	return session.Query(query)
}

func openSQLiteSession(database string) (*sqliteSession, error) {
	return openSQLiteSessionForAudit(context.Background(), database)
}

func openSQLiteSessionForAudit(parent context.Context, database string) (*sqliteSession, error) {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, sqliteSessionTimeout)
	session, err := openSQLiteSessionContext(ctx, database)
	if err != nil {
		cancel()
		return nil, err
	}
	session.cancel = cancel
	return session, nil
}

func openSQLiteSessionContext(ctx context.Context, database string) (*sqliteSession, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	abs, err := filepath.Abs(database)
	if err != nil {
		return nil, err
	}
	file, err := openRegularReadOnly(abs)
	if err != nil {
		return nil, fmt.Errorf("open SQLite database: %w", err)
	}
	info, statErr := file.Stat()
	if statErr != nil {
		_ = file.Close()
		return nil, fmt.Errorf("inspect SQLite database: %w", statErr)
	}
	if info.Size() < 0 || info.Size() > maxSQLiteDatabaseBytes {
		_ = file.Close()
		return nil, fmt.Errorf("SQLite database exceeds the %d byte safety limit", maxSQLiteDatabaseBytes)
	}
	openPath, anchor, err := sqliteOpenPath(file, abs)
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("anchor SQLite database path: %w", err)
	}
	dsn := sqlitePathDSN(openPath) + "&_pragma=" + url.QueryEscape("busy_timeout=5000") + "&_pragma=" + url.QueryEscape("query_only=1")
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		if anchor != nil {
			_ = anchor.Close()
		}
		_ = file.Close()
		return nil, fmt.Errorf("open SQLite read-only: %w", err)
	}
	db.SetMaxOpenConns(1)
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		_ = db.Close()
		if anchor != nil {
			_ = anchor.Close()
		}
		_ = file.Close()
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, errors.New("SQLite metadata session deadline exceeded")
		}
		return nil, fmt.Errorf("begin SQLite read-only snapshot: %w", err)
	}
	return &sqliteSession{ctx: ctx, file: file, anchor: anchor, db: db, tx: tx}, nil
}

func (s *sqliteSession) Close() {
	if s == nil {
		return
	}
	if s.tx != nil {
		_ = s.tx.Rollback()
	}
	if s.db != nil {
		_ = s.db.Close()
	}
	if s.file != nil {
		_ = s.file.Close()
	}
	if s.anchor != nil {
		_ = s.anchor.Close()
	}
	if s.cancel != nil {
		s.cancel()
	}
}

func (s *sqliteSession) Query(query string) ([][]string, error) {
	rows, err := s.tx.QueryContext(s.ctx, query)
	if err != nil {
		if errors.Is(s.ctx.Err(), context.DeadlineExceeded) {
			return nil, errors.New("SQLite metadata query deadline exceeded")
		}
		return nil, fmt.Errorf("query SQLite metadata: %w", err)
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	if len(columns) == 0 || len(columns) > maxSQLiteColumns {
		return nil, fmt.Errorf("SQLite metadata query returned %d columns; safety limit is %d", len(columns), maxSQLiteColumns)
	}
	var out [][]string
	totalBytes := 0
	for rows.Next() {
		if len(out) >= maxSQLiteRows {
			return nil, fmt.Errorf("SQLite metadata query exceeded the %d row safety limit", maxSQLiteRows)
		}
		values := make([]sql.RawBytes, len(columns))
		dest := make([]any, len(columns))
		for i := range values {
			dest[i] = &values[i]
		}
		if err := rows.Scan(dest...); err != nil {
			return nil, fmt.Errorf("scan SQLite metadata: %w", err)
		}
		row := make([]string, len(columns))
		for i, value := range values {
			if len(value) > maxSQLiteCellBytes {
				return nil, fmt.Errorf("SQLite metadata cell exceeds the %d byte safety limit", maxSQLiteCellBytes)
			}
			if len(value) > maxSQLiteResultBytes-totalBytes {
				return nil, fmt.Errorf("SQLite metadata result exceeds the %d byte safety limit", maxSQLiteResultBytes)
			}
			totalBytes += len(value)
			row[i] = string(value)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		if errors.Is(s.ctx.Err(), context.DeadlineExceeded) {
			return nil, errors.New("SQLite metadata query deadline exceeded")
		}
		return nil, err
	}
	return out, nil
}

func sqlitePathDSN(path string) string {
	return "file:" + filepath.ToSlash(path) + "?mode=ro"
}
