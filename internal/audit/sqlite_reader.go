package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

const (
	sqliteQueryTimeout     = 10 * time.Second
	maxSQLiteDatabaseBytes = 1 << 30
	maxSQLiteRows          = 10_000
	maxSQLiteColumns       = 64
	maxSQLiteCellBytes     = 1 << 20
	maxSQLiteResultBytes   = 8 << 20
)

// querySQLite opens panel databases in SQLite read-only mode. The driver is
// statically linked into the single VPS Scope binary, so audited hosts do not
// need the sqlite3 command. Queries are fixed by the program and select only
// non-secret metadata.
func querySQLite(database, query string) ([][]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), sqliteQueryTimeout)
	defer cancel()
	return querySQLiteContext(ctx, database, query)
}

func querySQLiteContext(ctx context.Context, database, query string) ([][]string, error) {
	abs, err := filepath.Abs(database)
	if err != nil {
		return nil, err
	}
	file, err := openRegularReadOnly(abs)
	if err != nil {
		return nil, fmt.Errorf("open SQLite database: %w", err)
	}
	info, statErr := file.Stat()
	closeErr := file.Close()
	if statErr != nil {
		return nil, fmt.Errorf("inspect SQLite database: %w", statErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close SQLite database preflight: %w", closeErr)
	}
	if info.Size() < 0 || info.Size() > maxSQLiteDatabaseBytes {
		return nil, fmt.Errorf("SQLite database exceeds the %d byte safety limit", maxSQLiteDatabaseBytes)
	}
	dsn := "file:" + filepath.ToSlash(abs) + "?mode=ro&_pragma=" + url.QueryEscape("busy_timeout=5000")
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open SQLite read-only: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
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
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, errors.New("SQLite metadata query deadline exceeded")
		}
		return nil, err
	}
	return out, nil
}
