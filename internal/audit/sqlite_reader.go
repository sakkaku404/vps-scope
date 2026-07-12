package audit

import (
	"database/sql"
	"fmt"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// querySQLite opens panel databases in SQLite read-only mode. The driver is
// statically linked into the single VPS Scope binary, so audited hosts do not
// need the sqlite3 command. Queries are fixed by the program and select only
// non-secret metadata.
func querySQLite(database, query string) ([][]string, error) {
	abs, err := filepath.Abs(database)
	if err != nil {
		return nil, err
	}
	dsn := "file:" + filepath.ToSlash(abs) + "?mode=ro"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open SQLite read-only: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("query SQLite metadata: %w", err)
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	var out [][]string
	for rows.Next() {
		values := make([]sql.NullString, len(columns))
		dest := make([]any, len(columns))
		for i := range values {
			dest[i] = &values[i]
		}
		if err := rows.Scan(dest...); err != nil {
			return nil, fmt.Errorf("scan SQLite metadata: %w", err)
		}
		row := make([]string, len(columns))
		for i, value := range values {
			if value.Valid {
				row[i] = value.String
			}
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
