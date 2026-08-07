package audit

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func newSQLiteFixture(t *testing.T) (string, *sql.DB) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "panel.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return path, db
}

func TestQuerySQLiteBoundsRows(t *testing.T) {
	path, db := newSQLiteFixture(t)
	if _, err := db.Exec(`CREATE TABLE metadata (value INTEGER);`); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := tx.Prepare(`INSERT INTO metadata(value) VALUES (?);`)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i <= maxSQLiteRows; i++ {
		if _, err := stmt.Exec(i); err != nil {
			t.Fatal(err)
		}
	}
	if err := stmt.Close(); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := querySQLite(path, `SELECT value FROM metadata;`); err == nil || !strings.Contains(err.Error(), "row safety limit") {
		t.Fatalf("querySQLite error=%v", err)
	}
}

func TestQuerySQLiteBoundsCellAndColumnCounts(t *testing.T) {
	path, db := newSQLiteFixture(t)
	if _, err := db.Exec(`CREATE TABLE metadata (value TEXT);`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO metadata(value) VALUES (?);`, strings.Repeat("x", maxSQLiteCellBytes+1)); err != nil {
		t.Fatal(err)
	}
	if _, err := querySQLite(path, `SELECT value FROM metadata;`); err == nil || !strings.Contains(err.Error(), "cell exceeds") {
		t.Fatalf("oversized cell error=%v", err)
	}
	columns := make([]string, maxSQLiteColumns+1)
	for i := range columns {
		columns[i] = strconv.Itoa(i)
	}
	if _, err := querySQLite(path, `SELECT `+strings.Join(columns, ",")+`;`); err == nil || !strings.Contains(err.Error(), "columns") {
		t.Fatalf("oversized column set error=%v", err)
	}
}

func TestQuerySQLiteBoundsTotalResult(t *testing.T) {
	path, db := newSQLiteFixture(t)
	if _, err := db.Exec(`CREATE TABLE metadata (value TEXT);`); err != nil {
		t.Fatal(err)
	}
	value := strings.Repeat("x", maxSQLiteCellBytes)
	for i := 0; i < maxSQLiteResultBytes/maxSQLiteCellBytes+1; i++ {
		if _, err := db.Exec(`INSERT INTO metadata(value) VALUES (?);`, value); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := querySQLite(path, `SELECT value FROM metadata;`); err == nil || !strings.Contains(err.Error(), "result exceeds") {
		t.Fatalf("oversized result error=%v", err)
	}
}

func TestQuerySQLiteBoundsDatabaseSizeBeforeParsing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversized.db")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, maxSQLiteDatabaseBytes+1); err != nil {
		t.Fatal(err)
	}
	if _, err := querySQLite(path, `SELECT 1;`); err == nil || !strings.Contains(err.Error(), "database exceeds") {
		t.Fatalf("oversized database error=%v", err)
	}
}

func TestQuerySQLiteDeadlineIsReportedExplicitly(t *testing.T) {
	path, db := newSQLiteFixture(t)
	if _, err := db.Exec(`CREATE TABLE metadata (value TEXT);`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer cancel()
	if _, err := querySQLiteContext(ctx, path, `SELECT value FROM metadata;`); err == nil || !strings.Contains(err.Error(), "deadline exceeded") {
		t.Fatalf("expired query context error=%v", err)
	}
}

func TestSQLiteSessionReadsWALAndKeepsOneSnapshot(t *testing.T) {
	path, writer := newSQLiteFixture(t)
	if _, err := writer.Exec(`PRAGMA journal_mode=WAL;`); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Exec(`PRAGMA wal_autocheckpoint=0; CREATE TABLE metadata (value INTEGER); INSERT INTO metadata VALUES (1);`); err != nil {
		t.Fatal(err)
	}
	session, err := openSQLiteSession(path)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	rows, err := session.Query(`SELECT count(*) FROM metadata;`)
	if err != nil || len(rows) != 1 || rows[0][0] != "1" {
		t.Fatalf("initial WAL snapshot rows=%v err=%v", rows, err)
	}
	if _, err := writer.Exec(`INSERT INTO metadata VALUES (2);`); err != nil {
		t.Fatal(err)
	}
	rows, err = session.Query(`SELECT count(*) FROM metadata;`)
	if err != nil || len(rows) != 1 || rows[0][0] != "1" {
		t.Fatalf("repeat snapshot rows=%v err=%v, want stable count 1", rows, err)
	}
}

func TestSQLiteSessionRejectsWrites(t *testing.T) {
	path, db := newSQLiteFixture(t)
	if _, err := db.Exec(`CREATE TABLE metadata (value INTEGER);`); err != nil {
		t.Fatal(err)
	}
	session, err := openSQLiteSession(path)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if _, err := session.Query(`INSERT INTO metadata VALUES (1) RETURNING value;`); err == nil {
		t.Fatal("read-only SQLite session accepted a write")
	}
}
