package testing

import (
	"context"
	"database/sql"
	"testing"

	"github.com/Lubbock/garden/auth"
	_ "modernc.org/sqlite"
)

func OpenMemDB(t testing.TB) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if _, err := db.Exec(`PRAGMA foreign_keys = ON`); err != nil {
		db.Close()
		t.Fatalf("pragma: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func NewService(t testing.TB) *auth.Service {
	t.Helper()
	svc := auth.NewService(OpenMemDB(t))
	if err := svc.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return svc
}
