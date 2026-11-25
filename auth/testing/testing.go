package testing

import (
	"testing"

	"github.com/Lubbock/garden/auth"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func OpenGORM(t testing.TB) *gorm.DB {
	t.Helper()
	db, err := auth.Open(sqlite.Open(":memory:"), auth.PoolConfig{MaxOpenConns: 1})
	if err != nil {
		t.Fatalf("open gorm: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("underlying db: %v", err)
	}
	t.Cleanup(func() { sqlDB.Close() })
	if err := db.Exec(`PRAGMA foreign_keys = ON`).Error; err != nil {
		t.Fatalf("pragma: %v", err)
	}
	return db
}

func NewService(t testing.TB) *auth.Service {
	t.Helper()
	svc := auth.NewService(OpenGORM(t))
	if err := svc.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return svc
}
