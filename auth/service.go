package auth

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

type Service struct {
	db *sql.DB
}

func NewService(db *sql.DB) *Service {
	return &Service{db: db}
}

const schema = `
CREATE TABLE IF NOT EXISTS permissions (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	code       TEXT NOT NULL UNIQUE,
	name       TEXT NOT NULL,
	type       TEXT NOT NULL CHECK (type IN ('menu','button','approval')),
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS role_permissions (
	role_id       TEXT NOT NULL,
	permission_id INTEGER NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
	PRIMARY KEY (role_id, permission_id)
);
CREATE INDEX IF NOT EXISTS idx_role_permissions_role ON role_permissions(role_id);
CREATE TABLE IF NOT EXISTS default_permissions (
	permission_id INTEGER PRIMARY KEY REFERENCES permissions(id) ON DELETE CASCADE
);
`

func (s *Service) Migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, schema)
	return err
}

func (s *Service) CreatePermission(ctx context.Context, p *Permission) error {
	if p.Code == "" {
		return ErrEmptyCode
	}
	if p.Name == "" {
		return ErrEmptyName
	}
	if !ValidPermissionType(p.Type) {
		return ErrInvalidType
	}
	now := time.Now().UTC()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}
	if p.UpdatedAt.IsZero() {
		p.UpdatedAt = now
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO permissions (code, name, type, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		p.Code, p.Name, string(p.Type), formatTime(p.CreatedAt), formatTime(p.UpdatedAt))
	if err != nil {
		if isUniqueErr(err) {
			return ErrDuplicateCode
		}
		return err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	p.ID = id
	p.CreatedAt = p.CreatedAt.UTC()
	p.UpdatedAt = p.UpdatedAt.UTC()
	return nil
}

func (s *Service) UpdatePermission(ctx context.Context, p Permission) error {
	if p.Code == "" {
		return ErrEmptyCode
	}
	if p.Name == "" {
		return ErrEmptyName
	}
	if !ValidPermissionType(p.Type) {
		return ErrInvalidType
	}
	if p.UpdatedAt.IsZero() {
		p.UpdatedAt = time.Now().UTC()
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE permissions SET code = ?, name = ?, type = ?, updated_at = ? WHERE id = ?`,
		p.Code, p.Name, string(p.Type), formatTime(p.UpdatedAt), p.ID)
	if err != nil {
		if isUniqueErr(err) {
			return ErrDuplicateCode
		}
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Service) DeletePermission(ctx context.Context, id int64) error {
	return s.BatchDeletePermissions(ctx, []int64{id})
}

func (s *Service) BatchDeletePermissions(ctx context.Context, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	ph := placeholders(len(ids))
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM role_permissions WHERE permission_id IN (`+ph+`)`, args...); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM default_permissions WHERE permission_id IN (`+ph+`)`, args...); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM permissions WHERE id IN (`+ph+`)`, args...); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Service) GetPermission(ctx context.Context, id int64) (Permission, error) {
	return s.queryPermission(ctx, `SELECT `+permCols+` FROM permissions WHERE id = ?`, id)
}

func (s *Service) GetPermissionByCode(ctx context.Context, code string) (Permission, error) {
	return s.queryPermission(ctx, `SELECT `+permCols+` FROM permissions WHERE code = ?`, code)
}

func (s *Service) ListPermissions(ctx context.Context) ([]Permission, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+permCols+` FROM permissions ORDER BY id`)
	if err != nil {
		return nil, err
	}
	return scanPermissions(rows)
}

const permCols = `id, code, name, type, created_at, updated_at`

func (s *Service) queryPermission(ctx context.Context, q string, args ...any) (Permission, error) {
	row := s.db.QueryRowContext(ctx, q, args...)
	var p Permission
	var t, ct, ut string
	err := row.Scan(&p.ID, &p.Code, &p.Name, &t, &ct, &ut)
	if errors.Is(err, sql.ErrNoRows) {
		return Permission{}, ErrNotFound
	}
	if err != nil {
		return Permission{}, err
	}
	p.Type = PermissionType(t)
	if p.CreatedAt, err = parseTime(ct); err != nil {
		return Permission{}, err
	}
	if p.UpdatedAt, err = parseTime(ut); err != nil {
		return Permission{}, err
	}
	return p, nil
}

func scanPermissions(rows *sql.Rows) ([]Permission, error) {
	defer rows.Close()
	var out []Permission
	for rows.Next() {
		var p Permission
		var t, ct, ut string
		if err := rows.Scan(&p.ID, &p.Code, &p.Name, &t, &ct, &ut); err != nil {
			return nil, err
		}
		p.Type = PermissionType(t)
		var err error
		if p.CreatedAt, err = parseTime(ct); err != nil {
			return nil, err
		}
		if p.UpdatedAt, err = parseTime(ut); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func placeholders(n int) string {
	b := make([]byte, 0, n*2-1)
	for i := 0; i < n; i++ {
		if i > 0 {
			b = append(b, ',', ' ')
		}
		b = append(b, '?')
	}
	return string(b)
}

func isUniqueErr(err error) bool {
	return strings.Contains(err.Error(), "UNIQUE constraint failed")
}

func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

func parseTime(s string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, s)
}
