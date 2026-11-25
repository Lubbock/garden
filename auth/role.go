package auth

import (
	"context"
	"database/sql"
	"errors"
)

func (s *Service) AssignRolePermission(ctx context.Context, roleID string, permissionID int64) error {
	if roleID == "" {
		return ErrEmptyRoleID
	}
	if _, err := s.GetPermission(ctx, permissionID); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)`,
		roleID, permissionID)
	return err
}

func (s *Service) UnassignRolePermission(ctx context.Context, roleID string, permissionID int64) error {
	if roleID == "" {
		return ErrEmptyRoleID
	}
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM role_permissions WHERE role_id = ? AND permission_id = ?`,
		roleID, permissionID)
	if err != nil {
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

func (s *Service) ListRolePermissions(ctx context.Context, roleID string) ([]Permission, error) {
	if roleID == "" {
		return nil, ErrEmptyRoleID
	}
	return s.listPermissions(ctx,
		`SELECT `+permCols+` FROM permissions p
		  WHERE p.id IN (SELECT permission_id FROM default_permissions)
		     OR EXISTS (SELECT 1 FROM role_permissions rp WHERE rp.permission_id = p.id AND rp.role_id = ?)
		  ORDER BY p.id`, roleID)
}

func (s *Service) ListRolePermissionsByType(ctx context.Context, roleID string, t PermissionType) ([]Permission, error) {
	if roleID == "" {
		return nil, ErrEmptyRoleID
	}
	if !ValidPermissionType(t) {
		return nil, ErrInvalidType
	}
	return s.listPermissions(ctx,
		`SELECT `+permCols+` FROM permissions p
		  WHERE p.type = ?
		    AND (p.id IN (SELECT permission_id FROM default_permissions)
		     OR EXISTS (SELECT 1 FROM role_permissions rp WHERE rp.permission_id = p.id AND rp.role_id = ?))
		  ORDER BY p.id`, string(t), roleID)
}

func (s *Service) ListPermissionsByRoles(ctx context.Context, roleIDs []string) ([]Permission, error) {
	if len(roleIDs) == 0 {
		return nil, ErrEmptyRoleID
	}
	args := make([]any, 0, len(roleIDs)+1)
	in := placeholders(len(roleIDs))
	for _, id := range roleIDs {
		if id == "" {
			return nil, ErrEmptyRoleID
		}
		args = append(args, id)
	}
	q := `SELECT ` + permCols + ` FROM permissions p
	      WHERE p.id IN (SELECT permission_id FROM default_permissions)
	         OR EXISTS (SELECT 1 FROM role_permissions rp WHERE rp.permission_id = p.id AND rp.role_id IN (` + in + `))
	      ORDER BY p.id`
	return s.listPermissions(ctx, q, args...)
}

func (s *Service) HasPermission(ctx context.Context, roleID, code string) (bool, error) {
	return s.HasPermissionInRoles(ctx, []string{roleID}, code)
}

func (s *Service) HasPermissionInRoles(ctx context.Context, roleIDs []string, code string) (bool, error) {
	if len(roleIDs) == 0 {
		return false, ErrEmptyRoleID
	}
	ids := make([]any, 0, len(roleIDs)+2)
	for _, id := range roleIDs {
		if id == "" {
			return false, ErrEmptyRoleID
		}
		ids = append(ids, id)
	}
	in := placeholders(len(roleIDs))
	var one int
	q := `SELECT 1 FROM permissions p
	      WHERE p.code = ?
	        AND (p.id IN (SELECT permission_id FROM default_permissions)
	         OR EXISTS (SELECT 1 FROM role_permissions rp WHERE rp.permission_id = p.id AND rp.role_id IN (` + in + `)))
	      LIMIT 1`
	args := append([]any{code}, ids...)
	err := s.db.QueryRowContext(ctx, q, args...).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		exists, err2 := s.permissionCodeExists(ctx, code)
		if err2 != nil {
			return false, err2
		}
		if !exists {
			return false, ErrNotFound
		}
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *Service) permissionCodeExists(ctx context.Context, code string) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM permissions WHERE code = ? LIMIT 1`, code).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *Service) listPermissions(ctx context.Context, q string, args ...any) ([]Permission, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	return scanPermissions(rows)
}
