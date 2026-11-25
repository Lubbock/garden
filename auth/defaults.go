package auth

import (
	"context"
)

func (s *Service) AddDefaultPermission(ctx context.Context, permissionID int64) error {
	if _, err := s.GetPermission(ctx, permissionID); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO default_permissions (permission_id) VALUES (?)`, permissionID)
	return err
}

func (s *Service) RemoveDefaultPermission(ctx context.Context, permissionID int64) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM default_permissions WHERE permission_id = ?`, permissionID)
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

func (s *Service) ListDefaultPermissions(ctx context.Context) ([]Permission, error) {
	return s.listPermissions(ctx,
		`SELECT `+permCols+` FROM permissions p
		  WHERE p.id IN (SELECT permission_id FROM default_permissions)
		  ORDER BY p.id`)
}
