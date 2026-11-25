package auth

import (
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func (s *Service) AssignRolePermission(roleID string, permissionID int64) error {
	if roleID == "" {
		return ErrEmptyRoleID
	}
	if _, err := s.GetPermission(permissionID); err != nil {
		return err
	}
	return s.db.Clauses(clause.OnConflict{DoNothing: true}).
		Create(&RolePermission{RoleID: roleID, PermissionID: permissionID}).Error
}

func (s *Service) UnassignRolePermission(roleID string, permissionID int64) error {
	if roleID == "" {
		return ErrEmptyRoleID
	}
	res := s.db.Where("role_id = ? AND permission_id = ?", roleID, permissionID).
		Delete(&RolePermission{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Service) ListRolePermissions(roleID string) ([]Permission, error) {
	if roleID == "" {
		return nil, ErrEmptyRoleID
	}
	return s.findGranted([]string{roleID}, "")
}

func (s *Service) ListRolePermissionsByType(roleID string, t PermissionType) ([]Permission, error) {
	if roleID == "" {
		return nil, ErrEmptyRoleID
	}
	if !ValidPermissionType(t) {
		return nil, ErrInvalidType
	}
	return s.findGranted([]string{roleID}, string(t))
}

func (s *Service) ListPermissionsByRoles(roleIDs []string) ([]Permission, error) {
	if len(roleIDs) == 0 {
		return nil, ErrEmptyRoleID
	}
	for _, id := range roleIDs {
		if id == "" {
			return nil, ErrEmptyRoleID
		}
	}
	return s.findGranted(roleIDs, "")
}

func (s *Service) HasPermission(roleID, code string) (bool, error) {
	return s.HasPermissionInRoles([]string{roleID}, code)
}

func (s *Service) HasPermissionInRoles(roleIDs []string, code string) (bool, error) {
	if len(roleIDs) == 0 {
		return false, ErrEmptyRoleID
	}
	for _, id := range roleIDs {
		if id == "" {
			return false, ErrEmptyRoleID
		}
	}
	var count int64
	err := s.db.Model(&Permission{}).Where("code = ?", code).
		Where(s.grantedCond(roleIDs)).Count(&count).Error
	if err != nil {
		return false, err
	}
	if count > 0 {
		return true, nil
	}
	var total int64
	if err := s.db.Model(&Permission{}).Where("code = ?", code).Count(&total).Error; err != nil {
		return false, err
	}
	if total == 0 {
		return false, ErrNotFound
	}
	return false, nil
}

func (s *Service) grantedCond(roleIDs []string) *gorm.DB {
	cond := s.db.Where("id IN (SELECT permission_id FROM default_permissions)")
	if len(roleIDs) == 1 {
		return cond.Or("id IN (SELECT permission_id FROM role_permissions WHERE role_id = ?)", roleIDs[0])
	}
	return cond.Or("id IN (SELECT permission_id FROM role_permissions WHERE role_id IN ?)", roleIDs)
}

func (s *Service) findGranted(roleIDs []string, typ string) ([]Permission, error) {
	var out []Permission
	q := s.db.Model(&Permission{}).Where(s.grantedCond(roleIDs))
	if typ != "" {
		q = q.Where("type = ?", typ)
	}
	err := q.Order("id").Find(&out).Error
	return out, err
}
