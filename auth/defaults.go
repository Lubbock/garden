package auth

import "gorm.io/gorm/clause"

func (s *Service) AddDefaultPermission(permissionID int64) error {
	if _, err := s.GetPermission(permissionID); err != nil {
		return err
	}
	return s.db.Clauses(clause.OnConflict{DoNothing: true}).
		Create(&DefaultPermission{PermissionID: permissionID}).Error
}

func (s *Service) RemoveDefaultPermission(permissionID int64) error {
	res := s.db.Delete(&DefaultPermission{}, "permission_id = ?", permissionID)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Service) ListDefaultPermissions() ([]Permission, error) {
	var out []Permission
	err := s.db.Model(&Permission{}).
		Where("id IN (SELECT permission_id FROM default_permissions)").
		Order("id").Find(&out).Error
	return out, err
}
