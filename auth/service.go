package auth

import (
	_ "embed"
	"errors"
	"strings"

	"gorm.io/gorm"
)

//go:embed schema.sql
var schemaSQL string

type Service struct {
	db *gorm.DB
}

func NewService(db *gorm.DB) *Service {
	return &Service{db: db}
}

func (s *Service) Migrate() error {
	return s.db.Exec(schemaSQL).Error
}

func (s *Service) CreatePermission(p *Permission) error {
	if p.Code == "" {
		return ErrEmptyCode
	}
	if p.Name == "" {
		return ErrEmptyName
	}
	if !ValidPermissionType(p.Type) {
		return ErrInvalidType
	}
	err := s.db.Create(p).Error
	if isDuplicateErr(err) {
		return ErrDuplicateCode
	}
	return err
}

func (s *Service) UpdatePermission(p Permission) error {
	if p.Code == "" {
		return ErrEmptyCode
	}
	if p.Name == "" {
		return ErrEmptyName
	}
	if !ValidPermissionType(p.Type) {
		return ErrInvalidType
	}
	res := s.db.Model(&Permission{}).Where("id = ?", p.ID).
		Updates(map[string]any{"code": p.Code, "name": p.Name, "type": string(p.Type)})
	if isDuplicateErr(res.Error) {
		return ErrDuplicateCode
	}
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Service) DeletePermission(id int64) error {
	return s.BatchDeletePermissions([]int64{id})
}

func (s *Service) BatchDeletePermissions(ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("permission_id IN ?", ids).Delete(&RolePermission{}).Error; err != nil {
			return err
		}
		if err := tx.Where("permission_id IN ?", ids).Delete(&DefaultPermission{}).Error; err != nil {
			return err
		}
		return tx.Where("id IN ?", ids).Delete(&Permission{}).Error
	})
}

func (s *Service) GetPermission(id int64) (Permission, error) {
	var p Permission
	err := s.db.First(&p, "id = ?", id).Error
	return p, mapNotFound(err)
}

func (s *Service) GetPermissionByCode(code string) (Permission, error) {
	var p Permission
	err := s.db.First(&p, "code = ?", code).Error
	return p, mapNotFound(err)
}

func (s *Service) ListPermissions() ([]Permission, error) {
	var out []Permission
	err := s.db.Order("id").Find(&out).Error
	return out, err
}

func mapNotFound(err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrNotFound
	}
	return err
}

func isDuplicateErr(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, gorm.ErrDuplicatedKey) ||
		strings.Contains(err.Error(), "UNIQUE constraint failed")
}
