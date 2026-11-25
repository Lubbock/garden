package auth

import (
	"errors"
	"time"
)

type PermissionType string

const (
	TypeMenu     PermissionType = "menu"
	TypeButton   PermissionType = "button"
	TypeApproval PermissionType = "approval"
)

func ValidPermissionType(t PermissionType) bool {
	switch t {
	case TypeMenu, TypeButton, TypeApproval:
		return true
	}
	return false
}

type Permission struct {
	ID        int64          `gorm:"column:id;primaryKey;autoIncrement"`
	Code      string         `gorm:"column:code"`
	Name      string         `gorm:"column:name"`
	Type      PermissionType `gorm:"column:type"`
	CreatedAt time.Time      `gorm:"column:created_at"`
	UpdatedAt time.Time      `gorm:"column:updated_at"`
}

func (Permission) TableName() string { return "permissions" }

type RolePermission struct {
	RoleID       string `gorm:"column:role_id;primaryKey"`
	PermissionID int64  `gorm:"column:permission_id;primaryKey"`
}

func (RolePermission) TableName() string { return "role_permissions" }

type DefaultPermission struct {
	PermissionID int64 `gorm:"column:permission_id;primaryKey"`
}

func (DefaultPermission) TableName() string { return "default_permissions" }

var (
	ErrNotFound      = errors.New("auth: permission not found")
	ErrDuplicateCode = errors.New("auth: permission code already exists")
	ErrInvalidType   = errors.New("auth: invalid permission type")
	ErrEmptyCode     = errors.New("auth: permission code is empty")
	ErrEmptyName     = errors.New("auth: permission name is empty")
	ErrEmptyRoleID   = errors.New("auth: role id is empty")
)
