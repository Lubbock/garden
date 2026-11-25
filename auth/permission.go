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
	ID        int64
	Code      string
	Name      string
	Type      PermissionType
	CreatedAt time.Time
	UpdatedAt time.Time
}

var (
	ErrNotFound      = errors.New("auth: permission not found")
	ErrDuplicateCode = errors.New("auth: permission code already exists")
	ErrInvalidType   = errors.New("auth: invalid permission type")
	ErrEmptyCode     = errors.New("auth: permission code is empty")
	ErrEmptyName     = errors.New("auth: permission name is empty")
	ErrEmptyRoleID   = errors.New("auth: role id is empty")
)
