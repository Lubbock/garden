package auth_test

import (
	"errors"
	"testing"

	"github.com/Lubbock/garden/auth"
	authtest "github.com/Lubbock/garden/auth/testing"
)

func newSvc(t *testing.T) *auth.Service {
	return authtest.NewService(t)
}

func mk(t *testing.T, svc *auth.Service, code, name string, typ auth.PermissionType) *auth.Permission {
	t.Helper()
	p := &auth.Permission{Code: code, Name: name, Type: typ}
	if err := svc.CreatePermission(p); err != nil {
		t.Fatalf("create %s: %v", code, err)
	}
	return p
}

func codes(ps []auth.Permission) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.Code
	}
	return out
}

func contains(codes []string, want string) bool {
	for _, c := range codes {
		if c == want {
			return true
		}
	}
	return false
}

func TestPoolConfig(t *testing.T) {
	db := authtest.OpenGORM(t)
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	if got := sqlDB.Stats().MaxOpenConnections; got != 1 {
		t.Fatalf("MaxOpenConnections = %d, want 1", got)
	}
}

func TestCreateGetUpdate(t *testing.T) {
	svc := newSvc(t)
	p := mk(t, svc, "menu:dashboard", "仪表盘", auth.TypeMenu)
	if p.ID <= 0 {
		t.Fatalf("id not set: %d", p.ID)
	}

	got, err := svc.GetPermission(p.ID)
	if err != nil {
		t.Fatalf("get by id: %v", err)
	}
	if got.Code != "menu:dashboard" || got.Name != "仪表盘" || got.Type != auth.TypeMenu {
		t.Fatalf("got = %+v", got)
	}
	if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
		t.Fatalf("timestamps not set: %+v", got)
	}

	byCode, err := svc.GetPermissionByCode("menu:dashboard")
	if err != nil {
		t.Fatalf("get by code: %v", err)
	}
	if byCode.ID != p.ID {
		t.Fatalf("byCode.ID = %d, want %d", byCode.ID, p.ID)
	}

	p.Name = "工作台"
	p.Type = auth.TypeButton
	if err := svc.UpdatePermission(*p); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, err = svc.GetPermission(p.ID)
	if err != nil {
		t.Fatalf("get after update: %v", err)
	}
	if got.Name != "工作台" || got.Type != auth.TypeButton {
		t.Fatalf("update not applied: %+v", got)
	}

	all, err := svc.ListPermissions()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("len(all) = %d, want 1", len(all))
	}
}

func TestCreateValidation(t *testing.T) {
	svc := newSvc(t)
	mk(t, svc, "btn:export", "导出", auth.TypeButton)

	cases := []struct {
		name string
		p    auth.Permission
		want error
	}{
		{"empty code", auth.Permission{Name: "x", Type: auth.TypeMenu}, auth.ErrEmptyCode},
		{"empty name", auth.Permission{Code: "x", Type: auth.TypeMenu}, auth.ErrEmptyName},
		{"invalid type", auth.Permission{Code: "x", Name: "x", Type: "api"}, auth.ErrInvalidType},
		{"duplicate code", auth.Permission{Code: "btn:export", Name: "y", Type: auth.TypeMenu}, auth.ErrDuplicateCode},
	}
	for _, tc := range cases {
		err := svc.CreatePermission(&tc.p)
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
	}
}

func TestUpdateNotFoundAndDuplicate(t *testing.T) {
	svc := newSvc(t)
	a := mk(t, svc, "menu:a", "A", auth.TypeMenu)
	mk(t, svc, "menu:b", "B", auth.TypeMenu)

	err := svc.UpdatePermission(auth.Permission{ID: 9999, Code: "menu:z", Name: "Z", Type: auth.TypeMenu})
	if !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	err = svc.UpdatePermission(auth.Permission{ID: a.ID, Code: "menu:b", Name: "A", Type: auth.TypeMenu})
	if !errors.Is(err, auth.ErrDuplicateCode) {
		t.Fatalf("err = %v, want ErrDuplicateCode", err)
	}
}

func TestDeleteAndBatchDelete(t *testing.T) {
	svc := newSvc(t)
	a := mk(t, svc, "menu:a", "A", auth.TypeMenu)
	b := mk(t, svc, "btn:b", "B", auth.TypeButton)
	c := mk(t, svc, "appr:c", "C", auth.TypeApproval)

	if err := svc.AssignRolePermission("r1", a.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.AddDefaultPermission(a.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.DeletePermission(a.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := svc.GetPermission(a.ID); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("get deleted: err = %v", err)
	}
	if _, err := svc.GetPermissionByCode("menu:a"); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("get deleted by code: err = %v", err)
	}
	roles, err := svc.ListRolePermissions("r1")
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) != 0 {
		t.Fatalf("role bindings not cleaned: %v", codes(roles))
	}
	defs, err := svc.ListDefaultPermissions()
	if err != nil {
		t.Fatal(err)
	}
	if len(defs) != 0 {
		t.Fatalf("default bindings not cleaned: %v", codes(defs))
	}

	if err := svc.BatchDeletePermissions([]int64{b.ID, c.ID}); err != nil {
		t.Fatalf("batch delete: %v", err)
	}
	all, _ := svc.ListPermissions()
	if len(all) != 0 {
		t.Fatalf("after batch: %v", codes(all))
	}
	if err := svc.BatchDeletePermissions(nil); err != nil {
		t.Fatalf("batch empty: %v", err)
	}
}

func TestAssignAndUnassign(t *testing.T) {
	svc := newSvc(t)
	p := mk(t, svc, "menu:a", "A", auth.TypeMenu)

	if err := svc.AssignRolePermission("", p.ID); !errors.Is(err, auth.ErrEmptyRoleID) {
		t.Fatalf("err = %v", err)
	}
	if err := svc.AssignRolePermission("r1", 9999); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("assign missing perm: err = %v", err)
	}
	if err := svc.AssignRolePermission("r1", p.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.AssignRolePermission("r1", p.ID); err != nil {
		t.Fatalf("idempotent assign: %v", err)
	}
	got, err := svc.ListRolePermissions("r1")
	if err != nil || len(got) != 1 {
		t.Fatalf("after assign: %v, %v", codes(got), err)
	}

	if err := svc.UnassignRolePermission("", p.ID); !errors.Is(err, auth.ErrEmptyRoleID) {
		t.Fatalf("err = %v", err)
	}
	if err := svc.UnassignRolePermission("r1", p.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.UnassignRolePermission("r1", p.ID); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("unassign twice: err = %v", err)
	}
}

func TestListRolePermissionsMergesDefaults(t *testing.T) {
	svc := newSvc(t)
	home := mk(t, svc, "menu:home", "首页", auth.TypeMenu)
	exp := mk(t, svc, "btn:export", "导出", auth.TypeButton)
	mk(t, svc, "approval:leave", "请假", auth.TypeApproval)

	if err := svc.AddDefaultPermission(home.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.AssignRolePermission("r1", exp.ID); err != nil {
		t.Fatal(err)
	}

	got, err := svc.ListRolePermissions("r1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !contains(codes(got), "menu:home") || !contains(codes(got), "btn:export") {
		t.Fatalf("got = %v", codes(got))
	}

	menus, err := svc.ListRolePermissionsByType("r1", auth.TypeMenu)
	if err != nil {
		t.Fatal(err)
	}
	if len(menus) != 1 || menus[0].Code != "menu:home" {
		t.Fatalf("menus = %v", codes(menus))
	}
	btns, err := svc.ListRolePermissionsByType("r1", auth.TypeButton)
	if err != nil {
		t.Fatal(err)
	}
	if len(btns) != 1 || btns[0].Code != "btn:export" {
		t.Fatalf("buttons = %v", codes(btns))
	}
	appr, err := svc.ListRolePermissionsByType("r1", auth.TypeApproval)
	if err != nil {
		t.Fatal(err)
	}
	if len(appr) != 0 {
		t.Fatalf("approvals = %v", codes(appr))
	}

	if _, err := svc.ListRolePermissions(""); !errors.Is(err, auth.ErrEmptyRoleID) {
		t.Fatalf("err = %v", err)
	}
	if _, err := svc.ListRolePermissionsByType("r1", "api"); !errors.Is(err, auth.ErrInvalidType) {
		t.Fatalf("err = %v", err)
	}
}

func TestListPermissionsByRoles(t *testing.T) {
	svc := newSvc(t)
	home := mk(t, svc, "menu:home", "首页", auth.TypeMenu)
	exp := mk(t, svc, "btn:export", "导出", auth.TypeButton)
	lv := mk(t, svc, "approval:leave", "请假", auth.TypeApproval)

	svc.AssignRolePermission("r1", home.ID)
	svc.AssignRolePermission("r1", exp.ID)
	svc.AssignRolePermission("r2", exp.ID)
	svc.AssignRolePermission("r2", lv.ID)

	got, err := svc.ListPermissionsByRoles([]string{"r1", "r2"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 dedup perms, got %v", codes(got))
	}
	only, err := svc.ListPermissionsByRoles([]string{"r1"})
	if err != nil || len(only) != 2 {
		t.Fatalf("r1 only: %v, %v", codes(only), err)
	}
	if _, err := svc.ListPermissionsByRoles(nil); !errors.Is(err, auth.ErrEmptyRoleID) {
		t.Fatalf("err = %v", err)
	}
	if _, err := svc.ListPermissionsByRoles([]string{"r1", ""}); !errors.Is(err, auth.ErrEmptyRoleID) {
		t.Fatalf("err = %v", err)
	}
}

func TestHasPermission(t *testing.T) {
	svc := newSvc(t)
	home := mk(t, svc, "menu:home", "首页", auth.TypeMenu)
	exp := mk(t, svc, "btn:export", "导出", auth.TypeButton)
	lv := mk(t, svc, "approval:leave", "请假", auth.TypeApproval)

	svc.AssignRolePermission("r1", exp.ID)
	svc.AddDefaultPermission(home.ID)

	ok, err := svc.HasPermission("r1", "btn:export")
	if err != nil || !ok {
		t.Fatalf("assigned: %v, %v", ok, err)
	}
	ok, err = svc.HasPermission("r1", "menu:home")
	if err != nil || !ok {
		t.Fatalf("via default: %v, %v", ok, err)
	}
	ok, err = svc.HasPermission("r1", "approval:leave")
	if err != nil || ok {
		t.Fatalf("not granted: %v, %v", ok, err)
	}
	if _, err := svc.HasPermission("r1", "no:such"); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("unknown code: err = %v", err)
	}
	if _, err := svc.HasPermission("", "btn:export"); !errors.Is(err, auth.ErrEmptyRoleID) {
		t.Fatalf("err = %v", err)
	}

	ok, err = svc.HasPermissionInRoles([]string{"r1", "r2"}, "approval:leave")
	if err != nil || ok {
		t.Fatalf("multi missing: %v, %v", ok, err)
	}
	svc.AssignRolePermission("r2", lv.ID)
	ok, err = svc.HasPermissionInRoles([]string{"r1", "r2"}, "approval:leave")
	if err != nil || !ok {
		t.Fatalf("multi granted: %v, %v", ok, err)
	}
}

func TestDefaults(t *testing.T) {
	svc := newSvc(t)
	a := mk(t, svc, "menu:a", "A", auth.TypeMenu)
	b := mk(t, svc, "menu:b", "B", auth.TypeMenu)

	if err := svc.AddDefaultPermission(a.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.AddDefaultPermission(a.ID); err != nil {
		t.Fatalf("idempotent: %v", err)
	}
	if err := svc.AddDefaultPermission(9999); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("missing perm: err = %v", err)
	}
	if err := svc.AddDefaultPermission(b.ID); err != nil {
		t.Fatal(err)
	}

	got, err := svc.ListDefaultPermissions()
	if err != nil || len(got) != 2 {
		t.Fatalf("defaults = %v, %v", codes(got), err)
	}
	anyRole, err := svc.ListRolePermissions("brand-new-role")
	if err != nil {
		t.Fatal(err)
	}
	if len(anyRole) != 2 {
		t.Fatalf("new role should inherit defaults, got %v", codes(anyRole))
	}

	if err := svc.RemoveDefaultPermission(a.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.RemoveDefaultPermission(a.ID); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("remove twice: err = %v", err)
	}
	got, _ = svc.ListDefaultPermissions()
	if len(got) != 1 || got[0].Code != "menu:b" {
		t.Fatalf("after remove: %v", codes(got))
	}
}
