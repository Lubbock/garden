CREATE TABLE IF NOT EXISTS sys_permissions (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	code       TEXT NOT NULL UNIQUE,
	name       TEXT NOT NULL,
	type       TEXT NOT NULL CHECK (type IN ('menu','button','approval')),
	created_at DATETIME NOT NULL,
	updated_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS sys_role_permissions (
	role_id       TEXT NOT NULL,
	permission_id INTEGER NOT NULL REFERENCES sys_permissions(id) ON DELETE CASCADE,
	PRIMARY KEY (role_id, permission_id)
);

CREATE INDEX IF NOT EXISTS idx_sys_role_permissions_role ON sys_role_permissions(role_id);

CREATE TABLE IF NOT EXISTS sys_default_permissions (
	permission_id INTEGER PRIMARY KEY REFERENCES sys_permissions(id) ON DELETE CASCADE
);
