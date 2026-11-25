CREATE TABLE IF NOT EXISTS permissions (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	code       TEXT NOT NULL UNIQUE,
	name       TEXT NOT NULL,
	type       TEXT NOT NULL CHECK (type IN ('menu','button','approval')),
	created_at DATETIME NOT NULL,
	updated_at DATETIME NOT NULL
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
