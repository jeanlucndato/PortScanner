"""Small, ordered SQLite schema migrations. Add future changes as new versions."""
from sqlalchemy import inspect, text


def migrate(engine):
    inspector = inspect(engine)
    tables = inspector.get_table_names()
    with engine.begin() as connection:
        if "schema_migrations" not in tables:
            connection.execute(text("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"))
        version = connection.execute(text("SELECT MAX(version) FROM schema_migrations")).scalar() or 0
        if version < 1:
            existing = set(inspect(engine).get_table_names())
            if "scan_runs" in existing:
                columns = {column["name"] for column in inspect(engine).get_columns("scan_runs")}
                additions = {
                    "profile": "VARCHAR NOT NULL DEFAULT 'common'",
                    "ports_requested": "TEXT NOT NULL DEFAULT '[]'",
                    "status": "VARCHAR NOT NULL DEFAULT 'completed'",
                    "progress": "INTEGER NOT NULL DEFAULT 100",
                    "current_target": "VARCHAR",
                    "error_message": "TEXT",
                }
                for name, definition in additions.items():
                    if name not in columns:
                        connection.execute(text(f"ALTER TABLE scan_runs ADD COLUMN {name} {definition}"))
                connection.execute(text("UPDATE scan_runs SET status = CASE WHEN end_time IS NULL THEN 'failed' ELSE 'completed' END, progress = CASE WHEN end_time IS NULL THEN 0 ELSE 100 END"))
            if "hosts" in existing:
                columns = {column["name"] for column in inspect(engine).get_columns("hosts")}
                if "hostname" not in columns:
                    connection.execute(text("ALTER TABLE hosts ADD COLUMN hostname VARCHAR"))
                uniques = inspect(engine).get_unique_constraints("hosts")
                if any(["ip_address"] == item.get("column_names") for item in uniques):
                    connection.execute(text("ALTER TABLE hosts RENAME TO hosts_legacy"))
                    connection.execute(text("CREATE TABLE hosts (id INTEGER NOT NULL PRIMARY KEY, ip_address VARCHAR NOT NULL, mac_address VARCHAR, hostname VARCHAR, scan_run_id INTEGER NOT NULL, FOREIGN KEY(scan_run_id) REFERENCES scan_runs (id))"))
                    connection.execute(text("INSERT INTO hosts (id, ip_address, mac_address, hostname, scan_run_id) SELECT id, ip_address, mac_address, hostname, scan_run_id FROM hosts_legacy"))
                    connection.execute(text("DROP TABLE hosts_legacy"))
            if "ports" in existing:
                connection.execute(text("UPDATE ports SET status = CASE WHEN lower(status) IN ('open','ouvert') THEN 'open' WHEN lower(status) IN ('closed','fermé','ferme') THEN 'closed' ELSE 'filtered' END"))
            connection.execute(text("INSERT INTO schema_migrations(version) VALUES (1)"))
            version = 1
        if version < 2:
            if "scan_runs" in inspect(engine).get_table_names():
                columns = {column["name"] for column in inspect(engine).get_columns("scan_runs")}
                if "active_guard" not in columns:
                    connection.execute(text("ALTER TABLE scan_runs ADD COLUMN active_guard INTEGER"))
                connection.execute(text("CREATE UNIQUE INDEX uq_one_active_scan ON scan_runs (active_guard)"))
            connection.execute(text("INSERT INTO schema_migrations(version) VALUES (2)"))
