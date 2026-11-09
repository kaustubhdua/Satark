from __future__ import annotations

import json
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text


def _alembic_config() -> Config:
    return Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))


def test_fresh_sqlite_database_upgrades_and_downgrades_all_revisions(tmp_path, monkeypatch):
    database = tmp_path / "fresh.db"
    monkeypatch.setenv("SATARK_DATABASE_URL", f"sqlite:///{database}")
    config = _alembic_config()

    command.upgrade(config, "head")
    engine = create_engine(f"sqlite:///{database}")
    inspector = inspect(engine)
    assert "satark_password_reset_tokens" in inspector.get_table_names()
    assert "satark_email_verification_tokens" in inspector.get_table_names()
    assert "email_verified_at" in {column["name"] for column in inspector.get_columns("satark_users")}
    assert "satark_auth_throttles" in inspector.get_table_names()
    audit_columns = {column["name"]: column for column in inspector.get_columns("satark_audit_events")}
    assert audit_columns["sequence"]["nullable"] is False
    assert any(
        item.get("name") == "uq_satark_audit_sequence"
        for item in inspector.get_unique_constraints("satark_audit_events")
    )

    command.downgrade(config, "base")
    assert "satark_audit_events" not in inspect(engine).get_table_names()
    engine.dispose()


def test_existing_sqlite_audit_chain_backfill_follows_hash_links_not_timestamps(tmp_path, monkeypatch):
    database = tmp_path / "legacy.db"
    engine = create_engine(f"sqlite:///{database}")
    with engine.begin() as connection:
        connection.exec_driver_sql("""
            CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL PRIMARY KEY)
        """)
        connection.execute(text("INSERT INTO alembic_version(version_num) VALUES ('20261109_0004')"))
        connection.exec_driver_sql("""
            CREATE TABLE satark_users (
                id VARCHAR(36) PRIMARY KEY,
                email VARCHAR(254) NOT NULL,
                password_hash VARCHAR(512) NOT NULL,
                is_active BOOLEAN NOT NULL,
                created_at DATETIME NOT NULL
            )
        """)
        connection.exec_driver_sql("""
            CREATE TABLE satark_audit_events (
                id VARCHAR(36) PRIMARY KEY,
                tenant_id VARCHAR(36) NOT NULL,
                actor_id VARCHAR(36) NOT NULL,
                event_type VARCHAR(100) NOT NULL,
                payload JSON NOT NULL,
                previous_hash VARCHAR(64) NOT NULL,
                event_hash VARCHAR(64) NOT NULL,
                created_at DATETIME NOT NULL
            )
        """)
        timestamp = "2026-11-09 12:00:00"
        connection.execute(text("""
            INSERT INTO satark_audit_events
                (id, tenant_id, actor_id, event_type, payload, previous_hash, event_hash, created_at)
            VALUES
                ('z-first', 'tenant-a', 'actor', 'first', :payload, :zero, :first, :created),
                ('a-second', 'tenant-a', 'actor', 'second', :payload, :first, :second, :created)
        """), {
            "payload": json.dumps({}),
            "zero": "0" * 64,
            "first": "a" * 64,
            "second": "b" * 64,
            "created": timestamp,
        })
    engine.dispose()

    monkeypatch.setenv("SATARK_DATABASE_URL", f"sqlite:///{database}")
    command.upgrade(_alembic_config(), "head")

    engine = create_engine(f"sqlite:///{database}")
    with engine.connect() as connection:
        rows = connection.execute(text("""
            SELECT id, sequence FROM satark_audit_events ORDER BY sequence
        """)).all()
    assert rows == [("z-first", 1), ("a-second", 2)]
    engine.dispose()
