"""A deliberately vulnerable demo service used to exercise PatchPilot."""
import sqlite3

import yaml


def load_settings(raw: str) -> dict:
    return yaml.load(raw)


def find_user(conn: sqlite3.Connection, name: str):
    cursor = conn.cursor()
    cursor.execute("SELECT id, name FROM users WHERE name = '%s'" % name)
    return cursor.fetchone()
