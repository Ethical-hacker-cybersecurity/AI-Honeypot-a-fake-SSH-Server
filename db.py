import sqlite3
import time
import threading
from contextlib import closing

import config

_lock = threading.Lock()


def _conn():
    c = sqlite3.connect(config.DB_PATH, timeout=10)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    with closing(_conn()) as c:
        c.execute("PRAGMA journal_mode=WAL")
        c.execute(
            """CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL, session_id TEXT, ip TEXT, username TEXT,
                event_type TEXT, command TEXT, response TEXT,
                tag TEXT, severity INTEGER)"""
        )
        c.commit()


def log_event(session_id, ip, username, event_type, command="", response="", tag="", severity=0):
    with _lock, closing(_conn()) as c:
        c.execute(
            "INSERT INTO events (ts, session_id, ip, username, event_type, command, response, tag, severity)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (time.time(), session_id, ip, username, event_type, command, response, tag, severity),
        )
        c.commit()


def fetch_events(limit=300, ascending=False):
    order = "ASC" if ascending else "DESC"
    with closing(_conn()) as c:
        rows = c.execute(f"SELECT * FROM events ORDER BY id {order} LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]


def clear_db():
    with _lock, closing(_conn()) as c:
        c.execute("DELETE FROM events")
        c.commit()
