import json
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path


DEFAULT_DATABASE_PATH = Path(
    os.environ.get("SCAN_DATABASE_PATH", Path(__file__).resolve().parent / "scan_history.db")
)
CLASSIFICATIONS = {"safe", "suspicious", "phishing"}
CREATE_SCANS_TABLE = """
    CREATE TABLE scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL,
        prediction TEXT NOT NULL CHECK (prediction IN ('safe', 'suspicious', 'phishing')),
        risk_score REAL NOT NULL,
        confidence REAL,
        reasons TEXT NOT NULL DEFAULT '[]',
        scanned_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    )
"""


@contextmanager
def connect(database_path=None):
    path = Path(database_path or DEFAULT_DATABASE_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=10)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _create_scans_table(connection):
    connection.execute(CREATE_SCANS_TABLE)


def _migrate_existing_scans(connection, columns):
    legacy_rows = connection.execute("SELECT * FROM scans ORDER BY id").fetchall()
    connection.execute("DROP INDEX IF EXISTS idx_scans_scanned_at")
    connection.execute("ALTER TABLE scans RENAME TO scans_legacy")
    _create_scans_table(connection)

    for row in legacy_rows:
        old_prediction = row["prediction"]
        classification = old_prediction if old_prediction in CLASSIFICATIONS else (
            "safe" if old_prediction == "legitimate" else "phishing"
        )
        old_confidence = row["confidence"] if "confidence" in columns else None
        if "risk_score" in columns and row["risk_score"] is not None:
            risk_score = row["risk_score"]
        elif old_confidence is None:
            risk_score = 0 if classification == "safe" else 100
        else:
            risk_score = (1 - old_confidence) * 100 if classification == "safe" else old_confidence * 100
        reasons = row["reasons"] if "reasons" in columns and row["reasons"] else "[]"
        scanned_at = row["scanned_at"] if "scanned_at" in columns else None
        connection.execute(
            "INSERT INTO scans (id, url, prediction, risk_score, confidence, reasons, scanned_at) "
            "VALUES (?, ?, ?, ?, ?, ?, COALESCE(?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))) ",
            (row["id"], row["url"], classification, risk_score, old_confidence, reasons, scanned_at),
        )
    connection.execute("DROP TABLE scans_legacy")


def init_db(database_path=None):
    with connect(database_path) as connection:
        table_exists = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'scans'"
        ).fetchone()
        if not table_exists:
            _create_scans_table(connection)
        else:
            columns = {row["name"] for row in connection.execute("PRAGMA table_info(scans)")}
            required_columns = {"id", "url", "prediction", "risk_score", "confidence", "reasons", "scanned_at"}
            if not required_columns.issubset(columns):
                _migrate_existing_scans(connection, columns)
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_scans_scanned_at ON scans (scanned_at DESC)"
        )


def record_scan(database_path, url, classification, risk_score, confidence, reasons):
    with connect(database_path) as connection:
        cursor = connection.execute(
            "INSERT INTO scans (url, prediction, risk_score, confidence, reasons) VALUES (?, ?, ?, ?, ?)",
            (url, classification, risk_score, confidence, json.dumps(reasons)),
        )
        row = connection.execute(
            "SELECT id, url, prediction, risk_score, confidence, reasons, scanned_at "
            "FROM scans WHERE id = ?",
            (cursor.lastrowid,),
        ).fetchone()
    return _decode_scan(row)


def _decode_scan(row):
    scan = dict(row)
    try:
        scan["reasons"] = json.loads(scan["reasons"])
    except (TypeError, json.JSONDecodeError):
        scan["reasons"] = []
    return scan


def get_dashboard_stats(database_path=None):
    with connect(database_path) as connection:
        row = connection.execute(
            """
            SELECT COUNT(*) AS total,
                   SUM(CASE WHEN prediction = 'safe' THEN 1 ELSE 0 END) AS safe,
                   SUM(CASE WHEN prediction = 'suspicious' THEN 1 ELSE 0 END) AS suspicious,
                   SUM(CASE WHEN prediction = 'phishing' THEN 1 ELSE 0 END) AS phishing
            FROM scans
            """
        ).fetchone()

    total = row["total"] or 0
    safe = row["safe"] or 0
    suspicious = row["suspicious"] or 0
    phishing = row["phishing"] or 0
    return {
        "total_scans": total,
        "safe_detected": safe,
        "suspicious_detected": suspicious,
        "phishing_detected": phishing,
        "threat_rate": round((phishing + suspicious) * 100 / total, 1) if total else 0,
    }


def search_scans(database_path=None, search="", classification=None, limit=50, offset=0):
    limit = max(1, min(int(limit), 200))
    offset = max(0, int(offset))
    clauses = []
    parameters = []
    if search:
        clauses.append("url LIKE ? ESCAPE '\\'")
        escaped_search = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        parameters.append(f"%{escaped_search}%")
    if classification in CLASSIFICATIONS:
        clauses.append("prediction = ?")
        parameters.append(classification)
    where_clause = " WHERE " + " AND ".join(clauses) if clauses else ""

    with connect(database_path) as connection:
        total = connection.execute(
            f"SELECT COUNT(*) FROM scans{where_clause}", parameters
        ).fetchone()[0]
        rows = connection.execute(
            "SELECT id, url, prediction, risk_score, confidence, reasons, scanned_at "
            f"FROM scans{where_clause} ORDER BY id DESC LIMIT ? OFFSET ?",
            (*parameters, limit, offset),
        ).fetchall()
    return [_decode_scan(row) for row in rows], total


def get_recent_scans(database_path=None, limit=10):
    return search_scans(database_path, limit=limit)[0]


def get_scans(database_path=None):
    with connect(database_path) as connection:
        rows = connection.execute(
            "SELECT id, url, prediction, risk_score, confidence, reasons, scanned_at "
            "FROM scans ORDER BY id DESC"
        ).fetchall()
    return [_decode_scan(row) for row in rows]


def delete_scan(database_path, scan_id):
    with connect(database_path) as connection:
        cursor = connection.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    return cursor.rowcount > 0


def clear_scans(database_path=None):
    with connect(database_path) as connection:
        cursor = connection.execute("DELETE FROM scans")
    return cursor.rowcount