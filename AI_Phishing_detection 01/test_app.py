import sqlite3
import tempfile
import unittest
from pathlib import Path

import app as phishing_app
from database import get_dashboard_stats, get_recent_scans, init_db


class PhishTowerAPITests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = str(Path(self.temporary_directory.name) / "test-scans.sqlite3")
        self.previous_database_path = phishing_app.app.config["DATABASE_PATH"]
        phishing_app.app.config.update(TESTING=True, DATABASE_PATH=self.database_path)
        init_db(self.database_path)
        self.client = phishing_app.app.test_client()
        self.assertEqual(self.client.get("/").status_code, 200)
        with self.client.session_transaction() as browser_session:
            self.csrf_token = browser_session["csrf_token"]
        self.headers = {"X-CSRF-Token": self.csrf_token}

    def tearDown(self):
        phishing_app.app.config["DATABASE_PATH"] = self.previous_database_path
        self.temporary_directory.cleanup()

    def scan(self, url):
        return self.client.post("/api/scan", json={"url": url}, headers=self.headers)

    def test_validation_and_three_class_scans(self):
        safe = self.scan("https://www.google.com")
        suspicious = self.scan("https://example.com/search?q=login")
        phishing = self.scan("https://secure-account-login.example.com/verify")

        self.assertEqual(safe.status_code, 200)
        self.assertEqual(safe.get_json()["scan"]["prediction"], "safe")
        self.assertEqual(suspicious.get_json()["scan"]["prediction"], "suspicious")
        self.assertEqual(phishing.get_json()["scan"]["prediction"], "phishing")
        self.assertTrue(phishing.get_json()["scan"]["features"]["suspicious_keywords"])

        for invalid_url in ["", "javascript:alert(1)", "https://", "x" * 2049, "https://user:pass@example.com"]:
            with self.subTest(url=invalid_url[:40]):
                self.assertEqual(self.scan(invalid_url).status_code, 400)

        self.assertEqual(self.client.post("/api/scan", json=[] , headers=self.headers).status_code, 400)

    def test_history_search_delete_clear_and_csv(self):
        first = self.scan("https://www.google.com").get_json()["scan"]
        self.scan("https://example.com/search?q=login")
        filtered = self.client.get("/api/history?search=google&classification=safe").get_json()
        self.assertEqual(filtered["total"], 1)
        self.assertEqual(filtered["scans"][0]["id"], first["id"])

        csv_response = self.client.get("/report.csv")
        self.assertEqual(csv_response.status_code, 200)
        self.assertIn(b"Risk score", csv_response.data)
        self.assertIn(b"https://www.google.com", csv_response.data)

        self.assertEqual(self.client.delete(f"/api/history/{first['id']}").status_code, 403)
        self.assertEqual(self.client.delete(f"/api/history/{first['id']}", headers=self.headers).status_code, 200)
        self.assertEqual(self.client.delete(f"/api/history/{first['id']}", headers=self.headers).status_code, 404)
        cleared = self.client.post("/api/history/clear", json={}, headers=self.headers)
        self.assertEqual(cleared.status_code, 200)
        self.assertEqual(cleared.get_json()["stats"]["total_scans"], 0)

    def test_legacy_history_migrates_without_losing_rows(self):
        legacy_path = Path(self.temporary_directory.name) / "legacy.sqlite3"
        connection = sqlite3.connect(legacy_path)
        connection.execute(
            "CREATE TABLE scans (id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT NOT NULL, "
            "prediction TEXT NOT NULL CHECK (prediction IN ('phishing', 'legitimate')), "
            "confidence REAL, scanned_at TEXT NOT NULL)"
        )
        connection.executemany(
            "INSERT INTO scans (url, prediction, confidence, scanned_at) VALUES (?, ?, ?, ?)",
            [
                ("https://legacy-safe.test", "legitimate", 0.9, "2026-01-01T00:00:00Z"),
                ("https://legacy-phish.test", "phishing", 0.95, "2026-01-02T00:00:00Z"),
            ],
        )
        connection.commit()
        connection.close()

        init_db(legacy_path)
        stats = get_dashboard_stats(legacy_path)
        scans = get_recent_scans(legacy_path)
        self.assertEqual(stats["safe_detected"], 1)
        self.assertEqual(stats["phishing_detected"], 1)
        self.assertEqual(scans[0]["risk_score"], 95)
        self.assertEqual(scans[0]["scanned_at"], "2026-01-02T00:00:00Z")


if __name__ == "__main__":
    unittest.main()