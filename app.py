from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse


ROOT = Path(__file__).parent
WEB_ROOT = ROOT / "web"
DATABASE = ROOT / "threatlens.db"
STATUSES = {"new", "acknowledged", "in-progress", "resolved", "closed"}


def connect_db() -> sqlite3.Connection:
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_db() -> None:
    with connect_db() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS indicators (
                id TEXT PRIMARY KEY,
                value TEXT NOT NULL UNIQUE,
                type TEXT NOT NULL,
                category TEXT NOT NULL,
                severity_score INTEGER NOT NULL,
                confidence INTEGER NOT NULL,
                tlp TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                country TEXT NOT NULL,
                source TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                description TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator_id TEXT NOT NULL REFERENCES indicators(id),
                state TEXT NOT NULL,
                assignee TEXT NOT NULL DEFAULT '',
                rule TEXT NOT NULL,
                created_at TEXT NOT NULL,
                description TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                object_type TEXT NOT NULL,
                object_id TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_indicators_score ON indicators(status, severity_score DESC);
            CREATE INDEX IF NOT EXISTS idx_alerts_state ON alerts(state, created_at DESC);
            """
        )
        if db.execute("SELECT COUNT(*) FROM indicators").fetchone()[0]:
            return

        now = datetime.now(timezone.utc)
        records = [
            ("ioc-001", "185.220.101.4", "ip", "TOR exit node", 96, 94, "amber", "DE", "AbuseIPDB", 1, "Repeated SSH scanning against three exposed assets."),
            ("ioc-002", "login-microsoft-secure.com", "domain", "Credential phishing", 91, 89, "amber", "NL", "URLhaus", 2, "Lookalike domain serving a credential-harvesting page."),
            ("ioc-003", "45.148.10.22", "ip", "Command and control", 84, 82, "green", "RU", "Feodo Tracker", 3, "Known botnet command-and-control infrastructure."),
            ("ioc-004", "d4a1c9f0b73e...", "hash_sha256", "Malware", 78, 76, "green", "US", "MalwareBazaar", 5, "Associated with a loader family; 37 of 71 engines detect it."),
            ("ioc-005", "cdn-update-check.net", "domain", "Suspicious infrastructure", 66, 68, "green", "SG", "ThreatFox", 8, "Recently observed domain with low-volume beaconing activity."),
            ("ioc-006", "91.240.118.172", "ip", "Brute force", 59, 61, "clear", "PL", "GreyNoise", 11, "Internet-wide scanning activity; investigate internal sightings."),
            ("ioc-007", "hxxps://dropper-files.org/a7", "url", "Malware delivery", 88, 87, "amber", "GB", "OTX", 16, "Payload delivery URL referenced by multiple community pulses."),
            ("ioc-008", "CVE-2025-2187", "cve", "Exploited vulnerability", 73, 79, "green", "US", "CISA KEV", 21, "Listed in the Known Exploited Vulnerabilities catalog."),
        ]
        for record in records:
            (ioc_id, value, kind, category, score, confidence, tlp, country, source, days, description) = record
            seen = (now - timedelta(days=days)).isoformat(timespec="seconds")
            db.execute(
                "INSERT INTO indicators VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?)",
                (ioc_id, value, kind, category, score, confidence, tlp, country, source, seen, seen, description),
            )

        alert_records = [
            ("ioc-001", "new", "", "High-confidence malicious IP", 1, "Matched internal authentication logs: 42 failed logins."),
            ("ioc-002", "new", "Priya Nair", "Phishing domain reported by 3 sources", 3, "Domain appeared in a user-submitted email report."),
            ("ioc-003", "acknowledged", "Daniel Okafor", "C2 indicator matched threat feed", 5, "Outbound DNS lookup observed on an internal host."),
            ("ioc-004", "in-progress", "Priya Nair", "Malware hash exceeds detection threshold", 8, "File hash found in endpoint telemetry."),
            ("ioc-007", "new", "", "Malware delivery URL observed", 12, "URL matched a recent payload delivery campaign."),
            ("ioc-005", "resolved", "Mei Lin Tan", "Newly registered suspicious domain", 19, "Reviewed and added to watchlist; no internal hits."),
        ]
        for ioc_id, state, assignee, rule, hours, description in alert_records:
            created = (now - timedelta(hours=hours)).isoformat(timespec="seconds")
            db.execute(
                "INSERT INTO alerts (indicator_id, state, assignee, rule, created_at, description) VALUES (?, ?, ?, ?, ?, ?)",
                (ioc_id, state, assignee, rule, created, description),
            )


def json_value(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


class ThreatLensHandler(BaseHTTPRequestHandler):
    server_version = "ThreatLens/1.0"

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def send_json(self, payload: object, status: int = 200) -> None:
        body = json_value(payload)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_static(self, filename: str) -> None:
        path = WEB_ROOT / filename
        if not path.is_file():
            self.send_error(404)
            return
        content_type = {".html": "text/html", ".css": "text/css", ".js": "text/javascript"}.get(path.suffix, "application/octet-stream")
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        request = urlparse(self.path)
        if request.path == "/":
            return self.send_static("index.html")
        if request.path == "/styles.css":
            return self.send_static("styles.css")
        if request.path == "/app.js":
            return self.send_static("app.js")
        if request.path == "/api/health":
            return self.send_json({"status": "ok", "service": "threatlens", "time": datetime.now(timezone.utc).isoformat()})
        if request.path == "/api/dashboard":
            return self.dashboard()
        if request.path == "/api/indicators":
            return self.indicators(parse_qs(request.query))
        if request.path == "/api/alerts":
            return self.alerts(parse_qs(request.query))
        self.send_json({"error_code": "not_found", "message": "Endpoint not found"}, 404)

    def dashboard(self) -> None:
        with connect_db() as db:
            active_iocs = db.execute("SELECT COUNT(*) FROM indicators WHERE status = 'active'").fetchone()[0]
            high_risk = db.execute("SELECT COUNT(*) FROM indicators WHERE status = 'active' AND severity_score >= 70").fetchone()[0]
            open_alerts = db.execute("SELECT COUNT(*) FROM alerts WHERE state NOT IN ('resolved', 'closed')").fetchone()[0]
            unassigned = db.execute("SELECT COUNT(*) FROM alerts WHERE state NOT IN ('resolved', 'closed') AND assignee = ''").fetchone()[0]
            rows = db.execute(
                """SELECT a.id, a.state, a.assignee, a.rule, a.created_at, a.description,
                          i.id AS indicator_id, i.value, i.type, i.category,
                          i.severity_score, i.confidence, i.tlp, i.country, i.source
                   FROM alerts a JOIN indicators i ON i.id = a.indicator_id
                   ORDER BY CASE a.state WHEN 'new' THEN 0 WHEN 'acknowledged' THEN 1 WHEN 'in-progress' THEN 2 ELSE 3 END,
                            i.severity_score DESC, a.created_at DESC"""
            ).fetchall()
            category_rows = db.execute(
                "SELECT category, COUNT(*) AS count FROM indicators WHERE status = 'active' GROUP BY category ORDER BY count DESC LIMIT 5"
            ).fetchall()
            indicators_count = db.execute("SELECT COUNT(*) FROM indicators").fetchone()[0]
        alerts = [dict(row) for row in rows]
        trend = []
        now = datetime.now(timezone.utc)
        for offset in range(6, -1, -1):
            day = (now - timedelta(days=offset)).date()
            trend.append({"day": day.strftime("%a"), "date": day.isoformat(), "alerts": max(2, 13 - offset * 2 + (offset % 3) * 2), "resolved": max(1, 9 - offset + (offset % 2))})
        self.send_json({
            "metrics": {"active_indicators": active_iocs, "high_risk": high_risk, "open_alerts": open_alerts, "unassigned": unassigned, "total_indicators": indicators_count},
            "alerts": alerts,
            "trend": trend,
            "categories": [dict(row) for row in category_rows],
            "sources": [
                {"name": "AbuseIPDB", "type": "IP reputation", "state": "Healthy", "updated": "2 min ago", "color": "mint"},
                {"name": "URLhaus", "type": "Malicious URLs", "state": "Healthy", "updated": "8 min ago", "color": "mint"},
                {"name": "Feodo Tracker", "type": "C2 infrastructure", "state": "Healthy", "updated": "14 min ago", "color": "mint"},
                {"name": "MalwareBazaar", "type": "Malware hashes", "state": "Delayed", "updated": "42 min ago", "color": "amber"},
            ],
        })

    def indicators(self, query: dict[str, list[str]]) -> None:
        search = query.get("q", [""])[0].strip()
        kind = query.get("type", [""])[0].strip()
        sql = "SELECT * FROM indicators WHERE 1 = 1"
        params: list[str] = []
        if search:
            sql += " AND (value LIKE ? OR category LIKE ? OR source LIKE ? OR description LIKE ?)"
            term = f"%{search}%"
            params.extend([term, term, term, term])
        if kind:
            sql += " AND type = ?"
            params.append(kind)
        sql += " ORDER BY severity_score DESC"
        with connect_db() as db:
            records = [dict(row) for row in db.execute(sql, params).fetchall()]
        self.send_json({"items": records, "total": len(records)})

    def alerts(self, query: dict[str, list[str]]) -> None:
        state = query.get("state", [""])[0].strip()
        with connect_db() as db:
            rows = db.execute(
                """SELECT a.id, a.state, a.assignee, a.rule, a.created_at, a.description,
                          i.id AS indicator_id, i.value, i.type, i.category,
                          i.severity_score, i.confidence, i.tlp, i.country, i.source
                   FROM alerts a JOIN indicators i ON i.id = a.indicator_id
                   WHERE (? = '' OR a.state = ?)
                   ORDER BY i.severity_score DESC, a.created_at DESC""",
                (state, state),
            ).fetchall()
        self.send_json({"items": [dict(row) for row in rows]})

    def do_PATCH(self) -> None:
        request = urlparse(self.path)
        pieces = request.path.strip("/").split("/")
        if len(pieces) != 3 or pieces[:2] != ["api", "alerts"]:
            return self.send_json({"error_code": "not_found", "message": "Endpoint not found"}, 404)
        try:
            alert_id = int(pieces[2])
            payload = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
        except (ValueError, json.JSONDecodeError):
            return self.send_json({"error_code": "invalid_request", "message": "A valid alert ID and JSON body are required"}, 400)
        state = payload.get("state")
        assignee = payload.get("assignee")
        if state is not None and state not in STATUSES:
            return self.send_json({"error_code": "invalid_state", "message": "Unsupported alert state"}, 400)
        if assignee is not None and (not isinstance(assignee, str) or len(assignee) > 120):
            return self.send_json({"error_code": "invalid_assignee", "message": "Assignee must be a string of at most 120 characters"}, 400)
        if state is None and assignee is None:
            return self.send_json({"error_code": "empty_update", "message": "Provide a state or assignee"}, 400)
        with connect_db() as db:
            current = db.execute("SELECT id, state, assignee FROM alerts WHERE id = ?", (alert_id,)).fetchone()
            if not current:
                return self.send_json({"error_code": "not_found", "message": "Alert not found"}, 404)
            next_state = state if state is not None else current["state"]
            next_assignee = assignee if assignee is not None else current["assignee"]
            db.execute("UPDATE alerts SET state = ?, assignee = ? WHERE id = ?", (next_state, next_assignee, alert_id))
            db.execute(
                "INSERT INTO audit_log (actor, action, object_type, object_id, created_at) VALUES (?, ?, ?, ?, ?)",
                ("Local analyst", "alert.updated", "alert", str(alert_id), datetime.now(timezone.utc).isoformat(timespec="seconds")),
            )
            updated = db.execute("SELECT id, state, assignee FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        self.send_json({"alert": dict(updated)})

    def do_POST(self) -> None:
        request = urlparse(self.path)
        pieces = request.path.strip("/").split("/")
        if len(pieces) == 4 and pieces[:2] == ["api", "indicators"] and pieces[3] == "enrich":
            indicator_id = unquote(pieces[2])
            with connect_db() as db:
                indicator = db.execute("SELECT id, value, type, source, confidence, severity_score FROM indicators WHERE id = ?", (indicator_id,)).fetchone()
            if not indicator:
                return self.send_json({"error_code": "not_found", "message": "Indicator not found"}, 404)
            self.send_json({"indicator": dict(indicator), "enriched_at": datetime.now(timezone.utc).isoformat(), "message": "Latest stored source verdicts returned"})
            return
        self.send_json({"error_code": "not_found", "message": "Endpoint not found"}, 404)


def main() -> None:
    initialize_db()
    server = ThreadingHTTPServer(("127.0.0.1", 8000), ThreatLensHandler)
    print("ThreatLens is running at http://127.0.0.1:8000")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping ThreatLens")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()