# ThreatLens

ThreatLens is a combined, local-first cyber threat intelligence dashboard and API. The Python service serves the frontend and JSON API from one process; SQLite persists the canonical indicator records, alert state, and audit entries.

## Run

Requires Python 3.9 or newer. No third-party packages, Node.js, or Docker are required.

```powershell
python app.py
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000). Stop the server with `Ctrl+C`. The local database is created as `threatlens.db` on first launch.

## Included workflow

- Analyst overview with severity-prioritized alerts, feed health, activity trends, and threat categories.
- Alert queue filters and global search; select an alert to inspect context, enrich, assign, acknowledge, investigate, or resolve it.
- Indicator registry with type filtering, search, severity and confidence, plus CSV export.
- State changes persist in SQLite and append an audit record.
- Responsive dark SOC dashboard with reduced-motion support.

The included records are clearly demonstration data. Feed health and enrichment results are seeded examples, not live provider integrations. Do not use this prototype as a production security control; authentication, RBAC, secret management, provider connectors, and deployment hardening remain future implementation work.

## API

All endpoints use the same origin as the dashboard:

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/health` | Service health |
| GET | `/api/dashboard` | Metrics, prioritized alerts, trend, categories, and feed status |
| GET | `/api/alerts?state=new` | Alert queue, optionally filtered by state |
| PATCH | `/api/alerts/{id}` | Update `state` and/or `assignee` |
| GET | `/api/indicators?q=term&type=ip` | Search and filter canonical indicators |
| POST | `/api/indicators/{id}/enrich` | Return the latest stored source verdict |

Example:

```powershell
Invoke-RestMethod -Method Patch -Uri http://127.0.0.1:8000/api/alerts/1 -ContentType 'application/json' -Body '{"state":"acknowledged","assignee":"Priya Nair"}'
```