# URL Audit Kit

SOC-style URL security platform with persistent telemetry, live scan progress, and threat intelligence views.

## Features
- FastAPI backend with SQLite persistence for scans, checks, and indicators
- Next.js SOC dashboard UI (dashboard, scanner, threat intel, history, reports, indicators, settings)
- Real-time scan progress over WebSocket
- Deterministic risk scoring (`LOW/MEDIUM/HIGH/CRITICAL`) plus optional AI threat summaries

## Quick Start

### Backend (FastAPI)
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python -m webapp
```

Backend default: `http://127.0.0.1:8765`

### Frontend (Next.js)
```bash
cd frontend
npm install
npm run dev
```

Frontend default: `http://localhost:3000`

## API Highlights
- `POST /api/audit` (`url`, optional `job_id`, optional `scan_mode=scan|deep|sandbox`)
- `WS /ws/progress/{job_id}`
- `GET /api/dashboard/overview`
- `GET /api/scans`, `GET /api/scans/{scan_id}`, `GET /api/scans/{scan_id}/report`
- `GET /api/iocs`
- `GET /api/threat-intelligence/map`

## CLI
```bash
source .venv/bin/activate
python cli.py https://example.com --json report.json
```

## Environment
See `.env.example` for optional scanner/reputation/AI keys.
