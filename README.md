# SentinelAI SOC

Security operations stack with log ingestion, alerting, UEBA, ML anomaly detection, and incident reporting.

**Stack**
- Backend: FastAPI + MongoDB (Motor)
- ML: scikit-learn, NumPy
- Frontend: React + Vite

**Repo layout**
- `backend/`: FastAPI service, UEBA, ML, incident APIs
- `frontend/`: React UI

**Prerequisites**
- Python 3.10+ (code uses `str | None` type unions)
- Node.js (Vite 7 works best on recent Node LTS)
- MongoDB running locally (or update the URI)

**Database**
- The backend connects to `mongodb://127.0.0.1:27017`
- Database name: `sentinelai`
- Collections created automatically on first insert:
`logs`, `alerts`, `ueba_profiles`, `ueba_sessions`, `ueba_user_profiles`, `ueba_incidents`

If your MongoDB URI is different, update it in `backend/app/core/database.py`.

**Backend setup**
1. Create and activate a virtual environment.
```bash
# Windows (PowerShell)
python -m venv .venv
.venv\Scripts\Activate.ps1

# If activation is blocked:
# Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
# This allows running local scripts (like venv activation) for your user only.
# Revert anytime with:
# Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Restricted

# macOS / Linux
python3 -m venv .venv
source .venv/bin/activate
```
2. Install dependencies:
```bash
pip install -r requirements.txt
```
3. Run the API:
```bash
cd backend
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

**Optional environment variables**
- `ABUSEIPDB_API_KEY`: Enables IP reputation lookup in incident details.

**Frontend setup**
```bash
cd frontend
npm install
npm run dev
```
Frontend default: `http://localhost:5173`
Backend default: `http://localhost:8000`

**Key endpoints**
- `POST /api/ingest` — ingest raw auth logs
- `GET /api/logs` — list logs (`ip`, `user`, `limit`)
- `GET /api/alerts` — list alerts (`severity`, `limit`)
- `POST /api/ml/train` — train anomaly model (`days`)
- `GET /api/incidents` — list UEBA incidents
- `GET /api/incidents/{incident_key}/details`
- `GET /api/incidents/{incident_key}/report?format=txt|html`
- `WS /ws/alerts` — websocket stream for alert broadcasts

**Example ingest**
```bash
curl -X POST http://127.0.0.1:8000/api/ingest \
  -H "Content-Type: application/json" \
  -d "{\"raw_log\":\"Failed password for root from 10.0.0.9 port 22 ssh2\"}"
```

**Test generators**
- `backend/tools/attack_simulator.py`: random log spam
- `backend/test_spam.py`: fixed IP spam

Run them after the backend is up:
```bash
python backend/tools/attack_simulator.py
```

**Notes**
- This repo currently does not include a `requirements.txt`. Consider adding one for reproducible installs.
- Don’t commit `node_modules/` to GitHub.
