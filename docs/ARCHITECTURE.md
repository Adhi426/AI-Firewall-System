# Architecture

## Data flow

1. A traffic flow (real or simulated) is submitted to the backend at
   `POST /api/traffic/analyze` as a JSON object of flow features.
2. The backend hands the feature vector to the AI engine (`ai_engine.predict`),
   which returns `{ label: "benign" | "malicious", confidence: 0-1 }`.
3. The backend's rule engine (`rules_engine.py`) checks, in order:
   - Is the source IP explicitly allow-listed? → **ALLOW**
   - Is the source IP explicitly deny-listed / already blocked? → **BLOCK**
   - Does the ML confidence exceed the configured block threshold? → **BLOCK** + auto-add to blocklist
   - Otherwise → **ALLOW**
4. Every decision is written to the `logs` table (flow features, verdict, confidence, timestamp).
5. The frontend polls `GET /api/logs`, `GET /api/blocked`, and `GET /api/rules`
   to render a live view, and can POST to `/api/traffic/simulate` to generate
   test traffic.

## AI engine

- `ai-engine/data/generate_data.py` builds a synthetic but realistic labelled
  dataset of network flows (benign traffic clusters vs. several attack
  patterns: port scan, DoS-like burst, brute force, data exfiltration).
- `ai-engine/train.py` trains a `RandomForestClassifier` (scikit-learn) on
  that dataset, evaluates it, and saves the model + feature scaler to
  `ai-engine/saved_model/`.
- `ai-engine/predict.py` loads the saved model and exposes `predict(features: dict) -> dict`,
  which the backend imports directly (no extra network hop).

## Backend

FastAPI app (`backend/app.py`) with routers:

- `routers/traffic.py` — analyze a flow, simulate traffic
- `routers/rules.py` — CRUD for firewall rules (allow-list / deny-list / threshold)
- `routers/logs.py` — list/query logs, blocked IPs, stats for the dashboard

Persistence is SQLite via SQLAlchemy (`backend/database.py`, `backend/models.py`),
matching `database/schema.sql`.

## Frontend

Plain HTML/CSS/JS (no build step) using Chart.js from a CDN for the traffic
chart. `frontend/app.js` polls the backend every few seconds and re-renders:

- live traffic log table with verdicts
- blocked-IP list with an "unblock" action
- rule manager (add/remove allow & deny rules, edit the block threshold)
- a small chart of benign vs malicious flows over time

## Extending toward real packet capture

To move from simulated flows to real traffic:

1. Use `scapy` or `pyshark` to sniff live packets (requires elevated
   privileges) and aggregate them into flows (5-tuple: src/dst IP, src/dst
   port, protocol) over a short time window.
2. Compute the same feature set the model was trained on (duration, packet
   count, byte count, packets/sec, etc.) for each flow.
3. POST the resulting feature dict to `/api/traffic/analyze` exactly as the
   simulator does.
4. To actually *enforce* a BLOCK verdict at the OS level, integrate with
   `iptables`/`nftables` (Linux) or the Windows Filtering Platform — this
   requires running the enforcement component with appropriate system
   privileges and is intentionally kept out of this reference app for safety
   and portability.
