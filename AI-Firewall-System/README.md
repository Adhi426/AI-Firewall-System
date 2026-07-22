# AI Firewall System

An AI-assisted network firewall that classifies traffic flows as **benign** or **malicious**
using a machine-learning model, then automatically enforces block/allow rules, logs every
decision, and exposes it all through a REST API and a live dashboard.

```
┌────────────┐     traffic flow     ┌─────────────┐     features      ┌────────────┐
│  Traffic   │ ───────────────────▶ │   Backend   │ ─────────────────▶│  AI Engine │
│  Source    │                      │  (FastAPI)  │◀───────────────── │ (ML Model) │
└────────────┘                      └──────┬──────┘   verdict+score   └────────────┘
                                            │
                                     ┌──────▼──────┐
                                     │   SQLite    │  rules / logs / blocked IPs
                                     └──────┬──────┘
                                            │
                                     ┌──────▼──────┐
                                     │  Frontend   │  live dashboard
                                     └─────────────┘
```

## Components

| Folder       | What it is                                                                 |
|--------------|-----------------------------------------------------------------------------|
| `ai-engine/` | Generates synthetic network-flow data, trains a RandomForest classifier, and serves predictions (used directly by the backend). |
| `backend/`   | FastAPI service: analyzes traffic through the AI engine, applies firewall rules, auto-blocks malicious IPs, stores everything in SQLite, and exposes a REST API. |
| `database/`  | SQL schema (SQLAlchemy also creates this automatically on first run). |
| `frontend/`  | Zero-build single-page dashboard (HTML/CSS/JS + Chart.js) that talks to the backend API. |
| `docs/`      | Architecture notes and setup guide. |

## Quick start

```bash
# 1. Train the AI model (only needs to be done once)
cd ai-engine
pip install -r requirements.txt
python train.py

# 2. Run the backend (serves the API + AI engine)
cd ../backend
pip install -r requirements.txt
uvicorn app:app --reload --port 8000

# 3. Open the dashboard
cd ../frontend
python -m http.server 5500
# visit http://localhost:5500
```

The dashboard talks to `http://localhost:8000` by default (see `frontend/app.js`).

## What it actually does

- The AI engine is trained on labelled network-flow features (duration, packet count,
  byte count, packets/sec, port, protocol, flag ratios, etc.) and outputs a
  malicious-probability score.
- The backend runs every incoming flow through the model, applies configurable
  threshold + custom rules (allow-list, deny-list, rate limits), decides
  **ALLOW / BLOCK**, writes an audit log entry, and auto-adds the source IP to the
  blocklist if it crosses the malicious-confidence threshold.
- The dashboard shows live traffic, blocked IPs, rule management, and lets you
  simulate traffic to see the pipeline work end-to-end without needing real
  network capture hardware.

## Notes on scope

This is a self-contained, runnable reference implementation meant as a strong
foundation to build on — it is not a production packet-filtering firewall (it
does not hook into the OS network stack / iptables). Wiring it up to real packet
capture (e.g. via `scapy` or `pyshark`) is a natural next step and is called out
in `docs/ARCHITECTURE.md`.
