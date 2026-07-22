# Setup Guide

## Requirements

- Python 3.10+
- pip

## 1. Train the AI model

```bash
cd ai-engine
pip install -r requirements.txt
python train.py
```

This generates a synthetic labelled traffic dataset, trains a
RandomForest classifier, and saves it to `ai-engine/saved_model/`.
You should see a classification report with high precision/recall printed
at the end — that confirms the model trained correctly.

You can sanity-check the saved model directly:

```bash
python predict.py
```

## 2. Run the backend API

```bash
cd ../backend
pip install -r requirements.txt
uvicorn app:app --reload --port 8000
```

- API root: http://localhost:8000/
- Interactive API docs (Swagger UI): http://localhost:8000/docs
- The SQLite database file `backend/firewall.db` is created automatically
  on first run.

## 3. Run the frontend dashboard

Any static file server works — no build step needed:

```bash
cd ../frontend
python -m http.server 5500
```

Open http://localhost:5500 in a browser. Click **"Simulate 15 flows"** a few
times to see traffic, blocked IPs, and the chart populate.

If your backend runs on a different host/port, edit `API_BASE` at the top of
`frontend/app.js`.

## 4. Try the API directly

```bash
# Analyze a hand-crafted flow that looks like a port scan
curl -X POST http://localhost:8000/api/traffic/analyze \
  -H "Content-Type: application/json" \
  -d '{
        "src_ip": "203.0.113.5", "dst_ip": "10.0.0.1",
        "duration_ms": 100, "packet_count": 5, "byte_count": 300,
        "packets_per_sec": 50, "avg_packet_size": 60,
        "src_port": 51000, "dst_port": 22, "protocol": "TCP",
        "syn_ratio": 0.95, "unique_ports_touched": 300
      }'

# Add an allow-list rule
curl -X POST http://localhost:8000/api/rules \
  -H "Content-Type: application/json" \
  -d '{"rule_type": "allow_ip", "value": "192.168.1.10", "description": "trusted host"}'

# Check current stats
curl http://localhost:8000/api/stats
```

## Troubleshooting

- **"No trained model found"** when starting the backend → run
  `python train.py` inside `ai-engine/` first (step 1).
- **Dashboard shows "disconnected"** → make sure the backend is running on
  port 8000, and that `API_BASE` in `frontend/app.js` matches.
- **CORS errors in the browser console** → the backend already allows all
  origins for local development (`backend/app.py`); if you changed that,
  add your frontend's origin back to `allow_origins`.
