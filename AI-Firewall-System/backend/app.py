import sys
import os

sys.path.append(os.path.dirname(__file__))
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(__file__)), "ai-engine"))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import models
from database import engine
from routers import traffic, rules, logs

models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="AI Firewall System",
    description="AI-assisted traffic classification, rule enforcement, and logging.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # demo/dev only — tighten this for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(traffic.router)
app.include_router(rules.router)
app.include_router(logs.router)


@app.get("/")
def root():
    return {
        "service": "AI Firewall System backend",
        "docs": "/docs",
        "endpoints": [
            "POST /api/traffic/analyze",
            "POST /api/traffic/simulate",
            "POST /api/traffic/simulate_batch?count=10",
            "GET  /api/logs",
            "GET  /api/blocked",
            "POST /api/blocked/{ip}/unblock",
            "GET  /api/rules",
            "POST /api/rules",
            "DELETE /api/rules/{id}",
            "GET  /api/stats",
        ],
    }
