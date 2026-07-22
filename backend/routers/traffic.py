import sys
import os
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

sys.path.append(os.path.dirname(os.path.dirname(__file__)))          # backend/
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "ai-engine"))

import models
import schemas
import rules_engine
import simulator
from database import get_db
from predict import predict as ai_predict

router = APIRouter(prefix="/api/traffic", tags=["traffic"])


def _analyze_flow(db: Session, flow: dict) -> models.TrafficLog:
    ai_result = ai_predict(flow)
    decision = rules_engine.decide(db, flow["src_ip"], ai_result)

    log = models.TrafficLog(
        src_ip=flow["src_ip"],
        dst_ip=flow.get("dst_ip", "10.0.0.1"),
        src_port=flow.get("src_port"),
        dst_port=flow.get("dst_port"),
        protocol=flow.get("protocol"),
        features=flow,
        label=ai_result["label"],
        confidence=ai_result["confidence"],
        verdict=decision["verdict"],
        reason=decision["reason"],
    )
    db.add(log)
    db.commit()
    db.refresh(log)
    return log


@router.post("/analyze", response_model=schemas.AnalyzeResult)
def analyze(flow: schemas.FlowIn, db: Session = Depends(get_db)):
    log = _analyze_flow(db, flow.model_dump())
    return log


@router.post("/simulate", response_model=schemas.AnalyzeResult)
def simulate(db: Session = Depends(get_db)):
    """Generate one random flow (benign / port-scan / DoS-like) and analyze it."""
    flow = simulator.random_flow()
    log = _analyze_flow(db, flow)
    return log


@router.post("/simulate_batch")
def simulate_batch(count: int = 10, db: Session = Depends(get_db)):
    """Generate several random flows at once, useful for demo-ing the dashboard."""
    results = []
    for _ in range(min(count, 200)):
        flow = simulator.random_flow()
        log = _analyze_flow(db, flow)
        results.append(log.id)
    return {"created": len(results), "log_ids": results}
