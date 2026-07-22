from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func

import models
import schemas
from database import get_db

router = APIRouter(prefix="/api", tags=["logs"])


@router.get("/logs", response_model=list[schemas.AnalyzeResult])
def get_logs(limit: int = 100, db: Session = Depends(get_db)):
    return (
        db.query(models.TrafficLog)
        .order_by(models.TrafficLog.timestamp.desc())
        .limit(min(limit, 500))
        .all()
    )


@router.get("/blocked", response_model=list[schemas.BlockedIPOut])
def get_blocked(db: Session = Depends(get_db)):
    return db.query(models.BlockedIP).order_by(models.BlockedIP.blocked_at.desc()).all()


@router.post("/blocked/{ip}/unblock")
def unblock_ip(ip: str, db: Session = Depends(get_db)):
    entry = db.query(models.BlockedIP).filter(models.BlockedIP.ip == ip).first()
    if not entry:
        raise HTTPException(404, "ip not found in blocklist")
    db.delete(entry)
    db.commit()
    return {"unblocked": ip}


@router.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    total = db.query(func.count(models.TrafficLog.id)).scalar() or 0
    blocked = db.query(func.count(models.TrafficLog.id)).filter(
        models.TrafficLog.verdict == "BLOCK"
    ).scalar() or 0
    allowed = total - blocked
    malicious = db.query(func.count(models.TrafficLog.id)).filter(
        models.TrafficLog.label == "malicious"
    ).scalar() or 0
    blocked_ips = db.query(func.count(models.BlockedIP.id)).scalar() or 0

    return {
        "total_flows": total,
        "allowed": allowed,
        "blocked": blocked,
        "malicious_detected": malicious,
        "currently_blocked_ips": blocked_ips,
    }
