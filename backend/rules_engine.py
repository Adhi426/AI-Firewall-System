"""
Decides ALLOW / BLOCK for a flow, given the AI verdict and the currently
configured rules (allow-list, deny-list, block-confidence-threshold).
"""
from sqlalchemy.orm import Session
import models

DEFAULT_THRESHOLD = 0.75


def get_threshold(db: Session) -> float:
    rule = db.query(models.Rule).filter(models.Rule.rule_type == "threshold").first()
    if rule:
        try:
            return float(rule.value)
        except ValueError:
            pass
    return DEFAULT_THRESHOLD


def is_allow_listed(db: Session, ip: str) -> bool:
    return db.query(models.Rule).filter(
        models.Rule.rule_type == "allow_ip", models.Rule.value == ip
    ).first() is not None


def is_deny_listed(db: Session, ip: str) -> bool:
    return db.query(models.Rule).filter(
        models.Rule.rule_type == "deny_ip", models.Rule.value == ip
    ).first() is not None


def is_blocked(db: Session, ip: str) -> bool:
    return db.query(models.BlockedIP).filter(models.BlockedIP.ip == ip).first() is not None


def decide(db: Session, src_ip: str, ai_result: dict) -> dict:
    """
    Returns { verdict: "ALLOW"|"BLOCK", reason: str }
    Also auto-blocks the source IP when the AI confidence crosses threshold.
    """
    if is_allow_listed(db, src_ip):
        return {"verdict": "ALLOW", "reason": "source IP is allow-listed"}

    if is_deny_listed(db, src_ip) or is_blocked(db, src_ip):
        return {"verdict": "BLOCK", "reason": "source IP is deny-listed / already blocked"}

    threshold = get_threshold(db)
    if ai_result["label"] == "malicious" and ai_result["confidence"] >= threshold:
        # auto-block
        existing = db.query(models.BlockedIP).filter(models.BlockedIP.ip == src_ip).first()
        if not existing:
            db.add(models.BlockedIP(
                ip=src_ip,
                reason=f"AI flagged malicious with confidence {ai_result['confidence']}",
                auto=True,
            ))
            db.commit()
        return {
            "verdict": "BLOCK",
            "reason": f"AI confidence {ai_result['confidence']} >= threshold {threshold}",
        }

    return {"verdict": "ALLOW", "reason": "AI did not flag this flow as malicious"}
