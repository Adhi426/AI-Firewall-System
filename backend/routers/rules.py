from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

import models
import schemas
from database import get_db

router = APIRouter(prefix="/api/rules", tags=["rules"])


@router.get("", response_model=list[schemas.RuleOut])
def list_rules(db: Session = Depends(get_db)):
    return db.query(models.Rule).order_by(models.Rule.created_at.desc()).all()


@router.post("", response_model=schemas.RuleOut)
def create_rule(rule: schemas.RuleIn, db: Session = Depends(get_db)):
    if rule.rule_type not in ("allow_ip", "deny_ip", "threshold"):
        raise HTTPException(400, "rule_type must be allow_ip, deny_ip, or threshold")

    # only one active threshold rule at a time
    if rule.rule_type == "threshold":
        existing = db.query(models.Rule).filter(models.Rule.rule_type == "threshold").first()
        if existing:
            existing.value = rule.value
            existing.description = rule.description
            db.commit()
            db.refresh(existing)
            return existing

    db_rule = models.Rule(**rule.model_dump())
    db.add(db_rule)
    db.commit()
    db.refresh(db_rule)
    return db_rule


@router.delete("/{rule_id}")
def delete_rule(rule_id: int, db: Session = Depends(get_db)):
    rule = db.query(models.Rule).filter(models.Rule.id == rule_id).first()
    if not rule:
        raise HTTPException(404, "rule not found")
    db.delete(rule)
    db.commit()
    return {"deleted": rule_id}
