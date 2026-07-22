from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, JSON
from database import Base


class TrafficLog(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    src_ip = Column(String, index=True)
    dst_ip = Column(String, index=True)
    src_port = Column(Integer)
    dst_port = Column(Integer)
    protocol = Column(String)
    features = Column(JSON)
    label = Column(String)          # "benign" | "malicious"
    confidence = Column(Float)
    verdict = Column(String)        # "ALLOW" | "BLOCK"
    reason = Column(String)         # why the verdict was reached


class BlockedIP(Base):
    __tablename__ = "blocked_ips"

    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String, unique=True, index=True)
    blocked_at = Column(DateTime, default=datetime.utcnow)
    reason = Column(String)
    auto = Column(Boolean, default=True)   # auto-blocked by AI vs manual


class Rule(Base):
    __tablename__ = "rules"

    id = Column(Integer, primary_key=True, index=True)
    rule_type = Column(String)      # "allow_ip" | "deny_ip" | "threshold"
    value = Column(String)          # IP for allow/deny, numeric string for threshold
    description = Column(String, default="")
    created_at = Column(DateTime, default=datetime.utcnow)
