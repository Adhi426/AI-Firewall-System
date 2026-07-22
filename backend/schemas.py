from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel


class FlowIn(BaseModel):
    src_ip: str
    dst_ip: str = "10.0.0.1"
    duration_ms: float
    packet_count: float
    byte_count: float
    packets_per_sec: float
    avg_packet_size: float
    src_port: int
    dst_port: int
    protocol: str = "TCP"          # "TCP" | "UDP" | "ICMP"
    syn_ratio: float = 0.0
    unique_ports_touched: int = 1


class AnalyzeResult(BaseModel):
    id: int
    timestamp: datetime
    src_ip: str
    dst_ip: str
    label: str
    confidence: float
    verdict: str
    reason: str

    class Config:
        from_attributes = True


class RuleIn(BaseModel):
    rule_type: str                 # "allow_ip" | "deny_ip" | "threshold"
    value: str
    description: Optional[str] = ""


class RuleOut(RuleIn):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True


class BlockedIPOut(BaseModel):
    id: int
    ip: str
    blocked_at: datetime
    reason: str
    auto: bool

    class Config:
        from_attributes = True
