from sqlalchemy import Column, Integer, String, Float, Text, DateTime, Boolean, JSON
from sqlalchemy.sql import func
from app.database import Base

class Case(Base):
    __tablename__ = "cases"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(String(64), unique=True, index=True, nullable=False)
    subject = Column(String(512))
    sender = Column(String(256))
    recipient = Column(String(256))
    raw_headers = Column(Text)
    body_text = Column(Text)
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String(16), default="LOW")
    risk_factors = Column(JSON, default=list)
    urls = Column(JSON, default=list)
    domains = Column(JSON, default=list)
    ips = Column(JSON, default=list)
    geo_locations = Column(JSON, default=list)
    recommendation = Column(String(32), default="ALLOW")
    blockchain_tx = Column(String(128), nullable=True)
    blockchain_hash = Column(String(128), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    is_reported = Column(Boolean, default=False)
    report_id = Column(String(64), nullable=True)
    # Salt + pepper stored for ID recovery and forensic audit
    case_salt = Column(String(16), nullable=True)
    case_pepper = Column(String(16), nullable=True)
    # Canary / Honeytoken trap fields
    canary_token = Column(String(64), nullable=True)    # active canary token for this case
    canary_hits = Column(JSON, default=list)            # list of beacon hit records
    evidence_hash = Column(String(64), nullable=True)   # SHA-256 of assembled evidence

class ThreatIntelCache(Base):
    __tablename__ = "threat_intel_cache"

    id = Column(Integer, primary_key=True)
    ioc = Column(String(512), unique=True, index=True)
    ioc_type = Column(String(32))  # url, domain, ip
    is_malicious = Column(Boolean, default=False)
    source = Column(String(64))
    raw = Column(JSON)
    checked_at = Column(DateTime(timezone=True), server_default=func.now())
