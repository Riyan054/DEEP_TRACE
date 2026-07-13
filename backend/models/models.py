import time
from sqlalchemy import Column, Integer, String, Float, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from backend.database.db import Base

class Packet(Base):
    __tablename__ = "packets"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(Float, default=time.time, index=True)
    protocol = Column(String, index=True)
    src_ip = Column(String, index=True)
    dst_ip = Column(String, index=True)
    src_port = Column(Integer, nullable=True, index=True)
    dst_port = Column(Integer, nullable=True, index=True)
    size = Column(Integer)
    ttl = Column(Integer, nullable=True)
    flags = Column(String, nullable=True)
    payload_len = Column(Integer, default=0)
    payload = Column(String, nullable=True)
    is_anomaly = Column(Boolean, default=False, index=True)
    anomaly_score = Column(Float, default=0.0)
    anomaly_reason = Column(String, nullable=True)
    severity = Column(String, default="Safe", index=True)  # Safe, Suspicious, Dangerous

    alerts = relationship("Alert", back_populates="packet", cascade="all, delete-orphan")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(Float, default=time.time, index=True)
    severity = Column(String, index=True)  # Info, Warning, Critical
    attack_type = Column(String, index=True)  # Port Scan, DoS, Brute Force, etc.
    reason = Column(String)
    src_ip = Column(String, nullable=True, index=True)
    dst_ip = Column(String, nullable=True, index=True)
    packet_id = Column(Integer, ForeignKey("packets.id", ondelete="CASCADE"), nullable=True)
    is_resolved = Column(Boolean, default=False)

    packet = relationship("Packet", back_populates="alerts")


class SystemLog(Base):
    __tablename__ = "system_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(Float, default=time.time, index=True)
    level = Column(String, index=True)  # INFO, WARNING, ERROR
    component = Column(String, index=True)  # Sniffer, ML Engine, Database, API
    message = Column(String)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(Float, default=time.time, index=True)
    user_action = Column(String, index=True)  # e.g., "Started sniffer", "Retrained ML"
    details = Column(String, nullable=True)
