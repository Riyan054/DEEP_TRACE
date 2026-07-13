from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

class PacketBase(BaseModel):
    timestamp: float
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    size: int
    ttl: Optional[int] = None
    flags: Optional[str] = None
    payload_len: int
    payload: Optional[str] = None

class PacketCreate(PacketBase):
    is_anomaly: bool = False
    anomaly_score: float = 0.0
    anomaly_reason: Optional[str] = None
    severity: str = "Safe"

class PacketSchema(PacketBase):
    id: int
    is_anomaly: bool
    anomaly_score: float
    anomaly_reason: Optional[str]
    severity: str

    class Config:
        from_attributes = True


class AlertBase(BaseModel):
    timestamp: float
    severity: str
    attack_type: str
    reason: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    packet_id: Optional[int] = None
    is_resolved: bool = False

class AlertSchema(AlertBase):
    id: int

    class Config:
        from_attributes = True


class SystemLogSchema(BaseModel):
    id: int
    timestamp: float
    level: str
    component: str
    message: str

    class Config:
        from_attributes = True


class AuditLogSchema(BaseModel):
    id: int
    timestamp: float
    user_action: str
    details: Optional[str] = None

    class Config:
        from_attributes = True


class SnifferControlSchema(BaseModel):
    action: str  # start, stop, pause, resume
    interface: Optional[str] = None
    pcap_path: Optional[str] = None  # For offline PCAP replay/analysis
    replay_speed: Optional[float] = 1.0  # Speed multiplier for replay

class SettingsSchema(BaseModel):
    mock_mode: bool
    refresh_rate: float
    packet_limit: int
    active_model: str
    interface: str
    notification_toggle: bool

class MLMetricsSchema(BaseModel):
    model_name: str
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    training_time: float
    trained_at: float
    samples_count: int

class ModelComparisonSchema(BaseModel):
    models: List[MLMetricsSchema]
    active_model: str

class SystemMetricsSchema(BaseModel):
    cpu_usage: float
    ram_usage: float
    disk_usage: float
    uptime: float
    sniffer_status: str  # running, stopped, paused
    db_status: str       # connected, error
    ml_status: str       # trained, untrained, error
    active_interface: str
