import os
import shutil
import tempfile
from fastapi import APIRouter, Depends, Query, HTTPException, UploadFile, File, Request, status
from fastapi.responses import Response, FileResponse, StreamingResponse
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any

from backend.database.db import get_db
from backend.models.models import Packet, Alert, SystemLog, AuditLog
from backend.schemas.schemas import (
    PacketSchema, AlertSchema, SnifferControlSchema, SettingsSchema,
    SystemMetricsSchema
)
from backend.reports.generator import ReportGenerator
from backend.utils.metrics import get_system_resource_metrics

router = APIRouter(prefix="/api")

# Helper to log audits
def log_audit(db: Session, action: str, details: str = None):
    try:
        audit = AuditLog(timestamp=time_time(), user_action=action, details=details)
        db.add(audit)
        db.commit()
    except Exception as e:
        print(f"Failed audit log: {e}")

# Injecting python's time
from time import time as time_time

@router.get("/interfaces", response_model=List[str])
def get_interfaces(request: Request):
    """Retrieve list of available network interfaces."""
    sniffer = request.app.state.sniffer
    return sniffer.get_interfaces()

@router.post("/sniffer/control")
def control_sniffer(control: SnifferControlSchema, request: Request, db: Session = Depends(get_db)):
    """Start, Stop, Pause, or Resume packet sniffing."""
    sniffer = request.app.state.sniffer
    action = control.action.lower()
    
    if action == "start":
        if control.interface:
            sniffer.set_interface(control.interface)
        sniffer.start()
        log_audit(db, "Start Sniffer", f"Interface: {sniffer.interface}")
    elif action == "stop":
        sniffer.stop()
        log_audit(db, "Stop Sniffer")
    elif action == "pause":
        sniffer.pause()
        log_audit(db, "Pause Sniffer")
    elif action == "resume":
        sniffer.resume()
        log_audit(db, "Resume Sniffer")
    else:
        raise HTTPException(status_code=400, detail="Invalid action. Use start, stop, pause, or resume.")
        
    return {"status": "success", "sniffer_status": "running" if sniffer.running and not sniffer.paused else "paused" if sniffer.paused else "stopped"}

@router.get("/sniffer/status")
def get_sniffer_status(request: Request):
    """Get the running status and parameters of the sniffer."""
    sniffer = request.app.state.sniffer
    state = "stopped"
    if sniffer.running:
        state = "paused" if sniffer.paused else "running"
    return {
        "status": state,
        "interface": sniffer.interface,
        "mock_mode": sniffer.mock_mode,
        "packets_captured": sniffer.packets_captured_count
    }

@router.get("/packets", response_model=Dict[str, Any])
def get_packets(
    request: Request,
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=1000),
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    port: Optional[int] = None,
    protocol: Optional[str] = None,
    severity: Optional[str] = None,
    is_anomaly: Optional[bool] = None,
    db: Session = Depends(get_db)
):
    """Search and filter through archived packets."""
    query = db.query(Packet)
    
    if src_ip:
        query = query.filter(Packet.src_ip.like(f"%{src_ip}%"))
    if dst_ip:
        query = query.filter(Packet.dst_ip.like(f"%{dst_ip}%"))
    if port:
        query = query.filter((Packet.src_port == port) | (Packet.dst_port == port))
    if protocol:
        query = query.filter(Packet.protocol.iexact(protocol))
    if severity:
        query = query.filter(Packet.severity.iexact(severity))
    if is_anomaly is not None:
        query = query.filter(Packet.is_anomaly == is_anomaly)
        
    total = query.count()
    packets = query.order_by(Packet.timestamp.desc()).offset((page - 1) * limit).limit(limit).all()
    
    return {
        "total": total,
        "page": page,
        "limit": limit,
        "packets": packets
    }

@router.get("/alerts", response_model=List[AlertSchema])
def get_alerts(
    severity: Optional[str] = None,
    attack_type: Optional[str] = None,
    resolved: Optional[bool] = None,
    db: Session = Depends(get_db)
):
    """Retrieve security alerts filtered by properties."""
    query = db.query(Alert)
    
    if severity:
        query = query.filter(Alert.severity.iexact(severity))
    if attack_type:
        query = query.filter(Alert.attack_type.like(f"%{attack_type}%"))
    if resolved is not None:
        query = query.filter(Alert.is_resolved == resolved)
        
    return query.order_by(Alert.timestamp.desc()).limit(100).all()

@router.post("/alerts/{alert_id}/resolve")
def resolve_alert(alert_id: int, db: Session = Depends(get_db)):
    """Mark a security alert as resolved."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.is_resolved = True
    db.commit()
    log_audit(db, "Resolve Alert", f"Alert ID: {alert_id}")
    return {"status": "success", "alert_id": alert_id}

@router.get("/settings", response_model=SettingsSchema)
def get_settings(request: Request):
    """Retrieve global network analyzer configuration."""
    sniffer = request.app.state.sniffer
    return {
        "mock_mode": sniffer.mock_mode,
        "refresh_rate": 1.0,
        "packet_limit": sniffer.packet_limit,
        "active_model": "Signature-based",
        "interface": sniffer.interface,
        "notification_toggle": True
    }

@router.post("/settings/update")
def update_settings(settings: SettingsSchema, request: Request, db: Session = Depends(get_db)):
    """Update global configuration parameters dynamically."""
    sniffer = request.app.state.sniffer
    
    # Apply changes
    sniffer.set_mock_mode(settings.mock_mode)
    sniffer.set_interface(settings.interface)
    sniffer.packet_limit = settings.packet_limit
    
    log_audit(db, "Update Settings", f"Mock: {settings.mock_mode}, Interface: {settings.interface}")
    return {"status": "success", "settings": settings}

@router.post("/dashboard/reset")
def reset_dashboard(request: Request, db: Session = Depends(get_db)):
    """Purge packets and alerts history to start fresh."""
    sniffer = request.app.state.sniffer
    success = sniffer.reset_stats()
    if not success:
        raise HTTPException(status_code=500, detail="Failed to purge database records.")
    log_audit(db, "Reset Dashboard")
    return {"status": "success"}

@router.get("/reports/generate")
def generate_report(type: str = Query("pdf", pattern="^(pdf|csv|json)$"), db: Session = Depends(get_db)):
    """Download system diagnostic reports in PDF, CSV, or JSON formats."""
    try:
        if type == "json":
            json_str = ReportGenerator.generate_json()
            return Response(content=json_str, media_type="application/json", headers={"Content-Disposition": "attachment;filename=nads_report.json"})
        elif type == "csv":
            csv_str = ReportGenerator.generate_csv()
            return Response(content=csv_str, media_type="text/csv", headers={"Content-Disposition": "attachment;filename=nads_alerts.csv"})
        else:
            pdf_bytes = ReportGenerator.generate_pdf()
            return Response(content=pdf_bytes, media_type="application/pdf", headers={"Content-Disposition": "attachment;filename=nads_report.pdf"})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report construction failed: {str(e)}")

@router.post("/pcap/upload")
def upload_pcap(request: Request, file: UploadFile = File(...), db: Session = Depends(get_db)):
    """Upload and analyze offline PCAP packet captures."""
    sniffer = request.app.state.sniffer
    if not file.filename.endswith(('.pcap', '.pcapng')):
        raise HTTPException(status_code=400, detail="File extension must be .pcap or .pcapng")
        
    temp_dir = tempfile.gettempdir()
    temp_file_path = os.path.join(temp_dir, file.filename)
    
    try:
        with open(temp_file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
            
        result = sniffer.parse_offline_pcap(temp_file_path)
        log_audit(db, "Upload PCAP", f"Filename: {file.filename}")
        
        # Cleanup
        os.remove(temp_file_path)
        return result
    except Exception as e:
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)
        raise HTTPException(status_code=500, detail=f"PCAP upload parse failed: {str(e)}")

@router.post("/pcap/replay")
def replay_pcap(payload: Dict[str, Any], request: Request, db: Session = Depends(get_db)):
    """Replay standard packet dump files back through sniffer."""
    sniffer = request.app.state.sniffer
    pcap_name = payload.get("filename")
    speed = float(payload.get("speed", 1.0))
    
    if not pcap_name:
        raise HTTPException(status_code=400, detail="pcap filename is required")
        
    # Search in default scratch space or uploaded directory
    pcap_path = os.path.join(tempfile.gettempdir(), pcap_name)
    if not os.path.exists(pcap_path):
        raise HTTPException(status_code=404, detail=f"PCAP file '{pcap_name}' not found.")
        
    # Stop active sniffer and start replay thread
    sniffer.stop()
    sniffer.start() # Reset active state
    sniffer.replay_pcap(pcap_path, speed)
    log_audit(db, "Replay PCAP", f"Filename: {pcap_name}, Speed: {speed}x")
    return {"status": "success"}

@router.get("/system/metrics", response_model=SystemMetricsSchema)
def get_system_metrics(request: Request, db: Session = Depends(get_db)):
    """Retrieve operational health, uptime, and hardware resource allocations."""
    sniffer = request.app.state.sniffer
    
    resources = get_system_resource_metrics()
    
    # Check DB status
    db_status = "connected"
    try:
        db.execute(db.select(1))
    except Exception:
        db_status = "error"
        
    # ML status
    ml_status = "disabled"
    
    sniffer_state = "stopped"
    if sniffer.running:
        sniffer_state = "paused" if sniffer.paused else "running"

    return {
        "cpu_usage": resources["cpu_usage"],
        "ram_usage": resources["ram_usage"],
        "disk_usage": resources["disk_usage"],
        "uptime": resources["uptime"],
        "sniffer_status": sniffer_state,
        "db_status": db_status,
        "ml_status": ml_status,
        "active_interface": sniffer.interface
    }

@router.get("/logs/system")
def get_system_logs(
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db)
):
    """Retrieve system diagnostics logs from database."""
    return db.query(SystemLog).order_by(SystemLog.timestamp.desc()).limit(limit).all()

@router.get("/logs/audit")
def get_audit_logs(
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db)
):
    """Retrieve user and capture audit logs from database."""
    return db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit).all()

