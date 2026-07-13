import asyncio
import json
import time
import queue
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from typing import List, Set, Dict, Any
from sqlalchemy.orm import Session

from backend.database.db import SessionLocal
from backend.models.models import Packet, Alert
from backend.utils.metrics import get_system_resource_metrics

router = APIRouter()

class ConnectionManager:
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception:
                # Handle stale connections
                pass

manager = ConnectionManager()

# Background broadcast loop
async def websocket_broadcaster(app):
    """
    Background worker that aggregates packet rates, bandwidth,
    system metrics, and alerts, and broadcasts updates over WebSockets.
    """
    print("WebSocket broadcaster loop initiated")
    sniffer = app.state.sniffer
    
    # Track bandwidth and packet count in sliding 1-second interval
    pps_window = []
    bandwidth_window = []
    
    while True:
        try:
            # Sleep matching refresh rate
            await asyncio.sleep(1.0)
            
            if not manager.active_connections:
                # Drain queue if no one is listening to avoid memory bloat
                while not sniffer.packet_queue.empty():
                    try:
                        sniffer.packet_queue.get_nowait()
                    except Exception:
                        pass
                continue
                
            # Collect all packets in queue since last broadcast
            current_packets = []
            bytes_in_second = 0
            while not sniffer.packet_queue.empty():
                try:
                    pkt = sniffer.packet_queue.get_nowait()
                    current_packets.append(pkt)
                    bytes_in_second += pkt["size"]
                except queue.Empty:
                    break
                except Exception:
                    break

            # Calculate PPS and Bandwidth
            now = time.time()
            pps_window.append((now, len(current_packets)))
            bandwidth_window.append((now, bytes_in_second))
            
            # Prune sliding window older than 10 seconds
            pps_window = [w for w in pps_window if now - w[0] <= 10.0]
            bandwidth_window = [w for w in bandwidth_window if now - w[0] <= 10.0]
            
            # Calculate averages
            tot_p = sum(w[1] for w in pps_window)
            tot_b = sum(w[1] for w in bandwidth_window)
            count_w = len(pps_window)
            
            avg_pps = tot_p / count_w if count_w > 0 else 0.0
            avg_bps = tot_b / count_w if count_w > 0 else 0.0
            avg_kbps = (avg_bps * 8) / 1000.0 # Convert to kilobits per second

            # Fetch analytics from Database
            db: Session = SessionLocal()
            try:
                # System Resources
                resources = get_system_resource_metrics()
                resources["active_interface"] = sniffer.interface
                
                # Check DB status
                db_status = "connected"
                try:
                    db.execute(db.select(1))
                except Exception:
                    db_status = "error"
                resources["db_status"] = db_status
                
                # Check ML status
                ml_status = "disabled"
                resources["ml_status"] = ml_status
                
                # Sniffer details
                state = "stopped"
                if sniffer.running:
                    state = "paused" if sniffer.paused else "running"
                resources["sniffer_status"] = state
                
                # Fetch recent packets (e.g., last 100) for distribution statistics
                last_packets = db.query(Packet).order_by(Packet.timestamp.desc()).limit(150).all()
                total_inspect = len(last_packets)
                
                # Build live stats
                protocols = {}
                severities = {"Safe": 0, "Suspicious": 0, "Dangerous": 0}
                anomalies_count = 0
                
                src_ips = {}
                dst_ips = {}
                
                for p in last_packets:
                    protocols[p.protocol] = protocols.get(p.protocol, 0) + 1
                    severities[p.severity] = severities.get(p.severity, 0) + 1
                    if p.is_anomaly:
                        anomalies_count += 1
                    src_ips[p.src_ip] = src_ips.get(p.src_ip, 0) + 1
                    dst_ips[p.dst_ip] = dst_ips.get(p.dst_ip, 0) + 1

                # Sort top sources/destinations
                top_sources = sorted([{"ip": ip, "count": c} for ip, c in src_ips.items()], key=lambda x: x["count"], reverse=True)[:5]
                top_destinations = sorted([{"ip": ip, "count": c} for ip, c in dst_ips.items()], key=lambda x: x["count"], reverse=True)[:5]
                
                # Compute network health score (percent safe packets in last 100)
                network_health = 100
                if total_inspect > 0:
                    network_health = int(((total_inspect - anomalies_count) / total_inspect) * 100)
                    
                # Threat meter is direct inverse
                threat_level = 100 - network_health

                # Fetch 5 most recent unresolved alerts
                recent_alerts = db.query(Alert).filter(Alert.is_resolved == False).order_by(Alert.timestamp.desc()).limit(10).all()
                alerts_data = [
                    {
                        "id": a.id,
                        "timestamp": a.timestamp,
                        "severity": a.severity,
                        "attack_type": a.attack_type,
                        "reason": a.reason,
                        "src_ip": a.src_ip,
                        "dst_ip": a.dst_ip
                    }
                    for a in recent_alerts
                ]

                # Compose payload
                payload = {
                    "type": "dashboard_update",
                    "timestamp": now,
                    "packets": current_packets, # Latest packets captured in this second
                    "resources": resources,
                    "stats": {
                        "pps": round(avg_pps, 1),
                        "kbps": round(avg_kbps, 1),
                        "network_health": network_health,
                        "threat_level": threat_level,
                        "protocols": protocols,
                        "severities": severities,
                        "top_sources": top_sources,
                        "top_destinations": top_destinations,
                        "alerts": alerts_data,
                        "total_captured": sniffer.packets_captured_count
                    }
                }
                
                await manager.broadcast(json.dumps(payload))
                
            except Exception as db_err:
                print(f"Error in broadcast db processing: {db_err}")
            finally:
                db.close()
                
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"WS broadcast loop encountered error: {e}")
            await asyncio.sleep(2.0)

@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """Endpoint for frontend clients to establish websocket dashboard subscriptions."""
    await manager.connect(websocket)
    try:
        while True:
            # We don't expect messages from client, but keep loop open to monitor disconnects
            data = await websocket.receive_text()
            # If client sends a ping, reply pong
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)
