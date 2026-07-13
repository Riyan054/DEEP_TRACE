import os
import sys
import time
import socket
import threading
import queue
import random
import traceback
from typing import List, Dict, Any, Optional, Tuple
import psutil

# Ensure scapy doesn't print warnings on startup
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Raw, get_if_list, Ether

# Add project root to sys.path if not present
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from backend.database.db import SessionLocal
from backend.models.models import Packet, Alert, SystemLog
from backend.utils.config import MOCK_MODE, PACKET_LIMIT

class PacketSniffer:
    def __init__(self):
        self.interface = "en0"
        self.mock_mode = MOCK_MODE
        self.packet_limit = PACKET_LIMIT
        self.running = False
        self.paused = False
        
        self._thread: Optional[threading.Thread] = None
        self._mock_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        
        self.packet_queue = queue.Queue(maxsize=1000)
        self.lock = threading.Lock()
        
        # Stats tracking
        self.packets_captured_count = 0
        self.recent_ips = {}
        self.port_scan_tracker = {} # {src_ip: set(dst_ports)}
        self.packet_rate_tracker = {} # {src_ip: [timestamps]}

    def get_interfaces(self) -> List[str]:
        """Fetch all available network interfaces on the system."""
        try:
            # Scapy's list
            scapy_ifs = get_if_list()
            # psutil's list
            psutil_ifs = list(psutil.net_if_addrs().keys())
            # Union of both
            interfaces = sorted(list(set(scapy_ifs + psutil_ifs)))
            # Exclude loopback if there are other interfaces, or keep it
            return interfaces if interfaces else ["lo0", "eth0", "en0"]
        except Exception as e:
            print(f"Error getting interfaces: {e}")
            return ["lo0", "eth0", "en0", "wlan0"]

    def set_interface(self, interface: str):
        """Set the active network interface."""
        with self.lock:
            self.interface = interface

    def set_mock_mode(self, enabled: bool):
        """Enable or disable mock traffic generation."""
        with self.lock:
            self.mock_mode = enabled
            self.log_system_event("Sniffer", "INFO", f"Mock capture mode set to: {enabled}")

    def log_system_event(self, component: str, level: str, message: str):
        """Utility to log system events directly to DB."""
        db = SessionLocal()
        try:
            log = SystemLog(timestamp=time.time(), level=level, component=component, message=message)
            db.add(log)
            db.commit()
        except Exception as e:
            print(f"Failed to write system log: {e}")
        finally:
            db.close()

    def start(self):
        """Start capturing packets in a background thread."""
        with self.lock:
            if self.running:
                return
            
            self.running = True
            self.paused = False
            self._stop_event.clear()
            
            self.log_system_event("Sniffer", "INFO", f"Starting packet sniffer (Mock mode: {self.mock_mode}, Interface: {self.interface})")
            
            if self.mock_mode:
                self._mock_thread = threading.Thread(target=self._run_mock_generator, daemon=True)
                self._mock_thread.start()
            else:
                self._thread = threading.Thread(target=self._run_sniff, daemon=True)
                self._thread.start()

    def stop(self):
        """Stop packet capture threads."""
        with self.lock:
            if not self.running:
                return
            
            self.running = False
            self.paused = False
            self._stop_event.set()
            
            self.log_system_event("Sniffer", "INFO", "Stopping packet sniffer engine")

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)
        if self._mock_thread and self._mock_thread.is_alive():
            self._mock_thread.join(timeout=1.0)

    def pause(self):
        """Pause packet stream ingestion."""
        with self.lock:
            if self.running and not self.paused:
                self.paused = True
                self.log_system_event("Sniffer", "INFO", "Packet capture stream paused")

    def resume(self):
        """Resume packet stream ingestion."""
        with self.lock:
            if self.running and self.paused:
                self.paused = False
                self.log_system_event("Sniffer", "INFO", "Packet capture stream resumed")

    def reset_stats(self):
        """Clear database packets and statistics."""
        db = SessionLocal()
        try:
            db.query(Packet).delete()
            db.query(Alert).delete()
            db.commit()
            self.packets_captured_count = 0
            self.recent_ips.clear()
            self.port_scan_tracker.clear()
            self.packet_rate_tracker.clear()
            self.log_system_event("Database", "INFO", "Database cache and dashboards reset")
            return True
        except Exception as e:
            db.rollback()
            self.log_system_event("Database", "ERROR", f"Failed to reset database: {str(e)}")
            return False
        finally:
            db.close()

    def _run_sniff(self):
        """Live packet sniffing thread (using Scapy)."""
        try:
            def packet_callback(pkt):
                if self._stop_event.is_set():
                    return True  # Tells scapy to stop sniffing
                
                if self.paused:
                    return
                
                try:
                    self._process_scapy_packet(pkt)
                except Exception as e:
                    print(f"Error processing packet: {e}")
                
            # Attempt to run scapy sniff. This requires root permissions on some OS.
            sniff(iface=self.interface, prn=packet_callback, store=0, stop_filter=lambda p: self._stop_event.is_set())
        except Exception as e:
            self.log_system_event("Sniffer", "ERROR", f"Live sniff failed (likely permission error). Falling back to Mock traffic: {str(e)}")
            # Auto fallback to Mock mode
            with self.lock:
                self.mock_mode = True
                self._mock_thread = threading.Thread(target=self._run_mock_generator, daemon=True)
                self._mock_thread.start()

    def _process_scapy_packet(self, pkt):
        """Extract features and process a scapy packet."""
        if not pkt.haslayer(IP):
            return

        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "ICMP" if pkt.haslayer(ICMP) else "OTHER"
        
        src_port = None
        dst_port = None
        flags = ""
        ttl = ip_layer.ttl
        size = len(pkt)
        
        if pkt.haslayer(TCP):
            tcp_layer = pkt[TCP]
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            flags = str(tcp_layer.flags)
        elif pkt.haslayer(UDP):
            udp_layer = pkt[UDP]
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            
        payload_len = 0
        payload_str = ""
        if pkt.haslayer(Raw):
            payload_len = len(pkt[Raw].load)
            try:
                payload_str = pkt[Raw].load.decode('utf-8', errors='ignore')[:200]
            except Exception:
                payload_str = str(pkt[Raw].load)[:200]

        # Populate basic packet info for detector/DB
        pkt_dict = {
            "timestamp": time.time(),
            "protocol": proto,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "size": size,
            "ttl": ttl,
            "flags": flags,
            "payload_len": payload_len,
            "payload": payload_str,
            "packet_rate": self._compute_packet_rate(src_ip)
        }

        self._evaluate_and_save_packet(pkt_dict)

    def _compute_packet_rate(self, src_ip: str) -> float:
        """Dynamically compute packets/sec for a source IP inside a sliding window."""
        now = time.time()
        if src_ip not in self.packet_rate_tracker:
            self.packet_rate_tracker[src_ip] = []
        
        # Add current timestamp
        self.packet_rate_tracker[src_ip].append(now)
        # Prune older than 5 seconds
        self.packet_rate_tracker[src_ip] = [t for t in self.packet_rate_tracker[src_ip] if now - t <= 5.0]
        
        count = len(self.packet_rate_tracker[src_ip])
        return count / 5.0 if count > 0 else 0.0

    def _evaluate_packet_anomaly(self, pkt: Dict[str, Any]) -> Tuple[bool, float, Optional[str]]:
        """Signature-based anomaly analyzer."""
        size = pkt.get("size") or 0
        flags = pkt.get("flags") or ""
        dst_port = pkt.get("dst_port") or 0
        rate = pkt.get("packet_rate") or 10.0
        proto = str(pkt.get("protocol", "")).upper()

        # Check for malformed packet
        if size > 65535 or size < 20:
            return True, 0.9, "Malformed Packet"
        # Check Large payload
        if size > 1500:
            return True, 0.75, "Large Payload"
        # Port scan signature
        if "S" in flags and dst_port in [21, 22, 23, 135, 139, 445, 3389] and rate > 50:
            return True, 0.85, "Port Scan"
        # DoS check
        if rate > 200:
            return True, 0.95, "DoS"
        
        # Check for abnormal protocol
        if proto not in ["TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP", "TLS", "OTHER"]:
            return True, 0.7, "Unknown Protocol"

        return False, 0.0, None

    def _evaluate_and_save_packet(self, pkt_dict: Dict[str, Any]):
        """Evaluate packet using signature rules, save to SQLite, trigger alerts and push to WebSocket queue."""
        db = SessionLocal()
        try:
            # 1. Run Signature-based anomaly detection
            is_anomaly, anomaly_score, anomaly_reason = self._evaluate_packet_anomaly(pkt_dict)
            
            # 2. Threat classification
            severity = "Safe"
            if is_anomaly:
                if anomaly_reason in ["DoS", "Port Scan"]:
                    severity = "Dangerous"
                else:
                    severity = "Suspicious"
                
            # Create DB Model
            db_packet = Packet(
                timestamp=pkt_dict["timestamp"],
                protocol=pkt_dict["protocol"],
                src_ip=pkt_dict["src_ip"],
                dst_ip=pkt_dict["dst_ip"],
                src_port=pkt_dict["src_port"],
                dst_port=pkt_dict["dst_port"],
                size=pkt_dict["size"],
                ttl=pkt_dict["ttl"],
                flags=pkt_dict["flags"],
                payload_len=pkt_dict["payload_len"],
                payload=pkt_dict["payload"],
                is_anomaly=is_anomaly,
                anomaly_score=anomaly_score,
                anomaly_reason=anomaly_reason,
                severity=severity
            )
            
            db.add(db_packet)
            db.commit()
            db.refresh(db_packet)
            
            self.packets_captured_count += 1
            
            # Keep DB size in check
            if self.packets_captured_count % 100 == 0:
                self._prune_db(db)

            # 3. Create Alert if anomaly is found
            if is_anomaly:
                alert_severity = "Warning" if severity == "Suspicious" else "Critical"
                alert = Alert(
                    timestamp=time.time(),
                    severity=alert_severity,
                    attack_type=anomaly_reason or "Abnormal Traffic Pattern",
                    reason=f"Anomaly detected from {pkt_dict['src_ip']} to {pkt_dict['dst_ip']}. Reason: {anomaly_reason or 'ML flag'}",
                    src_ip=pkt_dict["src_ip"],
                    dst_ip=pkt_dict["dst_ip"],
                    packet_id=db_packet.id
                )
                db.add(alert)
                db.commit()
            
            # 4. Push to websocket queue for live dashboard streaming
            # Format object for UI
            ui_pkt = {
                "id": db_packet.id,
                "timestamp": db_packet.timestamp,
                "protocol": db_packet.protocol,
                "src_ip": db_packet.src_ip,
                "dst_ip": db_packet.dst_ip,
                "src_port": db_packet.src_port,
                "dst_port": db_packet.dst_port,
                "size": db_packet.size,
                "ttl": db_packet.ttl,
                "flags": db_packet.flags,
                "payload_len": db_packet.payload_len,
                "is_anomaly": db_packet.is_anomaly,
                "anomaly_score": db_packet.anomaly_score,
                "anomaly_reason": db_packet.anomaly_reason,
                "severity": db_packet.severity
            }
            
            try:
                self.packet_queue.put_nowait(ui_pkt)
            except queue.Full:
                try:
                    self.packet_queue.get_nowait() # Remove oldest
                    self.packet_queue.put_nowait(ui_pkt)
                except Exception:
                    pass

        except Exception as e:
            db.rollback()
            print(f"Database write failure in packet processing: {e}")
            traceback.print_exc()
        finally:
            db.close()

    def _prune_db(self, db):
        """Ensure the packet table does not grow indefinitely beyond the PACKET_LIMIT."""
        try:
            total = db.query(Packet).count()
            if total > self.packet_limit:
                # Delete oldest excess packets
                excess = total - self.packet_limit + 500
                oldest_ids = db.query(Packet.id).order_by(Packet.timestamp.asc()).limit(excess).all()
                oldest_ids = [r[0] for r in oldest_ids]
                db.query(Packet).filter(Packet.id.in_(oldest_ids)).delete(synchronize_session=False)
                db.commit()
        except Exception as e:
            db.rollback()
            print(f"Error pruning database: {e}")

    def parse_offline_pcap(self, pcap_path: str, limit: int = 1000) -> Dict[str, Any]:
        """Sync parsing of an uploaded/offline PCAP file, loading it into database."""
        self.log_system_event("Sniffer", "INFO", f"Starting offline PCAP parsing: {os.path.basename(pcap_path)}")
        try:
            packets = sniff(offline=pcap_path, count=limit)
            count = 0
            for pkt in packets:
                if pkt.haslayer(IP):
                    self._process_scapy_packet(pkt)
                    count += 1
            
            self.log_system_event("Sniffer", "INFO", f"PCAP analysis finished. Imported {count} packets successfully.")
            return {"status": "success", "packets_imported": count}
        except Exception as e:
            self.log_system_event("Sniffer", "ERROR", f"Offline PCAP import failed: {str(e)}")
            return {"status": "error", "message": str(e)}

    def replay_pcap(self, pcap_path: str, speed: float = 1.0):
        """Starts a background thread that replays a PCAP file at configurable rate."""
        def run_replay():
            self.log_system_event("Sniffer", "INFO", f"Starting PCAP replay (Speed: {speed}x)")
            try:
                packets = sniff(offline=pcap_path)
                last_time = None
                
                for pkt in packets:
                    if not self.running or self._stop_event.is_set():
                        break
                    
                    while self.paused:
                        time.sleep(0.5)
                        if not self.running or self._stop_event.is_set():
                            break
                    
                    if pkt.haslayer(IP):
                        # Simple delay emulation
                        current_time = float(pkt.time)
                        if last_time is not None:
                            delay = (current_time - last_time) / speed
                            # Cap delay to 2 seconds to keep UI responsive
                            time.sleep(min(delay, 2.0))
                        
                        last_time = current_time
                        self._process_scapy_packet(pkt)
                
                self.log_system_event("Sniffer", "INFO", "PCAP replay finished.")
            except Exception as e:
                self.log_system_event("Sniffer", "ERROR", f"PCAP replay failed: {str(e)}")

        threading.Thread(target=run_replay, daemon=True).start()

    def _run_mock_generator(self):
        """Simulated Network Traffic Generator for smooth UI updates out-of-the-box."""
        common_ips = [
            "192.168.1.5", "10.0.0.12", "192.168.1.150", 
            "8.8.8.8", "1.1.1.1", "104.244.42.1", "142.250.190.46",
            "185.190.140.23", "45.33.32.156"
        ]
        local_ips = ["192.168.1.20", "192.168.1.25", "192.168.1.30"]

        self.log_system_event("Sniffer", "INFO", "Traffic generator simulator active.")

        while self.running and not self._stop_event.is_set():
            if self.paused:
                time.sleep(1.0)
                continue
                
            try:
                # Decide type of traffic: 88% normal, 12% malicious/anomalous
                traffic_roll = random.random()
                
                if traffic_roll < 0.88:
                    # Normal packets
                    src = random.choice(local_ips)
                    dst = random.choice(common_ips)
                    
                    # 50% TCP (HTTP/HTTPS), 40% UDP (DNS), 10% ARP/ICMP
                    proto_roll = random.random()
                    if proto_roll < 0.50:
                        proto = "TCP"
                        sport = random.randint(49152, 65535)
                        dport = random.choice([80, 443, 8080])
                        size = random.randint(100, 1450)
                        flags = random.choice(["A", "PA", "S"])
                    elif proto_roll < 0.90:
                        proto = "UDP"
                        sport = random.randint(49152, 65535)
                        dport = random.choice([53, 123, 443])
                        size = random.randint(60, 400)
                        flags = ""
                    else:
                        proto = random.choice(["ICMP", "ARP"])
                        sport = None
                        dport = None
                        size = random.choice([42, 74, 98])
                        flags = ""
                        if proto == "ARP":
                            src = "192.168.1.1" if random.random() > 0.5 else random.choice(local_ips)
                            dst = "0.0.0.0"
                            
                    pkt_dict = {
                        "timestamp": time.time(),
                        "protocol": proto,
                        "src_ip": src,
                        "dst_ip": dst,
                        "src_port": sport,
                        "dst_port": dport,
                        "size": size,
                        "ttl": random.choice([64, 128]),
                        "flags": flags,
                        "payload_len": max(0, size - 40),
                        "payload": "GET /index.html HTTP/1.1\r\nHost: example.com\r\n" if proto == "TCP" and dport == 80 else "",
                        "packet_rate": random.uniform(1.0, 10.0)
                    }
                    self._evaluate_and_save_packet(pkt_dict)
                    
                else:
                    # Anomalous packets
                    anomaly_type = random.choice(["dos", "portscan", "largepayload", "malformed", "unknown_proto"])
                    
                    if anomaly_type == "dos":
                        # DoS Flood Simulation: generate multiple packets in a burst
                        dos_ip = "185.220.101.4"  # Simulated malicious external IP
                        target_ip = "192.168.1.20"
                        burst_size = random.randint(15, 30)
                        for i in range(burst_size):
                            pkt_dict = {
                                "timestamp": time.time() + (i * 0.001),
                                "protocol": "TCP",
                                "src_ip": dos_ip,
                                "dst_ip": target_ip,
                                "src_port": random.randint(1024, 65535),
                                "dst_port": 80,
                                "size": 64,
                                "ttl": 64,
                                "flags": "S",  # SYN flood
                                "payload_len": 0,
                                "payload": "",
                                "packet_rate": float(burst_size * 10)  # High rate indicator
                            }
                            self._evaluate_and_save_packet(pkt_dict)
                            time.sleep(0.01)
                            
                    elif anomaly_type == "portscan":
                        # Port scan Simulation: probe multiple ports sequentially
                        scan_ip = "45.83.67.12"
                        target_ip = "192.168.1.25"
                        ports_to_scan = [21, 22, 23, 25, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080]
                        random.shuffle(ports_to_scan)
                        for dport in ports_to_scan[:8]:
                            pkt_dict = {
                                "timestamp": time.time(),
                                "protocol": "TCP",
                                "src_ip": scan_ip,
                                "dst_ip": target_ip,
                                "src_port": random.randint(3000, 60000),
                                "dst_port": dport,
                                "size": 64,
                                "ttl": 128,
                                "flags": "S",
                                "payload_len": 0,
                                "payload": "",
                                "packet_rate": 60.0
                            }
                            self._evaluate_and_save_packet(pkt_dict)
                            time.sleep(0.05)
                            
                    elif anomaly_type == "largepayload":
                        # Data Exfiltration / Large payload simulation
                        pkt_dict = {
                            "timestamp": time.time(),
                            "protocol": "TCP",
                            "src_ip": "192.168.1.20",
                            "dst_ip": "198.51.100.55",  # Remote drop server
                            "src_port": 49202,
                            "dst_port": 443,
                            "size": 65000,  # Giant size
                            "ttl": 64,
                            "flags": "PA",
                            "payload_len": 64960,
                            "payload": "EXFILTRATION_DATA_STREAM_" + "X" * 150,
                            "packet_rate": 8.0
                        }
                        self._evaluate_and_save_packet(pkt_dict)
                        
                    elif anomaly_type == "malformed":
                        # Malformed headers
                        pkt_dict = {
                            "timestamp": time.time(),
                            "protocol": "TCP",
                            "src_ip": "91.240.118.22",
                            "dst_ip": "192.168.1.30",
                            "src_port": 139,
                            "dst_port": 0,  # Invalid port
                            "size": 15,     # Invalid size (less than min header)
                            "ttl": 255,
                            "flags": "SFRPY",  # Nonsense flags
                            "payload_len": 0,
                            "payload": None,
                            "packet_rate": 5.0
                        }
                        self._evaluate_and_save_packet(pkt_dict)
                        
                    elif anomaly_type == "unknown_proto":
                        # Unknown protocol
                        pkt_dict = {
                            "timestamp": time.time(),
                            "protocol": "PROTO_99",  # Custom odd protocol
                            "src_ip": "185.143.172.90",
                            "dst_ip": "192.168.1.30",
                            "src_port": None,
                            "dst_port": None,
                            "size": 250,
                            "ttl": 128,
                            "flags": None,
                            "payload_len": 210,
                            "payload": "ENCRYPTED_TUNNEL_PAYLOAD",
                            "packet_rate": 2.0
                        }
                        self._evaluate_and_save_packet(pkt_dict)

                # Random sleep to govern data flow speed
                time.sleep(random.uniform(0.3, 0.9))

            except Exception as e:
                print(f"Error in traffic simulation cycle: {e}")
                time.sleep(1.0)
