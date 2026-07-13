import os
import csv
import json
import time
from typing import Dict, Any, List
from io import BytesIO

# Import ReportLab modules safely
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.units import inch

from backend.database.db import SessionLocal
from backend.models.models import Packet, Alert

class ReportGenerator:
    @staticmethod
    def get_statistics(db_session) -> Dict[str, Any]:
        """Query statistics needed for reports."""
        total_packets = db_session.query(Packet).count()
        total_anomalies = db_session.query(Packet).filter(Packet.is_anomaly == True).count()
        
        # Protocol counts
        protocols = {}
        for proto, count in db_session.query(Packet.protocol, db_session.func.count(Packet.id)).group_by(Packet.protocol).all():
            protocols[proto or "Unknown"] = count
            
        # Severity counts
        severities = {"Safe": 0, "Suspicious": 0, "Dangerous": 0}
        for sev, count in db_session.query(Packet.severity, db_session.func.count(Packet.id)).group_by(Packet.severity).all():
            if sev in severities:
                severities[sev] = count
                
        # Top source/destination talkers
        top_sources = []
        for ip, count in db_session.query(Packet.src_ip, db_session.func.count(Packet.id)).group_by(Packet.src_ip).order_by(db_session.func.count(Packet.id).desc()).limit(5).all():
            top_sources.append({"ip": ip, "count": count})
            
        top_destinations = []
        for ip, count in db_session.query(Packet.dst_ip, db_session.func.count(Packet.id)).group_by(Packet.dst_ip).order_by(db_session.func.count(Packet.id).desc()).limit(5).all():
            top_destinations.append({"ip": ip, "count": count})

        # Recent alerts
        alerts_list = []
        for alert in db_session.query(Alert).order_by(Alert.timestamp.desc()).limit(15).all():
            alerts_list.append({
                "timestamp": alert.timestamp,
                "severity": alert.severity,
                "attack_type": alert.attack_type,
                "reason": alert.reason,
                "src_ip": alert.src_ip,
                "dst_ip": alert.dst_ip
            })

        anomaly_rate = (total_anomalies / total_packets * 100) if total_packets > 0 else 0.0

        return {
            "timestamp": time.time(),
            "total_packets": total_packets,
            "total_anomalies": total_anomalies,
            "anomaly_rate": round(anomaly_rate, 2),
            "protocols": protocols,
            "severities": severities,
            "top_sources": top_sources,
            "top_destinations": top_destinations,
            "alerts": alerts_list
        }

    @classmethod
    def generate_json(cls) -> str:
        """Generate a JSON report."""
        db = SessionLocal()
        try:
            stats = cls.get_statistics(db)
            return json.dumps(stats, indent=2)
        finally:
            db.close()

    @classmethod
    def generate_csv(cls) -> str:
        """Generate a CSV report of recent alerts."""
        db = SessionLocal()
        try:
            stats = cls.get_statistics(db)
            output = BytesIO()
            writer = csv.writer(output.decode('utf-8') if hasattr(output, 'decode') else output)
            
            # Write Header
            writer.writerow(["Timestamp", "Severity", "Attack Type", "Source IP", "Destination IP", "Details"])
            for alert in stats["alerts"]:
                t_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(alert["timestamp"]))
                writer.writerow([
                    t_str,
                    alert["severity"],
                    alert["attack_type"],
                    alert["src_ip"] or "N/A",
                    alert["dst_ip"] or "N/A",
                    alert["reason"]
                ])
            return output.getvalue() if isinstance(output.getvalue(), str) else output.getvalue().decode('utf-8')
        finally:
            db.close()

    @classmethod
    def generate_pdf(cls) -> bytes:
        """Generate a formatted PDF report using ReportLab."""
        db = SessionLocal()
        try:
            stats = cls.get_statistics(db)
            buffer = BytesIO()
            
            # Create PDF doc
            doc = SimpleDocTemplate(
                buffer,
                pagesize=letter,
                rightMargin=36,
                leftMargin=36,
                topMargin=36,
                bottomMargin=36
            )
            
            styles = getSampleStyleSheet()
            
            # Custom Styles
            title_style = ParagraphStyle(
                'DocTitle',
                parent=styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#1E293B'),
                spaceAfter=15
            )
            
            h2_style = ParagraphStyle(
                'SectionHeader',
                parent=styles['Heading2'],
                fontSize=14,
                textColor=colors.HexColor('#0F172A'),
                spaceBefore=12,
                spaceAfter=8
            )
            
            body_style = ParagraphStyle(
                'BodyTextCustom',
                parent=styles['BodyText'],
                fontSize=10,
                textColor=colors.HexColor('#475569'),
                spaceAfter=8
            )
            
            code_style = ParagraphStyle(
                'CodeStyle',
                parent=styles['Code'],
                fontSize=9,
                textColor=colors.HexColor('#0F172A')
            )
            
            story = []
            
            # 1. Header Section
            story.append(Paragraph("DEEP TRACE: Network Anomaly Detection System", title_style))
            t_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stats["timestamp"]))
            story.append(Paragraph(f"<b>Security Assessment Report</b> | Generated: {t_str}", body_style))
            story.append(Spacer(1, 10))
            
            # 2. Executive Summary Metrics Table
            summary_data = [
                ["Metric", "Value"],
                ["Total Inspected Packets", f"{stats['total_packets']:,}"],
                ["Flagged Anomalies", f"{stats['total_anomalies']:,}"],
                ["Anomaly Ratio", f"{stats['anomaly_rate']}%"],
                ["Safe Packets Count", f"{stats['severities']['Safe']:,}"],
                ["Suspicious Packets Count", f"{stats['severities']['Suspicious']:,}"],
                ["Dangerous Packets Count", f"{stats['severities']['Dangerous']:,}"],
            ]
            t = Table(summary_data, colWidths=[3.0 * inch, 4.0 * inch])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1E293B')),
                ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0,0), (-1,0), 6),
                ('TOPPADDING', (0,0), (-1,0), 6),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#F8FAFC'), colors.white]),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
                ('FONTSIZE', (0,0), (-1,-1), 9),
            ]))
            story.append(t)
            story.append(Spacer(1, 15))
            
            # 3. Protocol Distribution Table
            story.append(Paragraph("Protocol Distribution Breakdown", h2_style))
            proto_data = [["Protocol", "Packet Count", "Percentage"]]
            for proto, count in stats["protocols"].items():
                pct = round((count / stats["total_packets"] * 100), 2) if stats["total_packets"] > 0 else 0
                proto_data.append([proto, f"{count:,}", f"{pct}%"])
            t_proto = Table(proto_data, colWidths=[2.3 * inch, 2.3 * inch, 2.4 * inch])
            t_proto.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#334155')),
                ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#F8FAFC'), colors.white]),
                ('FONTSIZE', (0,0), (-1,-1), 9),
            ]))
            story.append(t_proto)
            story.append(Spacer(1, 15))
            
            # 4. Top IP Sources
            story.append(Paragraph("Top Traffic Originators (Sources)", h2_style))
            src_data = [["Source IP Address", "Packet Count"]]
            for item in stats["top_sources"]:
                src_data.append([item["ip"], f"{item['count']:,}"])
            t_src = Table(src_data, colWidths=[3.5 * inch, 3.5 * inch])
            t_src.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#475569')),
                ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#F8FAFC'), colors.white]),
                ('FONTSIZE', (0,0), (-1,-1), 9),
            ]))
            story.append(t_src)
            story.append(Spacer(1, 15))
            
            # Page Break for clean structure
            story.append(PageBreak())

            # 5. Security Alerts Log
            story.append(Paragraph("Flagged Security Alerts & Incident Log", h2_style))
            if not stats["alerts"]:
                story.append(Paragraph("No severe anomalies or alerts triggered during this session.", body_style))
            else:
                alert_data = [["Time", "Severity", "Category", "Source", "Detail"]]
                for a in stats["alerts"]:
                    a_time = time.strftime('%H:%M:%S', time.localtime(a["timestamp"]))
                    severity_color = Paragraph(f"<font color='red'><b>{a['severity']}</b></font>" if a['severity'] == "Critical" else f"<font color='orange'><b>{a['severity']}</b></font>", body_style)
                    alert_data.append([
                        a_time,
                        severity_color,
                        a["attack_type"],
                        a["src_ip"] or "N/A",
                        Paragraph(a["reason"], body_style)
                    ])
                t_alert = Table(alert_data, colWidths=[0.8 * inch, 0.8 * inch, 1.2 * inch, 1.2 * inch, 3.0 * inch])
                t_alert.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#94A3B8')),
                    ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                    ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
                    ('VALIGN', (0,0), (-1,-1), 'TOP'),
                    ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#F8FAFC'), colors.white]),
                    ('FONTSIZE', (0,0), (-1,-1), 8),
                ]))
                story.append(t_alert)
            story.append(Spacer(1, 15))

            # 6. Actionable Security Recommendations
            story.append(Paragraph("Security Recommendations & Mitigation Plan", h2_style))
            recs = []
            
            has_dos = any(a["attack_type"] == "DoS" for a in stats["alerts"])
            has_scan = any(a["attack_type"] == "Port Scan" for a in stats["alerts"])
            has_exfil = any(a["attack_type"] == "Large Payload" for a in stats["alerts"])
            
            recs.append("<b>Establish Baseline Network Profiling:</b> Routinely audit signature rules against network states to improve detection accuracy and reduce false positives.")
            
            if has_dos:
                recs.append("<b>Mitigate Denials of Service (DoS):</b> Implement rate-limiting firewalls or deploy Cloudflare/AWS Shield protections. Apply connection pooling thresholds for source IPs exceeding 100 packets/sec.")
            if has_scan:
                recs.append("<b>Prevent Port Scans:</b> Close unused open ports on the border routers. Configure network IDS/IPS systems to auto-block IPs flagged with scanning behaviors (e.g. probing consecutive ports).")
            if has_exfil:
                recs.append("<b>Data Exfiltration Defense:</b> Set up Data Loss Prevention (DLP) rules that alert on outbound packet sizes greater than 1500 bytes and encrypt sensitive transfers.")
            
            # Default fallback recommendation
            if len(recs) == 1:
                recs.append("<b>General Security Hygiene:</b> Ensure all firewall logs are streamed to a centralized SIEM, update firmware on network appliances, and monitor external ingress paths.")
                
            for idx, rec in enumerate(recs):
                bullet = Paragraph(f"{idx+1}. {rec}", body_style)
                story.append(bullet)
                story.append(Spacer(1, 5))
                
            doc.build(story)
            pdf_bytes = buffer.getvalue()
            buffer.close()
            return pdf_bytes
        finally:
            db.close()
