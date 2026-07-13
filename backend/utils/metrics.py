import time
import psutil
from typing import Dict, Any

START_TIME = time.time()

def get_system_resource_metrics() -> Dict[str, float]:
    """Retrieve current system resource statistics."""
    try:
        cpu_usage = psutil.cpu_percent(interval=None)
        ram_usage = psutil.virtual_memory().percent
        disk_usage = psutil.disk_usage('/').percent
        uptime = time.time() - START_TIME
        
        return {
            "cpu_usage": cpu_usage,
            "ram_usage": ram_usage,
            "disk_usage": disk_usage,
            "uptime": uptime
        }
    except Exception as e:
        print(f"Error obtaining system metrics: {e}")
        return {
            "cpu_usage": 0.0,
            "ram_usage": 0.0,
            "disk_usage": 0.0,
            "uptime": 0.0
        }
