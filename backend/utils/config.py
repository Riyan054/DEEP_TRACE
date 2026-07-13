import os
from pathlib import Path

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DB_FILE = BASE_DIR / "database.db"
DB_PATH = f"sqlite:///{DB_FILE}"
MODEL_DIR = BASE_DIR / "ml" / "saved_models"

# Ensure directories exist
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(BASE_DIR / "logs", exist_ok=True)

# Application Settings
DEFAULT_INTERFACE = "en0"  # Fallback interface, can be changed dynamically
MOCK_MODE = True           # Default to True to run out of the box, can toggle via UI
PACKET_LIMIT = 5000        # Max packets stored in db during session
REFRESH_RATE = 1.0         # WebSockets broadcast rate in seconds
ACTIVE_MODEL = "Isolation Forest"
ALERTS_LIMIT = 1000

# Security/Detection Thresholds
PORT_SCAN_THRESHOLD = 20   # Ports probed per IP within 10 seconds
DOS_THRESHOLD = 100        # Packets per second from single IP
LARGE_PAYLOAD_LIMIT = 1500 # Bytes
NORMAL_PACKET_RATE = 50.0  # Packets per second average
