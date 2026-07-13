import os
import sys
import asyncio
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.database.db import init_db
from backend.ml.detector import AnomalyDetector
from backend.sniffer.sniffer import PacketSniffer
from backend.api.routes import router as api_router
from backend.api.websockets import router as ws_router, websocket_broadcaster

# Global reference for WS task
broadcast_task = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global broadcast_task
    
    # 1. Initialize SQLite Database
    init_db()
    
    # 2. Initialize ML Anomaly Detector
    detector = AnomalyDetector()
    app.state.detector = detector
    
    # 3. Initialize Packet Capture Engine
    sniffer = PacketSniffer(detector=detector)
    app.state.sniffer = sniffer
    
    # Write startup log
    sniffer.log_system_event("API", "INFO", "FastAPI server lifespan initializing.")
    
    # 4. Auto-start the packet sniffer
    sniffer.start()
    
    # 5. Spawn background WebSocket broadcaster
    broadcast_task = asyncio.create_task(websocket_broadcaster(app))
    
    yield
    
    # Shutdown routine
    sniffer.log_system_event("API", "INFO", "FastAPI server shutting down. Clearing tasks.")
    if broadcast_task:
        broadcast_task.cancel()
        try:
            await broadcast_task
        except asyncio.CancelledError:
            pass
            
    sniffer.stop()

# Instantiate FastAPI application
app = FastAPI(
    title="Network Anomaly Detection System (NADS) API",
    description="Enterprise API endpoint supporting live packet inspections and ML classifications",
    version="1.0.0",
    lifespan=lifespan
)

# CORS Policy configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for dev simplicity, restrict in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Route attachment
app.include_router(api_router)
app.include_router(ws_router)

@app.get("/")
def read_root():
    return {
        "app": "Network Anomaly Detection System (NADS) Backend",
        "status": "online",
        "documentation": "/docs"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
