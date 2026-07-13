from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session
from backend.utils.config import DB_PATH

# Create Engine (using SQLite, disable same thread check for multithreaded sniffer/web socket)
engine = create_engine(DB_PATH, connect_args={"check_same_thread": False})

# Create a thread-safe scoped session factory
session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
SessionLocal = scoped_session(session_factory)

# Base class for SQLAlchemy models
Base = declarative_base()

def get_db():
    """FastAPI database dependency providing a transactional session scope."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    """Initializes database tables according to defined metadata."""
    Base.metadata.create_all(bind=engine)
