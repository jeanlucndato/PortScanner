"""SQLAlchemy models and database setup for the scanner."""
import os
from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text, create_engine
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

Base = declarative_base()
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///scan_results.db")
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
ENGINE = create_engine(DATABASE_URL, echo=False, connect_args=connect_args)
Session = sessionmaker(bind=ENGINE, expire_on_commit=False)


class ScanRun(Base):
    __tablename__ = "scan_runs"
    id = Column(Integer, primary_key=True)
    network_range = Column(String, nullable=False)
    profile = Column(String, nullable=False, default="common")
    ports_requested = Column(Text, nullable=False, default="[]")
    status = Column(String, nullable=False, default="queued", index=True)
    progress = Column(Integer, nullable=False, default=0)
    current_target = Column(String)
    error_message = Column(Text)
    active_guard = Column(Integer, unique=True)
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime)
    hosts = relationship("Host", back_populates="scan_run", cascade="all, delete-orphan")


class Host(Base):
    __tablename__ = "hosts"
    id = Column(Integer, primary_key=True)
    ip_address = Column(String, nullable=False, index=True)
    mac_address = Column(String)
    hostname = Column(String)
    scan_run_id = Column(Integer, ForeignKey("scan_runs.id"), nullable=False, index=True)
    scan_run = relationship("ScanRun", back_populates="hosts")
    ports = relationship("Port", back_populates="host", cascade="all, delete-orphan")


class Port(Base):
    __tablename__ = "ports"
    id = Column(Integer, primary_key=True)
    port_number = Column(Integer, nullable=False)
    service_name = Column(String)
    status = Column(String, nullable=False)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False, index=True)
    host = relationship("Host", back_populates="ports")


def init_db():
    from migrations import migrate
    migrate(ENGINE)
    Base.metadata.create_all(ENGINE)
