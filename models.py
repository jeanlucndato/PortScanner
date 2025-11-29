from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime
from sqlalchemy import desc

# Définir la base pour les classes de modèles
Base = declarative_base()

# --- Modèle de Scan (pour l'historique) ---
class ScanRun(Base):
    """Représente une exécution complète du scanner."""
    __tablename__ = 'scan_runs'

    id = Column(Integer, primary_key=True)
    # Ex: '192.168.1.0/24'
    network_range = Column(String) 
    # Horodatage du scan
    start_time = Column(DateTime, default=datetime.now) 
    end_time = Column(DateTime)
    
    # Relation avec les hôtes trouvés (un scan peut avoir plusieurs hôtes)
    hosts = relationship("Host", back_populates="scan_run", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<ScanRun(id={self.id}, range='{self.network_range}')>"

# --- Modèle d'Hôte Actif ---
class Host(Base):
    """Représente un hôte actif trouvé lors d'un scan."""
    __tablename__ = 'hosts'

    id = Column(Integer, primary_key=True)
    ip_address = Column(String) # Ne mettons pas 'unique=True' pour permettre le stockage dans différents scans
    mac_address = Column(String)
    # Clé étrangère vers ScanRun
    scan_run_id = Column(Integer, ForeignKey('scan_runs.id')) 
    
    # Relation vers le ScanRun parent
    scan_run = relationship("ScanRun", back_populates="hosts")
    # Relation avec les ports ouverts (un hôte peut avoir plusieurs ports)
    ports = relationship("Port", back_populates="host", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Host(ip='{self.ip_address}')>"

# --- Modèle de Port Ouvert ---
class Port(Base):
    """Représente un port ouvert trouvé sur un hôte."""
    __tablename__ = 'ports'

    id = Column(Integer, primary_key=True)
    port_number = Column(Integer)
    service_name = Column(String)
    status = Column(String) # Ex: 'Ouvert'
    # Clé étrangère vers Host
    host_id = Column(Integer, ForeignKey('hosts.id'))
    
    # Relation vers l'hôte parent
    host = relationship("Host", back_populates="ports")

    def __repr__(self):
        return f"<Port(number={self.port_number}, service='{self.service_name}')>"

# Configuration de la base de données (SQLite dans le fichier 'scan_results.db')
ENGINE = create_engine('sqlite:///scan_results.db', echo=False)
Session = sessionmaker(bind=ENGINE)

def init_db():
    """Crée les tables si elles n'existent pas."""
    Base.metadata.create_all(ENGINE)
    print("Base de données initialisée (scan_results.db créée).")