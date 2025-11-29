from flask import Flask, render_template, request, jsonify
from scanner import NetworkScanner # Assurez-vous que scanner.py est à jour et fonctionnel
from models import init_db, Session, ScanRun, Host, Port # NOUVELLES IMPORTATIONS DB
import threading
from datetime import datetime
from sqlalchemy import desc

# --- Configuration de l'application Flask ---
app = Flask(__name__)

# Variable globale pour suivre l'état du scan (non-DB state)
is_scanning = False

# Initialiser la DB au démarrage de l'application
# Cela crée le fichier 'scan_results.db' si il n'existe pas et les tables.
with app.app_context():
    init_db()

# --- Fonctions Utilitaires pour la DB ---

def get_latest_scan_data(session):
    """Récupère le dernier ScanRun terminé et ses données complètes (hôtes, ports)."""
    # Récupère le dernier ScanRun (trié par heure de fin)
    latest_run = session.query(ScanRun).order_by(desc(ScanRun.end_time)).first()
    
    if not latest_run:
        return None

    active_hosts_data = []
    open_ports_by_host = {}

    # Charger les données depuis les relations SQLAlchemy
    for host in latest_run.hosts:
        active_hosts_data.append({
            "ip": host.ip_address,
            "mac": host.mac_address
        })
        
        ports_list = []
        for port in host.ports:
            ports_list.append({
                "port": port.port_number,
                "status": port.status,
                "service": port.service_name
            })
        
        open_ports_by_host[host.ip_address] = ports_list

    return {
        "last_scan_time": latest_run.end_time.strftime("%Y-%m-%d %H:%M:%S") if latest_run.end_time else "En cours...",
        "active_hosts": active_hosts_data,
        "open_ports_by_host": open_ports_by_host
    }

# --- Routes Flask ---

@app.route('/')
def index():
    """Page d'accueil du tableau de bord. Affiche les résultats du dernier scan."""
    session = Session()
    # Récupère le dernier scan depuis la DB
    results = get_latest_scan_data(session)
    session.close()
    
    # Prépare les données pour le template (si aucun scan n'a été fait)
    default_results = {"last_scan_time": None, "active_hosts": [], "open_ports_by_host": {}}
    
    return render_template('index.html', 
                           results=results if results else default_results, 
                           is_scanning=is_scanning)

@app.route('/scan/start', methods=['POST'])
def start_scan():
    """Déclenche un nouveau scan réseau."""
    global is_scanning
    if is_scanning:
        return jsonify({"status": "error", "message": "Un scan est déjà en cours."}), 409

    data = request.get_json()
    network_range = data.get('network_range', "192.168.1.0/24")
    
    # Exécuter le scan dans un thread séparé
    scan_thread = threading.Thread(target=run_full_scan, args=(network_range,))
    scan_thread.daemon = True
    scan_thread.start()
    
    is_scanning = True
    return jsonify({"status": "success", "message": "Scan démarré en arrière-plan."})

@app.route('/scan/status', methods=['GET'])
def get_scan_status():
    """Retourne l'état actuel du scan."""
    return jsonify({"is_scanning": is_scanning})

@app.route('/scan/results', methods=['GET'])
def get_scan_results():
    """Retourne les résultats du dernier scan en JSON depuis la DB."""
    session = Session()
    results = get_latest_scan_data(session)
    session.close()
    
    if results:
        return jsonify(results)
    return jsonify({"status": "error", "message": "Aucune donnée de scan trouvée."}), 404

def run_full_scan(network_range):
    """Fonction qui exécute les scans et ENREGISTRE les résultats dans la DB."""
    global is_scanning
    session = Session() # Ouvre une session DB pour ce thread
    
    # Création de l'entrée de l'historique de scan (ScanRun)
    new_scan_run = ScanRun(network_range=network_range, start_time=datetime.now())
    session.add(new_scan_run)
    
    try:
        print(f"Thread: Démarrage du scan complet pour {network_range}")
        scanner_instance = NetworkScanner(network_range)
        scanner_instance.arp_scan() # Exécute l'ARP scan

        # Enregistrement des hôtes actifs
        host_objects = []
        for host_data in scanner_instance.results["active_hosts"]:
            # Vérifie si l'IP existe déjà si vous voulez que les IPs soient uniques, mais pour l'historique on les crée
            new_host = Host(
                ip_address=host_data["ip"], 
                mac_address=host_data["mac"],
                scan_run=new_scan_run # Utilise la relation
            )
            session.add(new_host)
            host_objects.append(new_host)
        
        # Enregistrement des hôtes avant le port scan pour obtenir leurs IDs
        session.commit()

        # Exécution et enregistrement du Port Scan pour chaque hôte
        for host_obj in host_objects:
            # Récupère les ports scannés par le scanner.py
            ports_list = scanner_instance.port_scan(host_obj.ip_address)
            
            # Enregistrement des ports ouverts pour cet hôte
            for port_info in ports_list:
                new_port = Port(
                    port_number=port_info["port"],
                    service_name=port_info["service"],
                    status=port_info["status"],
                    host=host_obj # Utilise la relation
                )
                session.add(new_port)
        
        # Mise à jour de l'heure de fin et validation finale
        new_scan_run.end_time = datetime.now()
        session.commit()
        print("Thread: Scan complet terminé et enregistré dans la DB.")

    except Exception as e:
        session.rollback() # Annule toutes les opérations si une erreur survient
        print(f"Thread: Erreur lors du scan, transaction annulée: {e}")
    finally:
        is_scanning = False
        session.close() # Ferme la session DB

if __name__ == '__main__':
    # REMARQUE : L'exécution nécessite toujours les privilèges administrateur/sudo
    app.run(host='0.0.0.0', port=5000)