from flask import Flask, render_template, request, jsonify
from scanner import NetworkScanner
import os
import threading
import time

app = Flask(__name__)

# Stockage des résultats du scan. Dans un vrai projet, utilisez une BDD.
# Ici, simple variable pour l'exemple.
scan_results = {
    "last_scan_time": None,
    "active_hosts": [],
    "open_ports_by_host": {}
}

# Variable pour suivre l'état du scan
is_scanning = False

@app.route('/')
def index():
    """Page d'accueil du tableau de bord."""
    return render_template('index.html', results=scan_results, is_scanning=is_scanning)

@app.route('/scan/start', methods=['POST'])
def start_scan():
    """Déclenche un nouveau scan réseau."""
    global is_scanning
    if is_scanning:
        return jsonify({"status": "error", "message": "Un scan est déjà en cours."}), 409

    data = request.get_json()
    network_range = data.get('network_range', "192.168.1.0/24") # Default ou depuis l'utilisateur
    
    # Exécuter le scan dans un thread séparé pour ne pas bloquer l'interface web
    scan_thread = threading.Thread(target=run_full_scan, args=(network_range,))
    scan_thread.daemon = True # Permet au thread de s'arrêter avec l'app Flask
    scan_thread.start()
    
    is_scanning = True
    return jsonify({"status": "success", "message": "Scan démarré en arrière-plan."})

@app.route('/scan/status', methods=['GET'])
def get_scan_status():
    """Retourne l'état actuel du scan."""
    return jsonify({"is_scanning": is_scanning})

@app.route('/scan/results', methods=['GET'])
def get_scan_results():
    """Retourne les résultats du dernier scan en JSON."""
    return jsonify(scan_results)

def run_full_scan(network_range):
    """Fonction qui exécute les scans et met à jour les résultats."""
    global scan_results, is_scanning
    try:
        print(f"Thread: Démarrage du scan complet pour {network_range}")
        scanner_instance = NetworkScanner(network_range)
        
        # 1. ARP Scan
        active_hosts = scanner_instance.arp_scan()
        scan_results["active_hosts"] = active_hosts

        # 2. Port Scan pour chaque hôte actif
        scan_results["open_ports_by_host"] = {}
        if active_hosts:
            for host in active_hosts:
                # Limitez le nombre de ports ou de cibles pour éviter un scan trop long
                scanner_instance.port_scan(host["ip"])
                scan_results["open_ports_by_host"][host["ip"]] = scanner_instance.results["open_ports"].get(host["ip"], [])
        
        scan_results["last_scan_time"] = time.strftime("%Y-%m-%d %H:%M:%S")
        print("Thread: Scan complet terminé.")

    except Exception as e:
        print(f"Thread: Erreur lors du scan: {e}")
        # Gérer les erreurs (e.g., permissions)
        # Il faut que l'app Flask ait les droits pour lancer scapy
        # Si vous exécutez 'sudo python app.py', ça devrait aller.
    finally:
        is_scanning = False # Le scan est terminé, que ce soit un succès ou un échec

if __name__ == '__main__':
    # Flask doit être exécuté avec des privilèges pour Scapy
    # Sur Linux/macOS : sudo python app.py
    # Sur Windows : Ouvrir le terminal en tant qu'administrateur, puis python app.py
    # Pour le développement, vous pouvez utiliser app.run(debug=True)
    # Pour la production, utilisez un serveur WSGI (Gunicorn/uWSGI)
    app.run(host='0.0.0.0', port=5000)