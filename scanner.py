from scapy.all import ARP, Ether, srp, IP, TCP, sr1
import socket
import json

class NetworkScanner:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.results = {
            "active_hosts": [],
            "open_ports": {}
        }

    def arp_scan(self):
        """Scanne le réseau local pour les hôtes actifs en utilisant ARP."""
        print(f"[*] Démarrage du scan ARP sur {self.target_ip}")
        # Création du paquet ARP: Qui a l'IP X ? Répondez à mon IP
        # Ether() est optionnel mais assure un paquet Ethernet bien formé
        arp_request = ARP(pdst=self.target_ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff") # Adresse MAC de broadcast
        arp_request_broadcast = broadcast / arp_request

        # srp retourne deux listes: (répondants, non-répondants)
        answered_list, unanswered_list = srp(arp_request_broadcast, timeout=1, verbose=False)

        hosts = []
        for sent, received in answered_list:
            host_info = {"ip": received.psrc, "mac": received.hwsrc}
            hosts.append(host_info)
        self.results["active_hosts"] = hosts
        print(f"[*] {len(hosts)} hôtes actifs trouvés.")
        return hosts

    def port_scan(self, host_ip, ports_to_scan=None):
        """Scanne les ports TCP d'un hôte spécifique."""
        if not ports_to_scan:
            ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3389, 8080] # Ports courants
        
        print(f"[*] Démarrage du scan de ports sur {host_ip} pour les ports {ports_to_scan}")
        open_ports = []
        
        # Pour une meilleure performance et éviter de spammer, on peut faire des batchs ou être plus lent
        # Ici, on itère simplement. Pour de vrais scans, il faut gérer les flags TCP (SYN, ACK, RST)
        # On va faire un simple SYN scan.

        for port in ports_to_scan:
            try:
                # IP(dst=host_ip) : Paquet IP vers l'hôte cible
                # TCP(dport=port, flags="S") : Paquet TCP SYN vers le port
                # sr1(..., timeout=0.1, verbose=False) : Envoie le paquet et attend la première réponse
                resp = sr1(IP(dst=host_ip)/TCP(dport=port, flags="S"), timeout=0.1, verbose=False)
                
                # Si une réponse est reçue et qu'elle contient un flag SYN/ACK (0x12), le port est ouvert
                if resp and resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x12:
                    service_name = self._get_service_name(port)
                    open_ports.append({"port": port, "status": "Ouvert", "service": service_name})
                    print(f"    Port {port} ({service_name}) : Ouvert")
                # Si la réponse contient un flag RST/ACK (0x14), le port est fermé
                elif resp and resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x14:
                    print(f"    Port {port} : Fermé")
            except Exception as e:
                # Gérer les erreurs de permission ou autres
                print(f"    Erreur lors du scan du port {port} sur {host_ip}: {e}")
        
        self.results["open_ports"][host_ip] = open_ports
        print(f"[*] Scan de ports sur {host_ip} terminé. {len(open_ports)} ports ouverts.")
        return open_ports

    def _get_service_name(self, port):
        """Tente de trouver le nom du service associé à un port."""
        try:
            return socket.getservbyport(port)
        except OSError:
            return "Inconnu"

    def get_results_as_json(self):
        return json.dumps(self.results, indent=4)

if __name__ == "__main__":
    # Pour tester le scanner directement
    # Assurez-vous d'avoir les privilèges sudo/admin
    
    # Remplacer par l'IP de votre réseau local (ex: 192.168.1.0/24)
    # ou une IP spécifique pour le port scan (ex: 192.168.1.1 pour votre routeur)
    
    # Pour le scan ARP sur un sous-réseau (ex: tous les hôtes de 192.168.1.1 à 192.168.1.254)
    network_range = "192.168.1.0/24" # À adapter à votre réseau !
    scanner = NetworkScanner(network_range)
    active_hosts = scanner.arp_scan()

    # Pour le scan de ports sur un hôte spécifique (ex: votre routeur ou une autre machine sur votre réseau)
    # Choisissez une IP d'un hôte actif trouvé par le scan ARP, ou une IP connue.
    if active_hosts:
        target_for_port_scan = active_hosts[0]["ip"] # Scan le premier hôte trouvé
        scanner.port_scan(target_for_port_scan)
    else:
        print("Aucun hôte actif trouvé pour le scan de ports.")

    print("\n--- Résultats Complets (JSON) ---")
    print(scanner.get_results_as_json())