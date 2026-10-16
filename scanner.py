"""Bounded ARP discovery and TCP SYN scanning. Only scan authorized targets."""
import errno
import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor


PROFILES = {
    "common": [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 3389, 5432, 8080, 8443],
    "web": [80, 443, 8000, 8080, 8081, 8443, 8888],
    "database": [1433, 1521, 3306, 5432, 6379, 9042, 27017],
}


class NetworkScanner:
    def __init__(self, target_ip, timeout=1.0):
        self.target_ip = target_ip
        self.timeout = timeout

    def arp_scan(self):
        # ARP gives the best LAN discovery results but needs raw-packet privileges.
        try:
            from scapy.all import ARP, Ether, srp
            answered, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.target_ip), timeout=self.timeout, verbose=False)
            hosts = [{"ip": received.psrc, "mac": received.hwsrc} for _, received in answered]
            if hosts:
                return [self._with_hostname(host) for host in hosts]
        except (OSError, PermissionError, ImportError):
            pass

        # Unprivileged fallback: recognize hosts that respond on a common TCP port.
        network = ipaddress.ip_network(self.target_ip, strict=False)
        targets = [str(ip) for ip in network.hosts()]
        probe_ports = sorted(set(sum(PROFILES.values(), [])))

        def probe(ip):
            for port in probe_ports:
                try:
                    with socket.create_connection((ip, port), timeout=self.timeout):
                        return {"ip": ip, "mac": None}
                except ConnectionRefusedError:
                    return {"ip": ip, "mac": None}
                except (socket.timeout, TimeoutError, OSError):
                    continue
            return None

        with ThreadPoolExecutor(max_workers=64) as pool:
            hosts = [host for host in pool.map(probe, targets) if host]
        return [self._with_hostname(host) for host in hosts]

    @staticmethod
    def _with_hostname(host):
        try:
            host["hostname"] = socket.gethostbyaddr(host["ip"])[0]
        except (socket.herror, socket.gaierror, OSError):
            host["hostname"] = None
        return host

    def port_scan(self, host_ip, ports_to_scan):
        def probe(port):
            try:
                with socket.create_connection((host_ip, port), timeout=self.timeout):
                    status = "open"
            except ConnectionRefusedError:
                status = "closed"
            except (socket.timeout, TimeoutError):
                status = "filtered"
            except OSError as exc:
                status = "closed" if exc.errno == errno.ECONNREFUSED else "filtered"
            try:
                service = socket.getservbyport(port, "tcp")
            except OSError:
                service = "unknown"
            return {"port": port, "status": status, "service": service}

        with ThreadPoolExecutor(max_workers=min(32, len(ports_to_scan) or 1)) as pool:
            return sorted(pool.map(probe, ports_to_scan), key=lambda item: item["port"])
