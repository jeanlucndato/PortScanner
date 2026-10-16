import csv
import hmac
import io
import ipaddress
import json
import math
import os
import threading
import time
from datetime import datetime
from functools import wraps

from flask import Flask, Response, jsonify, render_template, request
from sqlalchemy import desc
from sqlalchemy.exc import IntegrityError
from dotenv import load_dotenv

load_dotenv()
from models import ENGINE, Host, Port, ScanRun, Session, init_db
from scanner import NetworkScanner, PROFILES

app = Flask(__name__)
MAX_HOSTS = int(os.getenv("MAX_SCAN_HOSTS", "256"))
MAX_TIMEOUT = float(os.getenv("MAX_SCAN_TIMEOUT", "2"))
MAX_SCAN_SECONDS = int(os.getenv("MAX_SCAN_SECONDS", "600"))
DEFAULT_TIMEOUT = float(os.getenv("SCAN_TIMEOUT", "0.5"))
job_lock = threading.Lock()
init_db()


@app.before_request
def require_basic_auth():
    username = os.getenv("SCANNER_USERNAME", "admin")
    password = os.getenv("SCANNER_PASSWORD", "admin1234")
    auth = request.authorization
    if not auth or not hmac.compare_digest(auth.username or "", username) or not hmac.compare_digest(auth.password or "", password):
        return Response("Authentication required", 401, {"WWW-Authenticate": 'Basic realm="Port Scanner"'})


def fail(message, code=400):
    return jsonify(status="error", message=message), code


def active_network(target):
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError:
        raise ValueError("Enter a valid IPv4 address or CIDR range.")
    if network.version != 4:
        raise ValueError("Only IPv4 targets are supported by the ARP scanner.")
    if network.num_addresses > MAX_HOSTS:
        raise ValueError(f"Range contains {network.num_addresses} addresses; limit is {MAX_HOSTS}.")
    return network


def job_dict(job):
    return {"id": job.id, "network_range": job.network_range, "profile": job.profile, "status": job.status,
            "progress": job.progress, "current_target": job.current_target, "error_message": job.error_message,
            "start_time": job.start_time.isoformat() if job.start_time else None,
            "end_time": job.end_time.isoformat() if job.end_time else None}


def expire_stale_job(session, job):
    if job and job.status in ("queued", "running") and job.start_time and (datetime.utcnow() - job.start_time).total_seconds() > MAX_SCAN_SECONDS + 30:
        job.status = "failed"
        job.error_message = f"Job exceeded the {MAX_SCAN_SECONDS}-second service time limit or was interrupted."
        job.end_time = datetime.utcnow()
        job.active_guard = None
        session.commit()


def latest_results(session):
    job = session.query(ScanRun).filter_by(status="completed").order_by(desc(ScanRun.end_time)).first()
    if not job:
        return {"scan": None, "hosts": []}
    hosts = []
    for host in job.hosts:
        hosts.append({"ip": host.ip_address, "mac": host.mac_address, "hostname": host.hostname,
                      "ports": [{"port": p.port_number, "service": p.service_name, "status": p.status} for p in host.ports]})
    return {"scan": job_dict(job), "hosts": hosts}


@app.route("/")
def index():
    with Session() as session:
        jobs = session.query(ScanRun).order_by(desc(ScanRun.id)).limit(20).all()
        payload = latest_results(session)
        job_rows = [job_dict(j) for j in jobs]
    return render_template("index.html", payload=payload, jobs=job_rows, profiles=PROFILES,
                           max_hosts=MAX_HOSTS, max_timeout=MAX_TIMEOUT)


@app.post("/scan/start")
def start_scan():
    data = request.get_json(silent=True) or {}
    try:
        if data.get("authorized") is not True:
            raise ValueError("Confirm that you are authorized to scan this network.")
        network = active_network(str(data.get("network_range", "")))
        profile = data.get("profile", "common")
        if profile not in PROFILES:
            raise ValueError("Choose a supported scan profile.")
        raw_ports = data.get("ports")
        if raw_ports is None or raw_ports == "":
            ports = PROFILES[profile]
        elif not isinstance(raw_ports, str):
            raise ValueError("Custom ports must be comma-separated numbers.")
        else:
            ports = sorted(set(int(p.strip()) for p in raw_ports.split(",")))
        if not ports or len(ports) > 256 or any(p < 1 or p > 65535 for p in ports):
            raise ValueError("Provide 1–256 TCP ports in the range 1–65535.")
        timeout = min(float(data.get("timeout", DEFAULT_TIMEOUT)), MAX_TIMEOUT)
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("Timeout must be greater than zero.")
    except (ValueError, TypeError) as exc:
        return fail(str(exc))
    with job_lock, Session() as session:
        active = session.query(ScanRun).filter(ScanRun.status.in_(["queued", "running"])).first()
        expire_stale_job(session, active)
        if active and active.status == "failed":
            active = None
        if active:
            return fail(f"Scan #{active.id} is already {active.status}.", 409)
        job = ScanRun(network_range=str(network), profile=profile, ports_requested=json.dumps(ports), status="queued", progress=0, active_guard=1)
        session.add(job)
        try:
            session.commit()
        except IntegrityError:
            session.rollback()
            return fail("Another scan was queued by a concurrent request.", 409)
        job_id = job.id
        threading.Thread(target=run_scan, args=(job_id, ports, timeout), daemon=True).start()
    return jsonify(status="queued", id=job_id), 202


def set_job(job_id, **values):
    with Session() as session:
        job = session.get(ScanRun, job_id)
        if job:
            for key, value in values.items():
                setattr(job, key, value)
            if values.get("status") in ("completed", "failed"):
                job.active_guard = None
            session.commit()


def run_scan(job_id, ports, timeout):
    deadline = time.monotonic() + MAX_SCAN_SECONDS
    set_job(job_id, status="running", start_time=datetime.utcnow())
    try:
        with Session() as session:
            job = session.get(ScanRun, job_id)
            target = job.network_range
        scanner = NetworkScanner(target, timeout)
        found = scanner.arp_scan()
        with Session() as session:
            job = session.get(ScanRun, job_id)
            for index, item in enumerate(found):
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"Scan exceeded the {MAX_SCAN_SECONDS}-second total time limit.")
                host = Host(ip_address=item["ip"], mac_address=item["mac"], hostname=item.get("hostname"), scan_run=job)
                session.add(host)
                session.flush()
                for item_port in scanner.port_scan(host.ip_address, ports):
                    session.add(Port(port_number=item_port["port"], status=item_port["status"], service_name=item_port["service"], host=host))
                job.current_target = host.ip_address
                job.progress = int((index + 1) * 99 / max(len(found), 1))
                session.commit()
            job.progress = 100
            job.status = "completed"
            job.active_guard = None
            job.end_time = datetime.utcnow()
            session.commit()
    except Exception as exc:
        set_job(job_id, status="failed", error_message=str(exc)[:1000], end_time=datetime.utcnow())


@app.get("/scan/status")
def scan_status():
    with Session() as session:
        job = session.query(ScanRun).order_by(desc(ScanRun.id)).first()
        expire_stale_job(session, job)
        return jsonify(job=job_dict(job) if job else None, is_scanning=bool(job and job.status in ("queued", "running")))


@app.get("/scan/results")
def scan_results():
    with Session() as session:
        return jsonify(latest_results(session))


@app.get("/scan/history")
def scan_history():
    with Session() as session:
        jobs = session.query(ScanRun).order_by(desc(ScanRun.id)).limit(100).all()
        return jsonify([job_dict(job) for job in jobs])


@app.get("/scan/<int:job_id>/diff")
def scan_diff(job_id):
    with Session() as session:
        current = session.get(ScanRun, job_id)
        previous = session.query(ScanRun).filter(ScanRun.status == "completed", ScanRun.network_range == current.network_range, ScanRun.id < job_id).order_by(desc(ScanRun.id)).first() if current else None
        if not current or current.status != "completed":
            return fail("Completed scan not found.", 404)
        old = {(h.ip_address, p.port_number): p.status for h in previous.hosts for p in h.ports} if previous else {}
        new = {(h.ip_address, p.port_number): p.status for h in current.hosts for p in h.ports}
        changes = [{"ip": ip, "port": port, "before": old.get((ip, port)), "after": new.get((ip, port))}
                   for ip, port in sorted(set(old) | set(new)) if old.get((ip, port)) != new.get((ip, port))]
        old_hosts = {h.ip_address for h in previous.hosts} if previous else set()
        return jsonify(previous_scan_id=previous.id if previous else None,
                       new_hosts=sorted({h.ip_address for h in current.hosts} - old_hosts), changed_ports=changes)


@app.get("/scan/export.csv")
def export_csv():
    with Session() as session:
        job_id = request.args.get("job_id", type=int)
        job = session.get(ScanRun, job_id) if job_id else session.query(ScanRun).filter_by(status="completed").order_by(desc(ScanRun.id)).first()
        if not job or job.status != "completed":
            return fail("Completed scan not found.", 404)
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["ip", "hostname", "mac", "port", "status", "service"])
        for host in job.hosts:
            if host.ports:
                for port in host.ports:
                    writer.writerow([host.ip_address, host.hostname, host.mac_address, port.port_number, port.status, port.service_name])
            else:
                writer.writerow([host.ip_address, host.hostname, host.mac_address, "", "", ""])
    return Response(output.getvalue(), mimetype="text/csv", headers={"Content-Disposition": f"attachment; filename=scan-{job.id}.csv"})


if __name__ == "__main__":
    app.run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "5000")), debug=False)
