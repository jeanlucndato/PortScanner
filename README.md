# Network Inventory Scanner

An authenticated Flask dashboard for discovering IPv4 hosts and checking TCP ports on networks you are authorized to assess. Scan targets are entered directly in the dashboard; no CIDR allowlist needs to be edited in a configuration file.

## Features

- Enter an IPv4 address or CIDR range and confirm authorization before each scan.
- Discover hosts with ARP when raw-packet access is available. If it is not, the scanner falls back to checking common TCP ports.
- Choose the common, web, or database profile, or enter up to 256 custom TCP ports.
- View persistent scan jobs with status, progress, current host, timestamps, and errors.
- View host IP, MAC address when discovered through ARP, reverse-DNS hostname when available, and TCP port states: open, closed, or filtered.
- Search, filter, and sort results; compare completed scans of the same target; export results as CSV.
- Store scan history in SQLite using SQLAlchemy and automatic schema migrations.

## Requirements

- Python 3.10 or newer. Python 3.14 requires SQLAlchemy 2.0.44 or newer, which is included in the dependency constraint.
- Linux, macOS, or Windows with network access to the authorized target.
- ARP discovery works only on the local Ethernet segment. The TCP fallback does not require elevated privileges, but it can only find hosts that respond on one of its common probe ports.

## Install

From the project directory:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade -r requirements.txt
cp .env.example .env
```

On Windows PowerShell, activate the environment with:

```powershell
.venv\Scripts\Activate.ps1
```

The app loads `.env` automatically. It binds to `127.0.0.1` by default, so it is available only from the local computer.

## Configure authentication

The default login is:

- Username: `admin`
- Password: `admin1234`

Change these values in `.env` before allowing other people or computers to access the service:

```dotenv
SCANNER_USERNAME=admin
SCANNER_PASSWORD=replace-this-with-a-long-unique-password
```

Keep `.env` private. It is excluded from Git. The default credentials are intended only for local use.

## Start the app

For local use:

```bash
.venv/bin/python app.py
```

Open <http://127.0.0.1:5000> and enter the Basic Auth credentials when prompted. On Windows, run `.venv\Scripts\python.exe app.py`.

## Use the dashboard from an Android phone

The dashboard is responsive and works in a mobile browser; a separate Android APK is not required. The scanner continues to run on the computer, while the phone displays and controls its dashboard.

For a quick test on a trusted home or office Wi-Fi network:

1. Connect the computer running the scanner and the Android phone to the same Wi-Fi network.
2. Start the app with Waitress listening on the network interface:

   ```bash
   .venv/bin/waitress-serve --listen=0.0.0.0:5000 app:app
   ```

   On Windows, run `.venv\Scripts\waitress-serve.exe --listen=0.0.0.0:5000 app:app` from the activated virtual environment.
3. Find the computer's local IPv4 address (for example, in its network settings) and open `http://COMPUTER-IP:5000` in Chrome on the phone, replacing `COMPUTER-IP` with that address.
4. Sign in with `SCANNER_USERNAME` and `SCANNER_PASSWORD` from the computer's `.env` file. If the page does not load, check that the computer's firewall allows inbound TCP connections on port 5000 from the private network.

You can use Chrome's **Add to Home screen** option to create a shortcut. This is a browser shortcut to the web app, not a standalone or offline Android app. Keep the computer and scanner server running while using it.

**Security:** This quick LAN setup uses HTTP. Basic Auth credentials and dashboard traffic are not encrypted, so use it only on a trusted private network. Do not forward port 5000 to the internet or use this setup on public Wi-Fi. For access beyond a trusted LAN, put Waitress behind an HTTPS reverse proxy and use strong, unique credentials. The app's `HOST` setting applies when running `app.py` directly; the Waitress command above controls its own bind address.

For a single-host WSGI deployment, run Waitress behind an HTTPS reverse proxy:

```bash
.venv/bin/waitress-serve --listen=127.0.0.1:8080 app:app
```

Do not expose Flask's development server directly to a network. Use Waitress for network access. Protect Basic Auth with HTTPS for durable use or any access beyond a trusted private LAN. The application does not provide individual user accounts, roles, TLS termination, or audit-retention controls. Its job coordination and current migration implementation are intended for one application host using SQLite.

## Run a scan

1. Enter the IPv4 address or CIDR you are authorized to scan, such as `192.168.1.0/24`.
2. Select a scan profile, or enter comma-separated TCP ports such as `22,80,443`.
3. Set a per-port timeout if needed. The configured maximum is 2 seconds by default.
4. Check the authorization confirmation and start the scan.

The target is limited to 256 addresses by default. Configure limits in `.env`:

```dotenv
MAX_SCAN_HOSTS=256
MAX_SCAN_TIMEOUT=2
SCAN_TIMEOUT=0.5
MAX_SCAN_SECONDS=600
DATABASE_URL=sqlite:///scan_results.db
HOST=127.0.0.1
PORT=5000
```

The app rejects invalid IPv4 ranges, ranges above the host limit, invalid ports, and scans without the authorization confirmation. Only one scan can run at a time. A filtered port means no conclusive TCP response arrived before timeout; it does not prove that a firewall is present. TCP checks use regular socket connections and do not need root privileges.

## Database and migrations

The SQLite database is created automatically at startup. Schema migrations are versioned in the `schema_migrations` table and run automatically. Back up the database before deploying an update. Migration 1 adds scan-job metadata and removes the old global unique constraint on host IP while preserving existing records. Migration 2 adds a database guard that allows only one active scan.

The database and other runtime artifacts are ignored by Git. Keep regular backups and test restoring them.

## Troubleshooting

- **Scan fails immediately:** Read the error displayed in the dashboard. If ARP access is denied, the scanner attempts TCP-based discovery instead.
- **No hosts are found:** Confirm the CIDR matches the target network and that the computer has a route to it. TCP fallback only detects hosts that respond on common TCP ports; routed networks and hosts that filter those ports may not be discovered.
- **Ports appear filtered:** Increase the timeout within the configured limit, verify that the target is reachable, and interpret filtered results as inconclusive.
- **Python 3.14 with an old SQLAlchemy:** Run `python -m pip install --upgrade -r requirements.txt` in the active virtual environment.
- **Cannot sign in:** Use the configured `SCANNER_USERNAME` and `SCANNER_PASSWORD`; if unset, the local defaults are `admin` and `admin1234`.

Only scan systems and networks for which you have explicit authorization.
