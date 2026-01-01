# Project Airdump - Usage Guide

Complete usage documentation for Project Airdump wireless reconnaissance system.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Shell Scripts](#shell-scripts)
  - [start_scan.sh](#start_scansh)
  - [stop_scan.sh](#stop_scansh)
  - [preflight_check.sh](#preflight_checksh)
- [Scan Orchestrator](#scan-orchestrator)
- [Configuration](#configuration)
- [Systemd Services](#systemd-services)
- [Analysis & Reporting](#analysis--reporting)
- [Database Operations](#database-operations)
- [Troubleshooting](#troubleshooting)

---

## Quick Start

### First-Time Setup

```bash
# 1. Install Python dependencies
pip install -r requirements.txt

# 2. Copy and edit configuration
cp config/config.yaml.example config/config.yaml
# Edit config/config.yaml with your settings (Kismet credentials, etc.)

# 3. Verify Kismet credentials match your ~/.kismet/kismet_httpd.conf
cat ~/.kismet/kismet_httpd.conf

# 4. Run pre-flight check
sudo ./scripts/preflight_check.sh

# 5. Start a test scan (15 seconds with mock GPS)
sudo ./scripts/start_scan.sh all --duration 15 --mock-gps
```

### Typical Drone Flight

```bash
# Pre-flight verification
sudo ./scripts/preflight_check.sh

# Start scan (5 minute duration)
sudo ./scripts/start_scan.sh all --duration 300

# Or unlimited duration (stop manually)
sudo ./scripts/start_scan.sh all

# Stop scan gracefully
sudo ./scripts/stop_scan.sh
```

---

## Shell Scripts

All scripts are located in the `scripts/` directory and require root privileges.

### start_scan.sh

**Purpose**: Start wireless scanning with automatic monitor mode setup.

**Usage**:
```bash
sudo ./scripts/start_scan.sh [MODE] [OPTIONS]
```

**Modes**:

| Mode | Description |
|------|-------------|
| `all` | Start all scanners (WiFi + Bluetooth) - **default** |
| `wifi` | WiFi scanning only |
| `bt` | Bluetooth scanning only |

**Options**:

| Option | Argument | Description |
|--------|----------|-------------|
| `--duration` | SECONDS | Scan duration in seconds. Omit for unlimited. |
| `--session-name` | NAME | Custom session name for identification |
| `--property-id` | ID | Property identifier for reports |
| `--mock-gps` | - | Use simulated GPS (for testing without GPS hardware) |
| `--help`, `-h` | - | Show help message |

**Examples**:

```bash
# Basic 5-minute scan
sudo ./scripts/start_scan.sh all --duration 300

# Named scan session for specific property
sudo ./scripts/start_scan.sh all --duration 600 \
    --session-name "Building-A-Survey" \
    --property-id "FACILITY-001"

# Test scan with mock GPS (no GPS hardware needed)
sudo ./scripts/start_scan.sh all --duration 60 --mock-gps

# Unlimited duration scan (stop manually with stop_scan.sh)
sudo ./scripts/start_scan.sh all

# WiFi only scan
sudo ./scripts/start_scan.sh wifi --duration 300
```

**What it does**:
1. Checks for root privileges
2. Verifies dependencies (Python, Kismet, tshark, gpsd)
3. Auto-detects WiFi interface (`wlan*` or `wlp*`)
4. Automatically enables monitor mode (via `airmon-ng` or `iw`)
5. Kills interfering processes (NetworkManager, wpa_supplicant)
6. Starts gpsd and Kismet if not running
7. Launches the scan orchestrator

---

### stop_scan.sh

**Purpose**: Gracefully stop all scanning and restore WiFi interface.

**Usage**:
```bash
sudo ./scripts/stop_scan.sh
```

**No arguments required.**

**What it does**:
1. Sends SIGTERM to scan orchestrator for graceful shutdown
2. Waits up to 10 seconds for clean exit
3. Force kills if still running
4. Restores WiFi interface from monitor mode to managed mode
5. Restarts NetworkManager (if available)
6. Cleans up temporary files

**Example**:
```bash
# Stop running scan
sudo ./scripts/stop_scan.sh
```

---

### preflight_check.sh

**Purpose**: Verify all systems operational before a scan or drone flight.

**Usage**:
```bash
sudo ./scripts/preflight_check.sh
```

**Checks performed**:

| Check | Status | Description |
|-------|--------|-------------|
| Root Access | PASS/FAIL | Script running as root |
| Python | PASS/FAIL | Python 3 available with version |
| Disk Space | PASS/WARN | Free space on data partition |
| Free RAM | PASS/WARN | Available memory |
| gpsd | PASS/WARN | GPS daemon running |
| Kismet | PASS/WARN | Kismet daemon running |
| WiFi Interface | PASS/FAIL | Wireless adapter detected |
| Monitor Mode | PASS/WARN | Interface in monitor mode |
| GPS Device | PASS/WARN | GPS hardware detected |
| GPS Fix | PASS/WARN | GPS has location fix |
| Config File | PASS/FAIL | config.yaml exists |
| Data Directory | PASS/FAIL | data/ directory exists |

**Exit codes**:
- `0` - All critical checks passed
- `1` - One or more critical checks failed

**Example output**:
```
=========================================
  Airdump Pre-flight Check
=========================================

## System Checks ##
[PASS] Root Access: Running as root
[PASS] Python: Python 3.11.0
[PASS] Disk Space: 50G free
[PASS] Free RAM: 2.1G available

## Service Checks ##
[PASS] gpsd: Running
[PASS] Kismet: Running

## Network Checks ##
[PASS] WiFi Interface: wlan0 found
[PASS] Monitor Mode: wlan0mon active

## GPS Checks ##
[PASS] GPS Device: /dev/ttyUSB0
[PASS] GPS Fix: 3D fix (8 satellites)

## Configuration Checks ##
[PASS] Config File: config/config.yaml exists
[PASS] Data Directory: data/ exists

=========================================
  Results: 12 passed, 0 warnings, 0 failed
=========================================
Pre-flight check PASSED - Ready for scan
```

---

## Scan Orchestrator

The Python scan orchestrator is the core scanning engine. It can be run directly for more control.

**Usage**:
```bash
sudo python3 -m scan_orchestrator [OPTIONS]
```

**Options**:

| Option | Argument | Default | Description |
|--------|----------|---------|-------------|
| `--config` | PATH | `config/config.yaml` | Configuration file path |
| `--data-dir` | PATH | `data` | Data output directory |
| `--duration` | SECONDS | unlimited | Scan duration |
| `--session-name` | NAME | auto-generated | Session identifier |
| `--property-id` | ID | from config | Property being scanned |
| `--mock-gps` | - | false | Use simulated GPS data |

**Examples**:

```bash
# Basic scan with custom config
sudo python3 -m scan_orchestrator --config /path/to/config.yaml

# 10-minute scan with custom data directory
sudo python3 -m scan_orchestrator --duration 600 --data-dir /mnt/data/scans

# Named session for specific property
sudo python3 -m scan_orchestrator \
    --duration 300 \
    --session-name "Warehouse-Survey" \
    --property-id "WH-001"

# Testing without GPS hardware
sudo python3 -m scan_orchestrator --mock-gps --duration 60
```

**Session IDs**:

Sessions are automatically named with format: `YYYYMMDD_HHMMSS`  
Example: `20251225_143052`

---

## Configuration

### Configuration File Location

```
config/config.yaml
```

Copy from `config/config.yaml.example` if not exists.

### Key Configuration Sections

#### General Settings

```yaml
general:
  node_id: "drone_alpha"        # Unique identifier (for swarm mode)
  property_id: "FACILITY-A"     # Default property ID
  operator: "admin"             # Operator name for reports
  data_dir: "/opt/airdump/data" # Where to store scan data
  log_level: "INFO"             # DEBUG, INFO, WARNING, ERROR
```

#### Kismet Connection

```yaml
kismet:
  host: "localhost"
  port: 2501
  username: "kismet"            # Must match ~/.kismet/kismet_httpd.conf
  password: "your_password"     # Must match ~/.kismet/kismet_httpd.conf
  poll_interval: 2.0            # Seconds between device polls
```

**Finding your Kismet credentials**:
```bash
cat ~/.kismet/kismet_httpd.conf
# or for root user:
sudo cat /root/.kismet/kismet_httpd.conf
```

#### GPS Settings

```yaml
gps:
  host: "localhost"
  port: 2947                    # gpsd default port
  poll_interval: 1.0            # GPS update rate
  fix_timeout: 30               # Seconds to wait for GPS fix
  min_satellites: 4             # Minimum satellites for valid fix
```

#### Packet Capture

```yaml
capture:
  enabled: true
  interface: ""                 # Empty = auto-detect monitor interface
  output_dir: "${data_dir}/pcap"
  rotate_size_mb: 100           # Rotate pcap files at this size
  max_storage_mb: 10000         # Delete oldest when exceeded
  filter: ""                    # BPF filter (empty = capture all)
```

#### Channel Hopping

```yaml
channel_hopping:
  mode: "adaptive"              # fast, slow, or adaptive
  
  fast_hop:
    channels_24ghz: [1, 6, 11]
    dwell_ms: 150               # Time per channel
    
  slow_hop:
    channels_24ghz: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
    dwell_ms: 750
    
  adaptive:
    velocity_threshold_ms: 2.0  # Switch to fast hop above this speed
    hover_timeout_s: 5          # Seconds stationary before slow hop
```

| Mode | Use Case | Dwell Time |
|------|----------|------------|
| `fast` | Moving quickly, catching APs | 150ms |
| `slow` | Hovering, catching client probes | 750ms |
| `adaptive` | Auto-switches based on GPS velocity | Dynamic |

#### Power Monitoring

```yaml
power:
  enabled: true
  warning_voltage: 7.0          # 2S LiPo warning
  critical_voltage: 6.6         # Begin graceful shutdown
  check_interval: 5             # Seconds between checks
```

---

## Systemd Services

For automated/unattended drone flights.

### Enable Automatic Scanning on Boot

```bash
# Enable all services
sudo systemctl enable airdump.target

# Start immediately
sudo systemctl start airdump.target
```

### Disable Automatic Mode

```bash
sudo systemctl disable airdump.target
sudo systemctl stop airdump.target
```

### Service Management

```bash
# Check status of all Airdump services
sudo systemctl status airdump-*

# View logs
sudo journalctl -u airdump.service -f

# Restart Kismet only
sudo systemctl restart airdump-kismet.service
```

### Available Services

| Service | Description |
|---------|-------------|
| `airdump.service` | Main scan orchestrator |
| `airdump-monitor.service` | Monitor mode setup |
| `airdump.target` | Combined target for all services |

---

## Analysis & Reporting

### Prerequisites

Install required Python packages for full report generation:

```bash
# Install system-wide (required for sudo access)
sudo pip install folium jinja2

# Or add to requirements.txt
pip install -r requirements.txt
```

| Package | Purpose |
|---------|---------|
| `jinja2` | HTML report generation |
| `folium` | Interactive map generation |

### List Available Sessions

Before generating reports, find your session ID:

```bash
# List recent scan sessions
sudo python3 -c "
import sqlite3
conn = sqlite3.connect('/opt/airdump/data/database/airdump.db')
conn.row_factory = sqlite3.Row
for row in conn.execute('SELECT session_id, start_time, status, wifi_device_count FROM scan_sessions ORDER BY id DESC LIMIT 10'):
    print(dict(row))
"
```

### Generate Reports

After a scan completes, generate reports from the database.

**Note**: Requires `sudo` because the database is owned by root.

**Usage**:
```bash
sudo python3 -m analysis.reporter --session-id SESSION_ID [OPTIONS]
```

**Options**:

| Option | Argument | Description |
|--------|----------|-------------|
| `--session-id` | ID | **Required**. Scan session ID (e.g., `20251225_071342`) |
| `--all` | - | Generate all report formats |
| `--format` | FORMAT | Generate specific format: `html`, `json`, `csv`, `map` |
| `--database` | PATH | Database path (default: `/opt/airdump/data/database/airdump.db`) |
| `--output-dir` | PATH | Output directory (default: `/opt/airdump/data/reports`) |
| `--whitelist` | PATH | Whitelist file for device comparison |

**Examples**:

```bash
# Generate all report formats for a session
sudo python3 -m analysis.reporter --session-id 20251225_071342 --all

# Generate specific formats
sudo python3 -m analysis.reporter --session-id 20251225_071342 --format html
sudo python3 -m analysis.reporter --session-id 20251225_071342 --format json
sudo python3 -m analysis.reporter --session-id 20251225_071342 --format csv

# Generate with whitelist comparison
sudo python3 -m analysis.reporter --session-id 20251225_071342 --all \
    --whitelist config/known_devices.json

# Custom output directory
sudo python3 -m analysis.reporter --session-id 20251225_071342 --all \
    --output-dir /home/user/reports
```

**Output**:

Reports are saved to `/opt/airdump/data/reports/` by default:

| Format | Filename | Description |
|--------|----------|-------------|
| HTML | `report_SESSION_TIMESTAMP.html` | Interactive report with styling |
| JSON | `report_SESSION_TIMESTAMP.json` | Machine-readable data export |
| CSV | `devices_SESSION_TIMESTAMP.csv` | Spreadsheet-compatible device list |
| Map | `map_SESSION_TIMESTAMP.html` | Interactive Folium map (requires GPS data) |

**Example Output**:
```
Generated reports for session 20251225_071342:
  html: /opt/airdump/data/reports/report_20251225_071342_20251225_083015.html
  json: /opt/airdump/data/reports/report_20251225_071342_20251225_083015.json

Analysis Summary:
  Total WiFi devices: 42
  Total BT devices: 15
  Unknown devices: 12
  Suspicious devices: 2
```

### Compare Against Whitelist

```bash
# Analyze scan and compare against known devices
sudo python3 -m analysis.analyzer --session-id 20251225_143052 \
    --whitelist config/known_devices.json
```

### Whitelist Format

Create `config/known_devices.json`:

```json
{
  "devices": [
    {
      "identifier": "AA:BB:CC:DD:EE:FF",
      "match_type": "mac",
      "name": "Office AP",
      "category": "infrastructure",
      "notes": "Main building access point"
    },
    {
      "identifier": "00:1A:2B",
      "match_type": "oui",
      "name": "Company Devices",
      "category": "corporate",
      "notes": "All company-issued devices"
    },
    {
      "identifier": "CorpWiFi",
      "match_type": "ssid",
      "name": "Corporate Network",
      "category": "infrastructure"
    }
  ]
}
```

**Match Types**:

| Type | Description | Example |
|------|-------------|---------|
| `mac` | Exact MAC address | `AA:BB:CC:DD:EE:FF` |
| `oui` | MAC prefix (manufacturer) | `00:1A:2B` |
| `ssid` | WiFi network name | `CorpWiFi` |
| `fingerprint` | Device fingerprint hash | `a1b2c3d4...` |

---

## Database Operations

### View Sessions

```bash
# List all scan sessions
python3 -c "
import sqlite3
conn = sqlite3.connect('/opt/airdump/data/database/airdump.db')
conn.row_factory = sqlite3.Row
for row in conn.execute('SELECT session_id, start_time, end_time, status FROM scan_sessions ORDER BY id DESC LIMIT 10'):
    print(dict(row))
"
```

### Export Data

```bash
# Export WiFi devices to JSON
python3 -c "
import sqlite3, json
conn = sqlite3.connect('/opt/airdump/data/database/airdump.db')
conn.row_factory = sqlite3.Row
devices = [dict(r) for r in conn.execute('SELECT * FROM wifi_devices')]
print(json.dumps(devices, indent=2))
" > wifi_devices.json
```

### Database Location

Default: `/opt/airdump/data/database/airdump.db`

Can be changed in `config/config.yaml`:
```yaml
database:
  path: "${data_dir}/database/airdump.db"
```

---

## Troubleshooting

### Common Issues

#### "401 Unauthorized" from Kismet

**Cause**: Kismet API credentials mismatch.

**Solution**:
```bash
# Check your Kismet credentials
cat ~/.kismet/kismet_httpd.conf
# or
sudo cat /root/.kismet/kismet_httpd.conf

# Update config/config.yaml to match
kismet:
  username: "kismet"
  password: "YOUR_ACTUAL_PASSWORD"

# If Kismet was started as root, copy credentials
sudo cp ~/.kismet/kismet_httpd.conf /root/.kismet/
sudo pkill kismet
sudo kismet --daemonize
```

#### "No WiFi interface found"

**Cause**: WiFi adapter not detected or not compatible.

**Solution**:
```bash
# Check available interfaces
iw dev

# Check if adapter supports monitor mode
iw phy phy0 info | grep -A 10 "Supported interface modes"

# Manually set monitor mode
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
```

#### "gpsd not running" / "GPS features disabled"

**Cause**: gpsd service not installed or not running.

**Solution**:
```bash
# Install gpsd
sudo apt install gpsd gpsd-clients

# Start gpsd with your GPS device
sudo gpsd /dev/ttyUSB0 -F /var/run/gpsd.sock

# Or use mock GPS for testing
sudo ./scripts/start_scan.sh all --mock-gps --duration 60
```

#### "Monitor mode failed"

**Cause**: NetworkManager or wpa_supplicant interfering.

**Solution**:
```bash
# Kill interfering processes
sudo airmon-ng check kill

# Or manually
sudo systemctl stop NetworkManager
sudo systemctl stop wpa_supplicant
```

#### WiFi Not Restored After Scan

**Cause**: stop_scan.sh didn't run or failed.

**Solution**:
```bash
# Manually restore managed mode
sudo airmon-ng stop wlan0mon
# or
sudo ip link set wlan0mon down
sudo iw dev wlan0mon set type managed
sudo ip link set wlan0mon up

# Restart NetworkManager
sudo systemctl restart NetworkManager
```

### Debug Mode

Enable verbose logging:

```yaml
# config/config.yaml
general:
  log_level: "DEBUG"
```

View logs:
```bash
tail -f data/logs/airdump.log
```

### Test Kismet Connection

```bash
# Test API connection
curl -u kismet:YOUR_PASSWORD http://localhost:2501/system/status.json | python3 -m json.tool
```

### Check Interface Status

```bash
# Show all wireless interfaces
iw dev

# Check interface mode
iw dev wlan0 info | grep type
```

---

## Data Directory Structure

```
data/
├── database/
│   └── airdump.db          # SQLite database
├── pcap/
│   └── capture_*.pcapng    # Packet captures
├── logs/
│   └── airdump.log         # Application logs
├── reports/
│   ├── report_*.html       # HTML reports
│   ├── report_*.json       # JSON exports
│   └── heatmap_*.html      # GPS heatmaps
└── scans/
    └── SESSION_ID/         # Per-session data
```

---

## Signal Handling

The scan orchestrator handles these signals gracefully:

| Signal | Action |
|--------|--------|
| `SIGTERM` | Graceful shutdown, flush data |
| `SIGINT` (Ctrl+C) | Graceful shutdown, flush data |

Data is always flushed to database before exit.

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `AIRDUMP_CONFIG` | Override config file path |
| `AIRDUMP_DATA_DIR` | Override data directory |

---

## Quick Reference Card

```bash
# Pre-flight check
sudo ./scripts/preflight_check.sh

# Start scan (5 minutes)
sudo ./scripts/start_scan.sh all --duration 300

# Start scan (unlimited, stop manually)
sudo ./scripts/start_scan.sh all

# Stop scan
sudo ./scripts/stop_scan.sh

# Test without GPS
sudo ./scripts/start_scan.sh all --duration 60 --mock-gps

# Check Kismet API
curl -u kismet:PASSWORD http://localhost:2501/system/status.json

# View recent sessions
python3 -c "import sqlite3; c=sqlite3.connect('/opt/airdump/data/database/airdump.db'); [print(r) for r in c.execute('SELECT session_id, status FROM scan_sessions ORDER BY id DESC LIMIT 5')]"

# Kill stuck Kismet
sudo pkill -9 kismet

# Restore WiFi interface
sudo airmon-ng stop wlan0mon
sudo systemctl restart NetworkManager
```
