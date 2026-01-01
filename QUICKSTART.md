# Airdump

**Wireless Signal Intelligence System for Security Audits**

Airdump is a drone-mounted wireless reconnaissance system designed to detect, fingerprint, and identify WiFi and Bluetooth devices across industrial properties. Built for security professionals conducting authorized wireless audits.

## Features

- **WiFi & Bluetooth Detection** - Captures all wireless devices via Kismet
- **Device Fingerprinting** - Identifies devices by behavior, not just MAC address
- **GPS Tagging** - Every detection tagged with coordinates (optional)
- **Whitelist Comparison** - Identify unauthorized devices against known inventory
- **Encrypted Storage** - SQLCipher database encryption for sensitive data
- **Multiple Reports** - HTML, JSON, CSV, and interactive maps
- **DJI Integration** - Correlate scan data with drone flight logs and photos
- **Swarm Mode** - Coordinate multiple drones from single controller
- **Automatic Cleanup** - Restores WiFi interface after scan

## Quick Start

### Prerequisites

```bash
# Install system dependencies
sudo apt install kismet gpsd gpsd-clients tshark python3-pip

# Install Python packages
pip3 install -r requirements.txt
```

### Basic Usage

```bash
# Start a 5-minute scan
./airdump scan --duration 300

# Start scan with GPS enabled
./airdump scan --duration 300 --gps

# Start scan and display results when done
./airdump scan --duration 300 --display

# Generate report for last scan
./airdump report

# Generate report for specific session
./airdump report --session airdump_scan_20251225_143022

# Show recent scans
./airdump status

# Stop running scan
./airdump stop
```

### With Database Encryption

```bash
# Scan with encrypted database (prompts for key)
./airdump --encryptdb scan --duration 300

# Or set key via environment variable
export AIRDUMP_DB_KEY="your-secure-key"
./airdump --encryptdb scan --duration 300
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `AIRDUMP_DB_KEY` | Database encryption key (alternative to interactive prompt) |
| `AIRDUMP_CONFIG` | Default config file path |
| `AIRDUMP_DATA_DIR` | Override data directory |

## CLI Reference

```
./airdump [global-options] <command> [command-options]

Global Options:
  --config, -c PATH     Config file (default: config/config.yaml)
  --data-dir, -d PATH   Data directory
  --encryptdb           Enable database encryption
  --verbose, -v         Verbose output

Commands:
  scan      Start a wireless scan
  report    Generate reports from scan data
  status    Show recent scan sessions
  stop      Stop running scan and restore interface
```

### Scan Options

| Option | Description |
|--------|-------------|
| `--duration, -t SECONDS` | Scan duration (default: unlimited, Ctrl+C to stop) |
| `--name, -n NAME` | Session name/description |
| `--property, -p ID` | Property identifier for reports |
| `--gps` | Enable GPS tracking (requires gpsd) |
| `--display` | Show results summary after scan |

### Report Options

| Option | Description |
|--------|-------------|
| `--session, -s ID` | Session ID (default: latest scan) |
| `--format, -f TYPES` | Output formats: html, json, csv, map |
| `--output, -o PATH` | Output directory |
| `--whitelist, -w FILE` | Known devices JSON for comparison |
| `--display` | Print summary to terminal |

---

## Configuration Reference

Config file: `config/config.yaml`

Variables like `${data_dir}` are expanded from the `general.data_dir` setting.

---

### General Settings

Node identification and paths.

```yaml
general:
  node_id: "drone_alpha"          # Unique identifier (used in swarm mode)
  property_id: "FACILITY-A"       # Default property for reports
  operator: "admin"               # Operator name for logs
  data_dir: "./data"              # Local dev (use /opt/airdump/data for production)
  log_level: "INFO"               # DEBUG, INFO, WARNING, ERROR
```

---

### Database

SQLite storage with optional SQLCipher encryption.

```yaml
database:
  path: "${data_dir}/database/airdump.db"
  encryption:
    enabled: false                # Enable with --encryptdb CLI flag
    key_file: "/run/airdump/db.key"  # RAM-only storage (tmpfs)
```

| Setting | Description |
|---------|-------------|
| `path` | Database file location |
| `encryption.enabled` | Enable SQLCipher encryption |
| `encryption.key_file` | Temporary key storage (use tmpfs for security) |

**Note:** When `--encryptdb` is used, key is prompted or read from `AIRDUMP_DB_KEY` env var.

---

### Kismet

Wireless detection engine. Kismet must be running separately.

```yaml
kismet:
  host: "localhost"
  port: 2501
  username: "kismet"
  password: "your-password"       # From kismet_httpd.conf
  poll_interval: 2.0              # Seconds between API polls
  wifi_interface: "wlan0"         # Interface for monitor mode
  bt_interface: "hci0"            # Bluetooth adapter
```

| Setting | Description |
|---------|-------------|
| `host`, `port` | Kismet REST API endpoint |
| `username`, `password` | API credentials (set in kismet_httpd.conf) |
| `poll_interval` | How often to query Kismet for new devices |
| `wifi_interface` | WiFi adapter (set to monitor mode by Kismet) |
| `bt_interface` | Bluetooth adapter for BT/BLE scanning |

---

### GPS

Position tracking via gpsd. Disabled by default.

```yaml
gps:
  enabled: false                  # Enable with --gps CLI flag
  host: "localhost"
  port: 2947                      # gpsd default port
  poll_interval: 1.0
  wait_for_fix: false             # Block scan start until GPS fix
  fix_timeout: 30                 # Seconds to wait for fix
  min_satellites: 4               # Minimum sats for valid fix
  export_gpx: true                # Export track as GPX file
```

| Setting | Description |
|---------|-------------|
| `enabled` | Master GPS switch (or use `--gps` flag) |
| `wait_for_fix` | If true, scan waits for GPS fix before starting |
| `fix_timeout` | Max seconds to wait for fix |
| `min_satellites` | Required satellites for position to be logged |
| `export_gpx` | Create GPX file of flight track |

---

### Packet Capture (tshark)

Deep packet capture for fingerprinting analysis.

```yaml
capture:
  enabled: true
  interface: ""                   # Empty = auto-detect monitor interface
  output_dir: "${data_dir}/pcap"
  rotate_size_mb: 100             # Rotate file at this size
  max_storage_mb: 10000           # Delete oldest when exceeded
  filter: ""                      # BPF filter (empty = capture all)
  gpg:
    enabled: true
    public_key: "${data_dir}/config/airdump-public.gpg"
    private_key: "${data_dir}/config/airdump-private.gpg"
```

| Setting | Description |
|---------|-------------|
| `interface` | Leave empty to auto-detect, or specify `wlan0mon` |
| `rotate_size_mb` | Start new capture file at this size |
| `max_storage_mb` | Total pcap storage limit |
| `filter` | Berkeley Packet Filter expression |
| `gpg.enabled` | Encrypt pcap files with GPG |
| `gpg.public_key` | GPG public key for encryption |
| `gpg.private_key` | GPG private key for decryption (keep secure!) |

**Generate GPG keypair:**
```bash
./airdump --create-keypair
```
This creates a 4096-bit RSA keypair. Keep the private key secure - copy it to your workstation and delete from drone after deployment.

---

### Channel Hopping

WiFi channel scanning strategy.

```yaml
channel_hopping:
  mode: "adaptive"                # fast, slow, or adaptive
  
  fast_hop:
    channels_24ghz: [1, 6, 11]
    channels_5ghz: [36, 40, 44, 48, 149, 153, 157, 161]
    dwell_ms: 150
    
  slow_hop:
    channels_24ghz: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
    channels_5ghz: [36, 40, 44, 48, 52, 56, 60, 64, ...]
    dwell_ms: 750
    
  adaptive:
    velocity_threshold_ms: 2.0    # m/s - fast hop above this speed
    hover_timeout_s: 5            # Seconds still before slow hop
```

| Mode | Use Case |
|------|----------|
| `fast` | Quick passes, beacon capture (150ms/channel) |
| `slow` | Hovering, client probe capture (750ms/channel) |
| `adaptive` | Auto-switch based on GPS velocity |

---

### Fingerprinting

Device identification by behavior patterns.

```yaml
fingerprinting:
  enabled: true
  signatures_db: "${data_dir}/config/fingerprints.db"
  min_confidence: 0.7             # 0.0-1.0, threshold for matches
  store_unknown: true             # Save unknown signatures for learning
```

| Setting | Description |
|---------|-------------|
| `signatures_db` | Known device signature database |
| `min_confidence` | Minimum match score to identify device |
| `store_unknown` | Store new fingerprints for future identification |

---

### Power Monitoring

Battery monitoring for drone payload (platform-specific).

```yaml
power:
  enabled: false
  adc_path: "/sys/bus/iio/devices/iio:device0/in_voltage0_raw"
  voltage_divider_ratio: 3.0
  warning_voltage: 7.0            # Warning threshold (2S LiPo)
  critical_voltage: 6.6           # Critical - save & prepare shutdown
  check_interval: 5
```

| Setting | Description |
|---------|-------------|
| `adc_path` | Sysfs path to ADC reading |
| `voltage_divider_ratio` | Scaling factor for voltage calculation |
| `warning_voltage` | Log warning below this voltage |
| `critical_voltage` | Initiate graceful shutdown |

---

### DJI Integration

Post-flight correlation with DJI drone data.

```yaml
dji_integration:
  enabled: true
  
  gps_upgrade:
    enabled: true
    time_tolerance_s: 1.0         # Match within this time window
    
  photo_linking:
    enabled: true
    radius_m: 10                  # Link photos within this distance
    time_tolerance_s: 5
    
  photo_capture:
    mode: "interval"              # interval, waypoint, manual
    interval_seconds: 3
```

**Purpose:** After flight, import DJI flight logs to:
- Upgrade GPS coordinates with higher-accuracy DJI positions
- Link geo-tagged photos to device detections

| Setting | Description |
|---------|-------------|
| `gps_upgrade.enabled` | Replace scan GPS with DJI log positions |
| `gps_upgrade.time_tolerance_s` | Max time diff for coordinate matching |
| `photo_linking.radius_m` | Link photos to devices within this distance |
| `photo_capture.mode` | How photos are triggered on drone |

---

### Remote Administration

SSH tunnel for in-flight monitoring (optional).

```yaml
remote:
  enabled: false
  
  jumphost:
    host: "jumphost.example.com"
    port: 22
    user: "tunnel"
    
  tunnel_port: 10001              # Unique per drone
  
  server_alive_interval: 30
  server_alive_count_max: 3
```

**Purpose:** Establish reverse SSH tunnel through a jumphost for remote access during flight.

| Setting | Description |
|---------|-------------|
| `jumphost.host` | SSH server to tunnel through |
| `tunnel_port` | Local port exposed on jumphost (unique per drone) |
| `server_alive_*` | SSH keepalive settings |

**Access:** `ssh -p 10001 scan@jumphost.example.com`

---

### Swarm Mode

Multi-drone coordination from single controller.

```yaml
swarm:
  enabled: false
  
  streaming:
    enabled: false
    output: "stdout"              # JSON-lines to stdout for controller
    
  heartbeat:
    enabled: true
    interval_s: 30
```

**Purpose:** Run multiple drones scanning different areas, controlled from one laptop/server.

| Setting | Description |
|---------|-------------|
| `streaming.enabled` | Stream detections as JSON-lines in real-time |
| `streaming.output` | Output destination (stdout for SSH capture) |
| `heartbeat.interval_s` | Status report frequency to controller |

**Architecture:**
```
Controller (laptop) ──► Jumphost ──┬── Drone A (client)
                                   ├── Drone B (client)
                                   └── Drone C (client)
```

---

### Analysis & Reporting

Post-scan analysis configuration.

```yaml
analysis:
  whitelist_path: "${data_dir}/config/known_devices.json"
  rssi_threshold: -85             # Ignore signals weaker than this
  reports_dir: "${data_dir}/reports"
  formats:
    - html
    - json
    - csv
```

| Setting | Description |
|---------|-------------|
| `whitelist_path` | Known devices JSON for comparison |
| `rssi_threshold` | Filter out weak/distant signals |
| `reports_dir` | Where reports are saved |
| `formats` | Default report formats to generate |

---

## Output Files

All files prefixed with `airdump_`:

| File Pattern | Description |
|--------------|-------------|
| `airdump_scan_YYYYMMDD_HHMMSS` | Session ID format |
| `airdump_report_*.html` | Interactive HTML report |
| `airdump_report_*.json` | Machine-readable JSON |
| `airdump_devices_*.csv` | Device list spreadsheet |
| `airdump_map_*.html` | Interactive map with markers |
| `airdump_capture_*.pcapng` | Packet capture file |

## Data Directory Structure

```
data/
├── database/
│   └── airdump.db          # SQLite database
├── pcap/                   # Packet captures
├── reports/                # Generated reports
├── config/
│   ├── known_devices.json  # Device whitelist
│   └── fingerprints.db     # Signature database
└── logs/                   # Application logs
```

## Troubleshooting

**WiFi stuck in monitor mode:**
```bash
./airdump stop
# Or manually:
sudo ip link set wlan0 down
sudo iw dev wlan0 set type managed
sudo ip link set wlan0 up
```

**Kismet connection failed:**
```bash
# Start Kismet first
sudo kismet -c wlan0
```

**No devices detected:**
- Ensure WiFi adapter supports monitor mode
- Check Kismet is receiving data: `http://localhost:2501`

## License

Private/Internal Use - Authorized security testing only.

---

*Built for drone-based wireless security audits. Always obtain proper authorization before scanning.*
