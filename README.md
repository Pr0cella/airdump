# Project Airdump

**Wireless Signal Intelligence System for Industrial Property Security Audits**

## Note: Work in progress.

A drone-mounted wireless reconnaissance system to detect, fingerprint, and identify unknown Bluetooth, WiFi, and RF devices across industrial properties. Uses Kismet for wireless detection, tshark for deep packet analysis, with planned SDR integration for broader RF spectrum monitoring. Designed to run on a ZeroPi SBC with support for both automated (systemd) and manual operation modes.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Directory Structure](#directory-structure)
- [Hardware Requirements](#hardware-requirements)
- [Software Dependencies](#software-dependencies)
- [Operation Modes](#operation-modes)
- [Channel Hopping Strategy](#channel-hopping-strategy)
- [Module Specifications](#module-specifications)
- [Device Fingerprinting](#device-fingerprinting)
- [DJI Mavic 2 Integration](#dji-mavic-2-integration)
- [Known Devices Whitelist](#known-devices-whitelist)
- [Data Storage](#data-storage)
- [Reports & Analysis](#reports--analysis)
- [SDR Integration Roadmap](#sdr-integration-roadmap)
- [Security Considerations](#security-considerations)
- [Implementation Phases](#implementation-phases)

---

## Overview

### Purpose

Perform comprehensive wireless signal surveys of private industrial properties to:

1. **Discovery Mode**: Collect baseline inventory of all WiFi and Bluetooth devices
2. **Audit Mode**: Compare detected devices against a known whitelist to identify unauthorized/unknown signals

### Key Features

- **Kismet-based scanning** for WiFi and Bluetooth with REST API integration
- **tshark packet capture** for deep protocol analysis and device fingerprinting
- **Device fingerprinting engine** to identify unknown devices by behavior signatures
- **GPS-tagged datapoints** - every detection includes coordinates
- **Future SDR support** for broader RF spectrum monitoring (433MHz, 868MHz, etc.)
- Flexible operation: systemd autostart OR manual execution
- Optional whitelist comparison (skip for initial baseline collection)
- SQLite storage with full GPS track logging
- Post-flight analysis and reporting tools

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          DRONE PLATFORM                                  │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │                         ZeroPi SBC                                   ││
│  │                                                                      ││
│  │  ┌────────────────────────────────────────────────────────────────┐ ││
│  │  │                    CAPTURE LAYER                                │ ││
│  │  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │ ││
│  │  │  │    Kismet    │  │    tshark    │  │   SDR (Future)       │  │ ││
│  │  │  │ WiFi + BT    │  │ Packet PCAP  │  │   rtl_433/gnuradio   │  │ ││
│  │  │  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────┘  │ ││
│  │  └─────────┼─────────────────┼────────────────────┼───────────────┘ ││
│  │            │                 │                    │                  ││
│  │  ┌─────────▼─────────────────▼────────────────────▼───────────────┐ ││
│  │  │                  PROCESSING LAYER                               │ ││
│  │  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │ ││
│  │  │  │ Fingerprint  │  │     GPS      │  │    Data Fusion       │  │ ││
│  │  │  │    Engine    │  │    Tagger    │  │    & Correlation     │  │ ││
│  │  │  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────┘  │ ││
│  │  └─────────┼─────────────────┼────────────────────┼───────────────┘ ││
│  │            │                 │                    │                  ││
│  │            └─────────────────┴────────────────────┘                  ││
│  │                              │                                       ││
│  │                       ┌──────▼──────┐                               ││
│  │                       │  Data Store │                               ││
│  │                       │   (SQLite)  │                               ││
│  │                       └─────────────┘                               ││
│  └─────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼ (Post-flight)
┌─────────────────────────────────────────────────────────────────────────┐
│                        ANALYSIS WORKSTATION                              │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────────┐ │
│  │ Known Devices   │  │   Comparator    │  │     Report Suite        │ │
│  │   Whitelist     │──▶│    Engine       │──▶│  • Unknown Devices     │ │
│  │   (Optional)    │  │                 │  │  • Fingerprint Matches  │ │
│  │                 │  │  Fingerprint DB │  │  • GPS Heat Maps        │ │
│  │                 │  │       ▲         │  │  • Temporal Analysis    │ │
│  └─────────────────┘  └───────┼─────────┘  └─────────────────────────┘ │
│                               │                                         │
│                    ┌──────────┴──────────┐                             │
│                    │  Signature Database │                             │
│                    │  (Device Profiles)  │                             │
│                    └─────────────────────┘                             │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Directory Structure

```
Project Airdump/
├── README.md                    # This file
├── requirements.txt             # Python dependencies
├── config/
│   ├── config.yaml              # Main configuration
│   ├── kismet.conf              # Kismet configuration overlay
│   ├── known_devices.json       # Whitelist (optional)
│   └── fingerprints.db          # Device fingerprint signatures
├── scanners/
│   ├── __init__.py
│   ├── kismet_controller.py     # Kismet REST API interface
│   ├── tshark_capture.py        # Packet capture & parsing
│   ├── sdr_scanner.py           # SDR integration (future)
│   └── gps_logger.py            # GPS coordinate logger
├── drone/
│   ├── __init__.py
│   ├── dji_correlator.py        # DJI flight log correlation
│   ├── dji_log_parser.py        # Parse DJI .DAT/.txt logs
│   ├── photo_linker.py          # Link geo-tagged photos to scans
│   └── power_monitor.py         # Battery voltage monitoring
├── fingerprinting/
│   ├── __init__.py
│   ├── engine.py                # Main fingerprinting logic
│   ├── wifi_fingerprint.py      # 802.11 probe/IE analysis
│   ├── bt_fingerprint.py        # Bluetooth SDP/GATT analysis
│   ├── oui_lookup.py            # MAC manufacturer lookup
│   └── signatures.py            # Signature matching algorithms
├── core/
│   ├── __init__.py
│   ├── database.py              # SQLite data layer
│   ├── models.py                # Data models
│   ├── gps_tagger.py            # GPS coordinate injection
│   └── utils.py                 # Shared utilities
├── analysis/
│   ├── __init__.py
│   ├── analyzer.py              # Comparison engine
│   ├── reporter.py              # Report generation
│   ├── heatmap.py               # GPS-based signal mapping
│   └── temporal.py              # Time-based pattern analysis
├── scripts/
│   ├── start_scan.sh            # Main scan launcher (manual mode)
│   ├── stop_scan.sh             # Graceful shutdown
│   ├── preflight_check.sh       # Pre-flight systems verification
│   ├── setup_interfaces.sh      # Configure WiFi monitor mode
│   └── install_dependencies.sh  # System setup script
├── systemd/
│   ├── airdump-kismet.service   # Kismet daemon service
│   ├── airdump-capture.service  # tshark capture service
│   ├── airdump-gps.service      # GPS logger service
│   ├── airdump-power.service    # Battery/power monitor service
│   └── airdump.target           # Combined target for all services
├── data/
│   ├── scans/                   # Raw scan outputs
│   ├── pcap/                    # Packet capture files
│   ├── dji/                     # DJI flight logs & photos
│   ├── database/                # SQLite database files
│   └── reports/                 # Generated reports
├── oui/
│   └── oui.txt                  # IEEE OUI database
└── tests/
    ├── test_kismet_controller.py
    ├── test_fingerprinting.py
    └── test_analyzer.py
```

---

## Hardware Requirements

| Component | Recommendation | Notes |
|-----------|---------------|-------|
| **SBC** | ZeroPi / Orange Pi Zero 2 | ARM-based, lightweight, 512MB+ RAM (1GB+ recommended for Kismet) |
| **WiFi Adapter** | Alfa AWUS036ACH / RTL8812AU-based | Must support monitor mode & packet injection |
| **Bluetooth** | Built-in or CSR 4.0 USB dongle | BLE support required for modern devices |
| **GPS** | U-blox NEO-6M/7M USB module | **Required** for location-tagged datapoints |
| **Storage** | 64GB+ microSD (Class 10/A1) | Fast write speeds for pcap capture |
| **Power** | 5V 3A from drone or powerbank | Stable power critical for reliability |
| **SDR (Future)** | RTL-SDR v3 / RTL-SDR Blog v4 | 24MHz-1.7GHz coverage for RF scanning |

### Tested Configurations

- ZeroPi + AWUS036ACH + CSR 4.0 dongle + NEO-6M GPS
- Orange Pi Zero 2 + RTL8812BU adapter + onboard BT + NEO-7M GPS

### WiFi Adapter Compatibility (Monitor Mode)

| Chipset | Monitor Mode | Packet Injection | Recommended |
|---------|--------------|------------------|-------------|
| RTL8812AU | ✅ | ✅ | ✅ Yes |
| RTL8814AU | ✅ | ✅ | ✅ Yes |
| MT7612U | ✅ | ✅ | ✅ Yes |
| RTL8812BU | ✅ | ⚠️ Limited | Acceptable |
| Atheros AR9271 | ✅ | ✅ | ✅ Yes (2.4GHz only) |

---

## Software Dependencies

### System Packages

```bash
# Kismet - primary wireless detection
kismet                   # WiFi + Bluetooth + SDR detection framework

# Packet capture
tshark                   # Wireshark CLI for deep packet analysis
tcpdump                  # Lightweight alternative capture

# Bluetooth stack
bluez                    # Bluetooth stack (for Kismet BT source)
bluez-tools              # Additional BT utilities

# GPS support
gpsd                     # GPS daemon
gpsd-clients             # GPS utilities (cgps, gpsmon)

# SDR support (future)
rtl-sdr                  # RTL-SDR drivers
rtl-433                  # 433/868/915 MHz decoder

# Python runtime
python3
python3-pip
python3-venv

# Build tools (for some Python packages)
build-essential
libpcap-dev
```

### Python Packages

```
pyyaml>=6.0              # Configuration parsing
requests>=2.28           # Kismet REST API client
sqlite-utils>=3.0        # SQLite helper library
gpsd-py3>=0.3.0          # GPS daemon interface
pyshark>=0.6             # tshark Python wrapper
scapy>=2.5               # Packet manipulation/analysis
jinja2>=3.0              # Report templating
rich>=13.0               # Terminal output formatting
folium>=0.14             # GPS heat map generation
pandas>=2.0              # Data analysis
```

### Kismet Configuration

Kismet runs as a daemon and exposes a REST API for programmatic access:

```bash
# Default Kismet API endpoint
http://localhost:2501

# Key API endpoints used:
GET  /devices/all_devices.json       # All detected devices
GET  /gps/location.json              # Current GPS position
GET  /phy/phy80211/devices.json      # WiFi-specific devices
GET  /phy/BTLE/devices.json          # Bluetooth LE devices
POST /datasource/add_source.json     # Add capture interface
```

---

## Operation Modes

### Mode 1: Automatic (systemd) - For Drone Flights

Scanners start automatically on boot. Ideal for unattended drone operations.

```bash
# Enable autostart
sudo systemctl enable airdump.target

# Disable autostart (for manual mode)
sudo systemctl disable airdump.target

# Check status
sudo systemctl status airdump-kismet.service
sudo systemctl status airdump-capture.service
sudo systemctl status airdump-gps.service
```

### Mode 2: Manual - For Granular Control

Run scanners individually with custom parameters.

```bash
# Start full scan suite manually
sudo ./scripts/start_scan.sh all --duration 300

# Start only Kismet (WiFi + BT detection)
sudo ./scripts/start_scan.sh kismet --duration 300

# Start only tshark capture (packet-level analysis)
sudo ./scripts/start_scan.sh capture --duration 300 --filter "wlan"

# Start with specific channels
sudo ./scripts/start_scan.sh all --channels 1,6,11 --duration 600

# Stop all scanners gracefully
sudo ./scripts/stop_scan.sh
```

### Mode Selection Logic

| Scenario | Recommended Mode |
|----------|------------------|
| Routine drone survey | Automatic (systemd) |
| Initial baseline collection | Manual |
| Targeted area investigation | Manual |
| Testing/debugging | Manual |
| Production flights | Automatic (systemd) |

---

## Channel Hopping Strategy

### The Challenge

WiFi operates across multiple channels, but your adapter can only listen to **one channel at a time**. During drone flight, you may only be in range of a device for 5-15 seconds, making channel strategy critical.

| Factor | Impact |
|--------|--------|
| **Flight speed** | Moving fast - limited time in range of each device |
| **Dwell time** | Too long per channel = miss devices on other channels |
| **Dwell time** | Too short = miss devices with low TX rates |
| **Probe timing** | Phones send probes every 30-60 seconds when idle |
| **AP beacons** | APs beacon every ~100ms, easier to catch |

### Channel Hopping Modes

```
┌─────────────────────────────────────────────────────────────────┐
│                   CHANNEL HOPPING MODES                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  FAST HOP (Discovery - catching APs):                           │
│  • Channels: 1, 6, 11 (2.4GHz) + 36, 149 (5GHz)                │
│  • Dwell: 100-200ms per channel                                 │
│  • Cycle: All channels in ~1 second                             │
│  • Best for: Fast passes, beacon capture                        │
│                                                                  │
│  SLOW HOP (Deep scan - catching clients):                       │
│  • Channels: All channels                                       │
│  • Dwell: 500ms-1s per channel                                  │
│  • Cycle: Full sweep in 10-15 seconds                           │
│  • Best for: Hovering, client probe capture                     │
│                                                                  │
│  ADAPTIVE (Intelligent - based on flight):                      │
│  • Moving fast → Fast hop                                       │
│  • Hovering/slow → Slow hop with extended dwell                 │
│  • GPS velocity triggers mode switch                            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Configuration

```yaml
# config/config.yaml
channel_hopping:
  mode: adaptive           # fast, slow, or adaptive
  
  fast_hop:
    channels_24ghz: [1, 6, 11]
    channels_5ghz: [36, 40, 44, 48, 149, 153, 157, 161]
    dwell_ms: 150
    
  slow_hop:
    channels_24ghz: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
    channels_5ghz: [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165]
    dwell_ms: 750
    
  adaptive:
    velocity_threshold_ms: 2.0    # m/s - switch to fast hop above this speed
    hover_timeout_s: 5            # seconds stationary before slow hop
```

### Kismet Channel Configuration

```bash
# In kismet.conf - let Kismet handle channel hopping
source=wlan1:name=WiFiMon,hop=true,hop_rate=5/sec

# Or lock to specific channels for manual control
source=wlan1:name=WiFiMon,channel=6
```

### Multi-Adapter Strategy (Advanced)

For comprehensive coverage, use multiple adapters:

```
┌─────────────────────────────────────────────────────────────────┐
│                   DUAL-ADAPTER SETUP                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Adapter 1 (wlan1): 2.4 GHz band                                │
│  • Channels 1, 6, 11 hopping                                    │
│  • Catches most consumer devices                                │
│                                                                  │
│  Adapter 2 (wlan2): 5 GHz band                                  │
│  • Channels 36-165 hopping                                      │
│  • Catches modern APs and enterprise devices                    │
│                                                                  │
│  Result: Simultaneous coverage of both bands                    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Module Specifications

### Kismet Controller (`scanners/kismet_controller.py`)

**Purpose**: Interface with Kismet daemon via REST API for WiFi and Bluetooth detection

**Captures (WiFi)**:
| Field | Description |
|-------|-------------|
| `device_key` | Kismet unique device identifier |
| `mac_address` | Device MAC address |
| `device_name` | SSID or device name |
| `device_type` | AP, Client, Bridge, etc. |
| `channel` | Operating channel |
| `frequency` | Frequency in MHz |
| `signal_dbm` | Signal strength (dBm) |
| `encryption` | Security type (WPA2, WPA3, OWE, Open) |
| `manufacturer` | OUI-derived vendor |
| `first_seen` | First detection timestamp |
| `last_seen` | Last detection timestamp |
| `gps_lat` | Latitude at detection |
| `gps_lon` | Longitude at detection |
| `gps_alt` | Altitude at detection |
| `packets_total` | Total packets observed |
| `fingerprint_hash` | Computed device fingerprint |

**Captures (Bluetooth)**:
| Field | Description |
|-------|-------------|
| `device_key` | Kismet unique device identifier |
| `mac_address` | Device MAC address |
| `device_name` | Advertised device name |
| `device_type` | BR/EDR, BLE, or Dual-mode |
| `device_class` | Bluetooth device class (if available) |
| `rssi` | Signal strength (dBm) |
| `manufacturer` | OUI-derived vendor |
| `service_uuids` | Advertised service UUIDs |
| `first_seen` | First detection timestamp |
| `last_seen` | Last detection timestamp |
| `gps_lat` | Latitude at detection |
| `gps_lon` | Longitude at detection |
| `gps_alt` | Altitude at detection |
| `fingerprint_hash` | Computed device fingerprint |

### tshark Capture (`scanners/tshark_capture.py`)

**Purpose**: Deep packet capture for fingerprinting and protocol analysis

**Captures**:
| Data Type | Fields Extracted |
|-----------|------------------|
| **Probe Requests** | Source MAC, SSID list, supported rates, HT/VHT capabilities, vendor IEs |
| **Beacon Frames** | BSSID, SSID, channel, RSN info, vendor IEs, supported rates |
| **Association** | Client MAC, AP MAC, capabilities, supported rates |
| **DHCP** | Hostname, vendor class, requested options (fingerprint) |
| **mDNS/Bonjour** | Service advertisements, device names |
| **All Frames** | GPS-tagged with timestamp |

**Output**: PCAP files + parsed JSON for fingerprinting

### GPS Logger (`scanners/gps_logger.py`)

**Purpose**: Continuous GPS position logging with high-frequency updates

**Captures**:
| Field | Description |
|-------|-------------|
| `timestamp` | UTC timestamp (ISO 8601) |
| `latitude` | Decimal degrees (WGS84) |
| `longitude` | Decimal degrees (WGS84) |
| `altitude` | Meters above sea level |
| `speed` | Ground speed (m/s) |
| `track` | Heading (degrees true) |
| `fix_quality` | GPS fix type (None/2D/3D) |
| `hdop` | Horizontal dilution of precision |
| `satellites` | Number of satellites in view |

**Integration**: All other modules query GPS logger to tag every datapoint with location.

---

## Device Fingerprinting

### Overview

Device fingerprinting enables identification of **unknown devices** even when MAC addresses are randomized or device names are generic. The fingerprinting engine combines multiple signals to create a unique device signature.

### Fingerprinting Methods

#### 1. WiFi Probe Request Analysis
| Signal | Description | Uniqueness |
|--------|-------------|------------|
| **Probe SSID List** | Previously connected networks | High |
| **Supported Rates** | 802.11 data rates advertised | Medium |
| **HT/VHT Capabilities** | 802.11n/ac feature flags | High |
| **Vendor IEs** | Vendor-specific information elements | Very High |
| **Probe Interval** | Time between probe requests | Medium |
| **Sequence Numbers** | Frame sequence patterns | Medium |

#### 2. 802.11 Information Elements (IEs)
| IE Type | Fingerprint Value |
|---------|-------------------|
| RSN (48) | Supported cipher suites, AKM |
| Extended Capabilities (127) | Feature flags |
| Vendor Specific (221) | OUI + vendor data |
| HT Capabilities (45) | Channel width, SM power save, etc. |
| VHT Capabilities (191) | 802.11ac features |
| Extended Supported Rates (50) | Additional rates |

#### 3. Bluetooth Fingerprinting
| Signal | Description | Uniqueness |
|--------|-------------|------------|
| **Device Class** | Major/minor class bits | Medium |
| **Service UUIDs** | Advertised services | High |
| **Manufacturer Data** | BLE advertisement data | Very High |
| **TX Power Level** | Advertised transmit power | Low |
| **Advertisement Interval** | Time between BLE advertisements | Medium |
| **GATT Services** | Discoverable GATT characteristics | Very High |

#### 4. Network Behavior Fingerprinting
| Signal | Description |
|--------|-------------|
| **DHCP Fingerprint** | Requested options, vendor class ID |
| **mDNS/Bonjour** | Service advertisements, hostname |
| **NetBIOS** | Hostname, workgroup |
| **User-Agent** | HTTP user agent strings (if captured) |

### Fingerprint Hash Computation

```
fingerprint_hash = SHA256(
    canonical_sort([
        supported_rates,
        ht_capabilities,
        vht_capabilities,
        vendor_ies,
        probe_ssid_list,
        device_class,
        service_uuids
    ])
)
```

### Signature Database (`config/fingerprints.db`)

Known device signatures for identification:

```json
{
  "signatures": [
    {
      "fingerprint_hash": "a1b2c3d4...",
      "device_type": "iPhone",
      "os_version": "iOS 17.x",
      "confidence": 0.95,
      "identifiers": {
        "vendor_ie_oui": "00:17:F2",
        "ht_cap_info": "0x016f",
        "supported_rates": [12, 18, 24, 36, 48, 72, 96, 108]
      }
    },
    {
      "fingerprint_hash": "e5f6g7h8...",
      "device_type": "ESP32",
      "os_version": "ESP-IDF",
      "confidence": 0.90,
      "identifiers": {
        "vendor_ie_oui": "24:0A:C4",
        "probe_interval_ms": 100
      }
    }
  ]
}
```

### Fingerprint Matching Pipeline

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Capture    │────▶│   Extract    │────▶│   Compute    │────▶│    Match     │
│   Packets    │     │   Features   │     │  Hash + Sig  │     │   Database   │
└──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
                                                                       │
                     ┌──────────────────────────────────────────────────┘
                     ▼
              ┌─────────────┐
              │  Match Found │──Yes──▶ Identify device type/model
              └─────────────┘
                     │ No
                     ▼
              ┌─────────────┐
              │  Partial    │──Yes──▶ Suggest probable device type
              │   Match     │
              └─────────────┘
                     │ No
                     ▼
              ┌─────────────┐
              │   Unknown   │──────▶ Flag for investigation
              │   Device    │        Store signature for learning
              └─────────────┘
```

---

## DJI Mavic 2 Integration

### Overview

The DJI Mavic 2 serves as the aerial platform carrying the ZeroPi scanning payload. This section covers integration strategies for correlating scan data with drone telemetry and imagery.

### Hardware Setup

```
┌─────────────────────────────────────────────────────────────────┐
│                      DJI Mavic 2 Pro/Zoom                        │
│                                                                  │
│    ┌─────────────────────────────────────────────────────────┐  │
│    │            Vibration-Dampened Mount (Top/Bottom)         │  │
│    │  ┌───────────────────────────────────────────────────┐  │  │
│    │  │                  ZeroPi SBC                        │  │  │
│    │  │  • 2S LiPo (7.4V) + 5V BEC (separate power!)      │  │  │
│    │  │  • WiFi adapter (Alfa) - external antenna          │  │  │
│    │  │  • BT adapter (CSR 4.0)                           │  │  │
│    │  │  • GPS module (NEO-6M) - backup/real-time         │  │  │
│    │  │  • 64GB microSD (Class 10)                        │  │  │
│    │  │  • Status LED (GPIO) - visible from ground        │  │  │
│    │  └───────────────────────────────────────────────────┘  │  │
│    │              Total Weight: ~120-150g                     │  │
│    └─────────────────────────────────────────────────────────┘  │
│                                                                  │
│    ⚠️  CRITICAL SETTINGS:                                       │
│    • Drone Control: 5.8GHz (avoid 2.4GHz interference)         │
│    • Photos: Interval 3-5s or waypoint-triggered               │
│    • Flight logs: Enable detailed logging                      │
│    • Max payload: ~150g for safe flight characteristics        │
└─────────────────────────────────────────────────────────────────┘
```

### RF Interference Considerations

| Issue | Risk | Mitigation |
|-------|------|------------|
| **2.4GHz WiFi Scanning** | Can disrupt drone control link | Use 5.8GHz for drone; scan 2.4GHz only |
| **EMI from SBC** | May affect drone compass/GPS | Mount away from drone body, shielding |
| **USB Cable Noise** | RF interference | Use short, shielded USB cables |
| **Vibration** | SD card corruption, USB disconnect | Gel/foam vibration dampening |

### Flight Time Impact

| Configuration | Expected Flight Time |
|---------------|---------------------|
| Mavic 2 (no payload) | ~31 minutes |
| + ZeroPi + adapters (~120g) | ~22-25 minutes |
| + SDR (future, ~150g total) | ~20-22 minutes |

### GPS Data Sources

| Source | Accuracy | Real-time | Use Case |
|--------|----------|-----------|----------|
| **ZeroPi GPS (NEO-6M/7M)** | ~2.5m CEP | ✅ Yes | Real-time tagging during flight |
| **DJI Flight Logs** | ~1m CEP | ❌ Post-flight | High-accuracy correlation |
| **Combined** | Best of both | Hybrid | Production deployments |

**Recommendation**: Use both - ZeroPi GPS for real-time tagging, then upgrade coordinates post-flight using DJI logs.

### DJI Flight Log Integration

#### Supported Log Formats

| Format | Source | Parser |
|--------|--------|--------|
| `.DAT` | DJI Go 4 app (iOS/Android) | `dji_log_parser.py` |
| `.txt` | DJI Assistant 2 export | `dji_log_parser.py` |
| `.csv` | Third-party tools (Airdata, etc.) | Direct import |

#### Flight Log Tools

```bash
# Parse DJI flight logs
# Install djiparsetxt for .txt log parsing
pip install djiparsetxt

# Convert .DAT to CSV (using CsvView or similar)
# Download from: https://datfile.net/CsvView/downloads.html

# Web-based viewer for quick analysis
# https://www.phantomhelp.com/logviewer/
```

#### DJI Correlator Module (`drone/dji_correlator.py`)

**Purpose**: Correlate ZeroPi scan data with DJI flight telemetry

**Features**:
- Match scan timestamps to flight log GPS positions
- Upgrade ZeroPi GPS coordinates with DJI high-accuracy positions
- Link geo-tagged photos to device detections
- Generate merged flight + scan timeline

```python
# Usage example
from drone.dji_correlator import DJICorrelator

correlator = DJICorrelator(
    scan_session="20251225_001",
    flight_log="data/dji/DJIFlightRecord_2025-12-25.txt"
)

# Upgrade GPS coordinates in scan database
correlator.upgrade_coordinates()

# Link photos to detections
correlator.link_photos("data/dji/photos/")

# Export merged timeline
correlator.export_timeline("reports/flight_timeline.json")
```

### Post-Flight Correlation Workflow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     POST-FLIGHT DATA CORRELATION                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐ │
│  │   ZeroPi    │   │  DJI Drone  │   │  DJI Drone  │   │  Analysis   │ │
│  │  Scan Data  │   │ Flight Log  │   │   Photos    │   │ Workstation │ │
│  │ (SQLite+GPS)│   │(.DAT/.txt)  │   │  (JPEG+GPS) │   │             │ │
│  └──────┬──────┘   └──────┬──────┘   └──────┬──────┘   └──────┬──────┘ │
│         │                 │                 │                  │        │
│         │    Step 1: Extract from SD cards / DJI app          │        │
│         └─────────────────┴─────────────────┘                  │        │
│                           │                                    │        │
│                    ┌──────▼──────┐                             │        │
│                    │   Import    │◀────────────────────────────┘        │
│                    │   Script    │                                      │
│                    └──────┬──────┘                                      │
│                           │                                             │
│         ┌─────────────────┼─────────────────┐                          │
│         ▼                 ▼                 ▼                          │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐                   │
│  │  Parse DJI  │   │   Match     │   │   Link      │                   │
│  │  Flight Log │   │  Timestamps │   │   Photos    │                   │
│  └──────┬──────┘   └──────┬──────┘   └──────┬──────┘                   │
│         │                 │                 │                          │
│         └─────────────────┴─────────────────┘                          │
│                           │                                             │
│                    ┌──────▼──────┐                                      │
│                    │  Correlator │                                      │
│                    │   Engine    │                                      │
│                    └──────┬──────┘                                      │
│                           │                                             │
│         ┌─────────────────┼─────────────────┐                          │
│         ▼                 ▼                 ▼                          │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐                   │
│  │  Upgraded   │   │   Merged    │   │   Photo-    │                   │
│  │  GPS Coords │   │  Timeline   │   │   Linked    │                   │
│  │  (±1m)      │   │             │   │  Detections │                   │
│  └─────────────┘   └─────────────┘   └─────────────┘                   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Photo Integration

The Mavic 2 can capture geo-tagged photos correlated with scan data:

```yaml
# config/config.yaml
dji_integration:
  photo_capture:
    mode: interval          # interval, waypoint, or manual
    interval_seconds: 3
    
  correlation:
    time_tolerance_ms: 500  # Match photos within 500ms of detection
    gps_tolerance_m: 5      # Match photos within 5m of detection
```

### Pre-Flight Checklist Script (`scripts/preflight_check.sh`)

**Purpose**: Verify all systems operational before takeoff

```bash
#!/bin/bash
# Pre-flight system verification

echo "═══════════════════════════════════════════════════════════"
echo "         AIRDUMP PRE-FLIGHT CHECKLIST                      "
echo "═══════════════════════════════════════════════════════════"

PASS="✅"
FAIL="❌"
WARN="⚠️"
ALL_OK=true

# Check 1: Kismet service
if systemctl is-active --quiet airdump-kismet.service; then
    echo "$PASS Kismet service: RUNNING"
else
    echo "$FAIL Kismet service: NOT RUNNING"
    ALL_OK=false
fi

# Check 2: GPS fix
GPS_FIX=$(gpspipe -w -n 5 2>/dev/null | grep -m1 '"mode":' | grep -oP '"mode":\K[0-9]+')
if [ "$GPS_FIX" -ge 2 ]; then
    echo "$PASS GPS fix: ACQUIRED (Mode $GPS_FIX)"
else
    echo "$FAIL GPS fix: NO FIX"
    ALL_OK=false
fi

# Check 3: WiFi adapter in monitor mode
if iwconfig wlan1 2>/dev/null | grep -q "Mode:Monitor"; then
    echo "$PASS WiFi adapter: MONITOR MODE"
else
    echo "$FAIL WiFi adapter: NOT IN MONITOR MODE"
    ALL_OK=false
fi

# Check 4: Bluetooth adapter
if hciconfig hci0 2>/dev/null | grep -q "UP RUNNING"; then
    echo "$PASS Bluetooth adapter: UP"
else
    echo "$WARN Bluetooth adapter: DOWN (optional)"
fi

# Check 5: Storage space
FREE_SPACE=$(df -m /data | tail -1 | awk '{print $4}')
if [ "$FREE_SPACE" -gt 10000 ]; then
    echo "$PASS Storage: ${FREE_SPACE}MB free"
else
    echo "$WARN Storage: LOW (${FREE_SPACE}MB free)"
fi

# Check 6: Battery voltage (if ADC available)
if [ -f /sys/class/power_supply/battery/voltage_now ]; then
    VOLTAGE=$(cat /sys/class/power_supply/battery/voltage_now)
    VOLTAGE_V=$(echo "scale=2; $VOLTAGE / 1000000" | bc)
    if (( $(echo "$VOLTAGE_V > 7.0" | bc -l) )); then
        echo "$PASS Payload battery: ${VOLTAGE_V}V"
    else
        echo "$FAIL Payload battery: LOW (${VOLTAGE_V}V)"
        ALL_OK=false
    fi
fi

# Check 7: Time sync
if timedatectl | grep -q "synchronized: yes"; then
    echo "$PASS Time sync: SYNCHRONIZED"
else
    echo "$WARN Time sync: NOT SYNCED (using GPS time)"
fi

echo "═══════════════════════════════════════════════════════════"
if $ALL_OK; then
    echo "$PASS ALL SYSTEMS GO - READY FOR FLIGHT"
    exit 0
else
    echo "$FAIL PRE-FLIGHT CHECKS FAILED - DO NOT FLY"
    exit 1
fi
```

### Graceful Power-Off Handling (`drone/power_monitor.py`)

**Purpose**: Detect low battery and safely shutdown to prevent data loss

```python
"""
Power monitor for graceful shutdown on low battery.
Monitors voltage via ADC or I2C battery monitor.
"""

import time
import signal
import subprocess
from pathlib import Path

class PowerMonitor:
    def __init__(self, config):
        self.warning_voltage = config.get('warning_voltage', 7.0)  # 2S LiPo
        self.critical_voltage = config.get('critical_voltage', 6.6)
        self.check_interval = config.get('check_interval_s', 5)
        self.adc_path = config.get('adc_path', '/sys/bus/iio/devices/iio:device0/in_voltage0_raw')
        self.voltage_divider_ratio = config.get('voltage_divider_ratio', 3.0)
        
    def read_voltage(self):
        """Read battery voltage from ADC"""
        try:
            with open(self.adc_path, 'r') as f:
                raw = int(f.read().strip())
            # Convert ADC reading to voltage (adjust for your ADC)
            voltage = (raw / 4095.0) * 3.3 * self.voltage_divider_ratio
            return voltage
        except Exception as e:
            return None
            
    def graceful_shutdown(self):
        """Flush all data and shutdown safely"""
        print("⚠️ CRITICAL BATTERY - INITIATING GRACEFUL SHUTDOWN")
        
        # Signal all services to stop and flush
        subprocess.run(['systemctl', 'stop', 'airdump.target'], timeout=30)
        
        # Sync filesystems
        subprocess.run(['sync'])
        
        # Log shutdown event
        Path('/data/shutdown_log.txt').write_text(
            f"Emergency shutdown at {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        )
        
        # Shutdown
        subprocess.run(['shutdown', '-h', 'now'])
        
    def run(self):
        """Main monitoring loop"""
        while True:
            voltage = self.read_voltage()
            
            if voltage is None:
                time.sleep(self.check_interval)
                continue
                
            if voltage <= self.critical_voltage:
                self.graceful_shutdown()
                break
            elif voltage <= self.warning_voltage:
                print(f"⚠️ LOW BATTERY WARNING: {voltage:.2f}V")
                # Could trigger LED warning here
                
            time.sleep(self.check_interval)
```

### Database Schema Updates

```sql
-- DJI flight log data
CREATE TABLE dji_flights (
    id INTEGER PRIMARY KEY,
    session_id TEXT,
    flight_log_file TEXT,
    start_time DATETIME,
    end_time DATETIME,
    duration_seconds INTEGER,
    distance_meters REAL,
    max_altitude_m REAL,
    max_speed_ms REAL,
    home_lat REAL,
    home_lon REAL,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(session_id)
);

-- DJI high-resolution GPS track
CREATE TABLE dji_gps_track (
    id INTEGER PRIMARY KEY,
    flight_id INTEGER,
    timestamp DATETIME,
    latitude REAL,
    longitude REAL,
    altitude_msl REAL,
    altitude_agl REAL,
    velocity_x REAL,
    velocity_y REAL,
    velocity_z REAL,
    gimbal_pitch REAL,
    gimbal_yaw REAL,
    FOREIGN KEY (flight_id) REFERENCES dji_flights(id)
);

-- Linked photos
CREATE TABLE dji_photos (
    id INTEGER PRIMARY KEY,
    session_id TEXT,
    filename TEXT,
    timestamp DATETIME,
    gps_lat REAL,
    gps_lon REAL,
    gps_alt REAL,
    linked_device_id INTEGER,      -- NULL if no device nearby
    distance_to_device_m REAL,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(session_id)
);
```

---

## Known Devices Whitelist

### Purpose

The whitelist is **optional** and serves two purposes:

1. **Baseline Collection (No Whitelist)**: First scan of a property to discover all devices
2. **Audit Mode (With Whitelist)**: Compare against known devices to find anomalies

### Whitelist Format (`config/known_devices.json`)

```json
{
  "metadata": {
    "version": "1.0",
    "last_updated": "2025-12-25",
    "property_id": "FACILITY-A"
  },
  "wifi_devices": [
    {
      "bssid": "AA:BB:CC:DD:EE:FF",
      "essid": "CORP-WIFI",
      "description": "Main office access point",
      "location": "Building A, Floor 2"
    },
    {
      "bssid": "11:22:33:*",
      "essid": null,
      "description": "All Ubiquiti APs (OUI prefix match)",
      "location": "Campus-wide"
    }
  ],
  "bluetooth_devices": [
    {
      "mac_address": "AA:BB:CC:DD:EE:FF",
      "device_name": "Warehouse Scanner 01",
      "description": "Inventory barcode scanner",
      "location": "Warehouse B"
    },
    {
      "mac_address": null,
      "device_name": "COMPANY-*",
      "description": "All company-issued devices (name pattern)",
      "location": "Various"
    }
  ],
  "oui_whitelist": [
    {
      "prefix": "00:1A:2B",
      "manufacturer": "Cisco Systems",
      "description": "All Cisco network equipment"
    }
  ]
}
```

### Matching Rules

1. **Exact MAC match**: Full MAC address comparison
2. **OUI prefix match**: First 3 octets (manufacturer ID)
3. **Wildcard patterns**: Support for `*` wildcards in MAC and names
4. **Name patterns**: Regex-capable device name matching

### Usage

```bash
# Scan WITHOUT whitelist comparison (discovery mode)
python3 -m analysis.analyzer --scan-id 20251225_001 --discovery-only

# Scan WITH whitelist comparison (audit mode)
python3 -m analysis.analyzer --scan-id 20251225_001 --whitelist config/known_devices.json

# Generate whitelist from scan results (baseline creation)
python3 -m analysis.analyzer --scan-id 20251225_001 --export-whitelist new_baseline.json
```

---

## Data Storage

### SQLite Database Schema

```sql
-- Scan sessions
CREATE TABLE scan_sessions (
    id INTEGER PRIMARY KEY,
    session_id TEXT UNIQUE,
    start_time DATETIME,
    end_time DATETIME,
    property_id TEXT,
    operator TEXT,
    scan_type TEXT,  -- 'wifi', 'bluetooth', 'both'
    notes TEXT
);

-- WiFi devices
CREATE TABLE wifi_devices (
    id INTEGER PRIMARY KEY,
    session_id TEXT,
    device_key TEXT,
    bssid TEXT,
    essid TEXT,
    device_type TEXT,
    channel INTEGER,
    frequency INTEGER,
    signal_dbm INTEGER,
    encryption TEXT,
    manufacturer TEXT,
    packets_total INTEGER,
    first_seen DATETIME,
    last_seen DATETIME,
    gps_lat REAL,
    gps_lon REAL,
    gps_alt REAL,
    fingerprint_hash TEXT,
    fingerprint_data JSON,
    is_known BOOLEAN DEFAULT FALSE,
    identified_as TEXT,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(session_id)
);

-- Bluetooth devices
CREATE TABLE bt_devices (
    id INTEGER PRIMARY KEY,
    session_id TEXT,
    device_key TEXT,
    mac_address TEXT,
    device_name TEXT,
    device_class TEXT,
    device_type TEXT,
    rssi INTEGER,
    manufacturer TEXT,
    service_uuids JSON,
    first_seen DATETIME,
    last_seen DATETIME,
    gps_lat REAL,
    gps_lon REAL,
    gps_alt REAL,
    fingerprint_hash TEXT,
    fingerprint_data JSON,
    is_known BOOLEAN DEFAULT FALSE,
    identified_as TEXT,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(session_id)
);

-- GPS track log
CREATE TABLE gps_track (
    id INTEGER PRIMARY KEY,
    session_id TEXT,
    timestamp DATETIME,
    latitude REAL,
    longitude REAL,
    altitude REAL,
    speed REAL,
    track REAL,
    fix_quality TEXT,
    hdop REAL,
    satellites INTEGER,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(session_id)
);

-- Device fingerprints (signature database)
CREATE TABLE fingerprint_signatures (
    id INTEGER PRIMARY KEY,
    fingerprint_hash TEXT UNIQUE,
    device_type TEXT,
    device_model TEXT,
    os_version TEXT,
    confidence REAL,
    identifiers JSON,
    first_seen DATETIME,
    times_seen INTEGER DEFAULT 1,
    notes TEXT
);

-- Packet capture metadata
CREATE TABLE pcap_files (
    id INTEGER PRIMARY KEY,
    session_id TEXT,
    filename TEXT,
    start_time DATETIME,
    end_time DATETIME,
    file_size INTEGER,
    packet_count INTEGER,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(session_id)
);
```

### File Storage

```
data/
├── scans/
│   ├── 20251225_001/
│   │   ├── kismet.kismet        # Kismet database (SQLite format)
│   │   ├── capture.pcapng       # tshark packet capture
│   │   ├── gps_track.gpx        # GPS track (GPX format)
│   │   └── session_info.json    # Session metadata
│   └── 20251225_002/
│       └── ...
├── pcap/
│   └── raw/                     # Raw pcap archives
├── database/
│   └── airdump.db               # SQLite database
└── reports/
    ├── 20251225_001_report.html
    ├── 20251225_001_unknown.csv
    ├── 20251225_001_heatmap.html # GPS signal heatmap
    └── 20251225_001_summary.json
```

---

## Reports & Analysis

### Report Types

| Report | Format | Description |
|--------|--------|-------------|
| **Summary Report** | JSON | Statistics, device counts, session info |
| **Unknown Devices** | CSV | List of devices not in whitelist |
| **Fingerprint Report** | JSON | Device fingerprints with identification confidence |
| **Full Report** | HTML | Complete analysis with visualizations |
| **GPS Heat Map** | HTML | Interactive map with signal locations (Folium) |
| **Temporal Analysis** | JSON | Device presence patterns over time |
| **Whitelist Export** | JSON | Convert scan to whitelist format |

### Analysis Commands

```bash
# Generate all reports for a scan session
python3 -m analysis.reporter --scan-id 20251225_001 --all

# Generate only unknown devices list
python3 -m analysis.reporter --scan-id 20251225_001 --unknown-only

# Compare two scans (diff analysis)
python3 -m analysis.reporter --compare 20251225_001 20251226_001

# Export to whitelist (for baseline creation)
python3 -m analysis.reporter --scan-id 20251225_001 --export-whitelist

# Generate GPS heat map
python3 -m analysis.reporter --scan-id 20251225_001 --heatmap

# Fingerprint analysis - identify unknown devices
python3 -m analysis.analyzer --scan-id 20251225_001 --fingerprint
```

### Sample Report Output

```
╔══════════════════════════════════════════════════════════════════╗
║                    AIRDUMP SCAN REPORT                           ║
║                    Session: 20251225_001                         ║
╠══════════════════════════════════════════════════════════════════╣
║ Property: FACILITY-A          Date: 2025-12-25 14:30 UTC        ║
║ Duration: 00:45:23            Operator: admin                    ║
╠══════════════════════════════════════════════════════════════════╣
║                        WIFI SUMMARY                              ║
║ Total APs Detected:     47                                       ║
║ Known APs:              42                                       ║
║ ⚠ UNKNOWN APs:           5                                       ║
╠══════════════════════════════════════════════════════════════════╣
║                     BLUETOOTH SUMMARY                            ║
║ Total Devices Detected: 128                                      ║
║ Known Devices:          115                                      ║
║ ⚠ UNKNOWN Devices:       13                                      ║
╠══════════════════════════════════════════════════════════════════╣
║                    ⚠ UNKNOWN DEVICES                             ║
╠══════════════════════════════════════════════════════════════════╣
║ WIFI:                                                            ║
║   • AA:BB:CC:DD:EE:01  "SuspiciousNet"     Ch6  -45dBm          ║
║   • AA:BB:CC:DD:EE:02  "Hidden"            Ch11 -62dBm          ║
║   • ...                                                          ║
║ BLUETOOTH:                                                       ║
║   • 11:22:33:44:55:01  "Unknown Device"    BLE  -55dBm          ║
║   • 11:22:33:44:55:02  ""                  Classic -70dBm       ║
║   • ...                                                          ║
╚══════════════════════════════════════════════════════════════════╝
```

---

## SDR Integration Roadmap

### Overview

Software Defined Radio (SDR) integration is planned for Phase 7+ to expand detection capabilities beyond WiFi and Bluetooth to include broader RF spectrum monitoring.

### Planned SDR Hardware

| Device | Frequency Range | Use Case | Price |
|--------|-----------------|----------|-------|
| **RTL-SDR Blog v4** | 24 MHz - 1.766 GHz | General purpose, 433/868/915 MHz | ~$40 |
| **RTL-SDR v3** | 500 kHz - 1.766 GHz | HF + VHF/UHF coverage | ~$30 |
| **HackRF One** | 1 MHz - 6 GHz | Wide spectrum, TX capable | ~$300 |
| **SDRPlay RSPdx** | 1 kHz - 2 GHz | High sensitivity, wide bandwidth | ~$250 |

### Target Signal Types

| Frequency Band | Protocol/Devices | Detection Tool |
|---------------|------------------|----------------|
| **433 MHz** | Wireless sensors, remotes, TPMS, weather stations | `rtl_433` |
| **868 MHz** (EU) | LoRa, Zigbee, smart home devices | `rtl_433` |
| **915 MHz** (US) | LoRa, ISM band devices | `rtl_433` |
| **315 MHz** | Garage doors, older remotes | `rtl_433` |
| **2.4 GHz** | Zigbee, proprietary wireless | Custom / `inspectrum` |
| **Sub-GHz general** | Unknown transmitters | Spectrum analysis |

### SDR Software Stack

```bash
# Core SDR tools
rtl-sdr                  # RTL-SDR drivers & utilities
rtl_433                  # Multi-protocol decoder for ISM bands
gnuradio                 # Signal processing framework (optional)
inspectrum               # Signal analysis tool

# Python integration
pyrtlsdr                 # RTL-SDR Python bindings
```

### Planned SDR Scanner Module (`scanners/sdr_scanner.py`)

**Captures**:
| Field | Description |
|-------|-------------|
| `frequency_mhz` | Center frequency of signal |
| `protocol` | Decoded protocol (if known) |
| `device_model` | Device model (if identified by rtl_433) |
| `device_id` | Transmitter ID (if available) |
| `signal_dbm` | Signal strength |
| `modulation` | OOK, FSK, ASK, etc. |
| `raw_data` | Hex dump of raw transmission |
| `timestamp` | UTC timestamp |
| `gps_lat` | Latitude at detection |
| `gps_lon` | Longitude at detection |

### SDR Integration Architecture

```
┌────────────────────────────────────────────────────────────┐
│                    SDR Capture Pipeline                     │
│                                                            │
│  ┌──────────┐    ┌──────────┐    ┌──────────────────────┐ │
│  │ RTL-SDR  │───▶│ rtl_433  │───▶│  JSON Event Stream   │ │
│  │ Hardware │    │ Decoder  │    │  (decoded packets)   │ │
│  └──────────┘    └──────────┘    └──────────┬───────────┘ │
│                                             │              │
│                                             ▼              │
│                                    ┌──────────────────┐   │
│                                    │   GPS Tagger +   │   │
│                                    │   Database Store │   │
│                                    └──────────────────┘   │
└────────────────────────────────────────────────────────────┘
```

### rtl_433 Integration Example

```bash
# Run rtl_433 with JSON output for parsing
rtl_433 -F json -M time:utc -M level -M protocol | \
  python3 -m scanners.sdr_scanner --input-stream
```

### Security Considerations for SDR

- **Legal**: Only passive reception (not transmitting)
- **Scope**: Many ISM band devices may originate from neighboring properties
- **Filtering**: Use GPS boundaries and signal strength thresholds

---

## Architectural Recommendations

1. **Headless Operation**: Auto-start via systemd with no user interaction required during flight

2. **Graceful Shutdown**: Handle SIGTERM properly to flush data before power loss

3. **Redundant Storage**: Write to both SD card and USB drive for data safety

4. **Scan Duration**: Configurable scan windows (e.g., 30-60 seconds per location)

5. **Signal Filtering**: Use RSSI thresholds to filter distant signals from neighboring properties

6. **MAC Randomization**: Modern devices randomize MACs - fingerprinting engine compensates for this

7. **Time Sync**: Use GPS time (PPS) or NTP before flight for accurate timestamps

8. **Offline Operation**: Design for zero network connectivity during flight

9. **LED Indicators**: Use GPIO LEDs to show scan status (scanning, error, complete)

10. **Signature Learning**: Unknown devices are stored in fingerprint DB for future identification

---

## Security Considerations

### Legal Compliance

- ✅ **Authorization**: Only scan properties you own or have explicit written permission to audit
- ✅ **Passive Scanning**: This system performs passive monitoring only (no deauth, no injection)
- ✅ **Data Handling**: Implement proper data retention and destruction policies

### Operational Security

- Encrypt SQLite database with SQLCipher (optional)
- Secure boot configuration for ZeroPi
- Physical tamper protection for drone-mounted equipment
- Audit logs for all scan sessions

### Scope Limiting

- GPS geofencing to discard signals outside property boundaries
- RSSI threshold filtering for proximity control
- Session-based data isolation

---

## Implementation Phases

| Phase | Description | Components | Status |
|-------|-------------|------------|--------|
| **Phase 1** | Core Kismet integration | `kismet_controller.py`, config | 🔲 Pending |
| **Phase 2** | tshark packet capture | `tshark_capture.py` | 🔲 Pending |
| **Phase 3** | GPS integration | `gps_logger.py`, `gps_tagger.py` | 🔲 Pending |
| **Phase 4** | Data storage layer | `database.py`, `models.py` | 🔲 Pending |
| **Phase 5** | Device fingerprinting | `fingerprinting/*` | 🔲 Pending |
| **Phase 6** | Analysis & reporting | `analyzer.py`, `reporter.py`, `heatmap.py` | 🔲 Pending |
| **Phase 7** | DJI integration | `dji_correlator.py`, `dji_log_parser.py`, `photo_linker.py` | 🔲 Pending |
| **Phase 8** | Drone operations | `preflight_check.sh`, `power_monitor.py`, channel hopping | 🔲 Pending |
| **Phase 9** | systemd services | Service files, boot scripts | 🔲 Pending |
| **Phase 10** | SDR integration | `sdr_scanner.py`, rtl_433 config | 🔲 Future |
| **Phase 11** | Testing & deployment | Field tests, documentation | 🔲 Pending |

---

## Quick Start

```bash
# 1. Clone/copy project to ZeroPi
scp -r "Project Airdump" user@zeropi:/opt/

# 2. Run installation script
ssh user@zeropi
cd /opt/Project\ Airdump
sudo ./scripts/install_dependencies.sh

# 3. Configure (edit as needed)
cp config/config.yaml.example config/config.yaml
nano config/config.yaml

# 4. Setup Kismet
sudo kismet --override kismet_site=config/kismet.conf

# 5. Test manual scan
sudo ./scripts/start_scan.sh all --duration 60

# 6. Run pre-flight check
sudo ./scripts/preflight_check.sh

# 7. Enable autostart for drone deployment
sudo systemctl enable airdump.target

# 8. Reboot and verify
sudo reboot
# After reboot, check logs:
journalctl -u airdump-kismet.service -f
journalctl -u airdump-capture.service -f
```

### Post-Flight Workflow

```bash
# 1. Copy DJI flight log from phone/SD card
cp /mnt/dji/DJIFlightRecord*.txt data/dji/

# 2. Copy geo-tagged photos
cp /mnt/dji/DCIM/*.JPG data/dji/photos/

# 3. Run correlation
python3 -m drone.dji_correlator \
    --scan-id 20251225_001 \
    --flight-log data/dji/DJIFlightRecord_2025-12-25.txt \
    --photos data/dji/photos/

# 4. Generate reports with correlated data
python3 -m analysis.reporter --scan-id 20251225_001 --all
```

---

## License

Private/Internal Use - Property of [Your Organization]

---

## Changelog

- **2025-12-25**: Initial project specification
- **2025-12-25**: Updated to use Kismet + tshark stack, added fingerprinting engine, SDR roadmap
- **2025-12-25**: Added DJI Mavic 2 integration, channel hopping strategy, pre-flight checks, power monitoring
