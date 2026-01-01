"""
Project Airdump - Test Configuration

Pytest fixtures and configuration for all tests.
"""

import os
import sys
import pytest
import tempfile
import sqlite3
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.models import (
    GPSPosition, ScanSession, WiFiDevice, BTDevice,
    DeviceType, BTDeviceType, ScanStatus, GPSFixQuality
)


# =============================================================================
# FIXTURES - GPS
# =============================================================================

@pytest.fixture
def sample_gps_position():
    """Valid GPS position fixture."""
    return GPSPosition(
        latitude=51.5074,
        longitude=-0.1278,
        altitude=30.0,
        speed=0.5,
        track=90.0,
        fix_quality=GPSFixQuality.FIX_3D,
        hdop=1.2,
        satellites=8,
        timestamp=datetime.now(timezone.utc),
        gps_valid=True,
    )


@pytest.fixture
def no_fix_gps_position():
    """GPS position without fix."""
    return GPSPosition(
        latitude=None,
        longitude=None,
        altitude=None,
        fix_quality=GPSFixQuality.NONE,
        satellites=0,
        gps_valid=False,
    )


# =============================================================================
# FIXTURES - SCAN SESSION
# =============================================================================

@pytest.fixture
def sample_session():
    """Sample scan session fixture."""
    return ScanSession(
        session_id="20251225_120000",
        start_time=datetime.now(timezone.utc),
        status=ScanStatus.RUNNING,
        property_id="TEST-FACILITY",
        operator="test_user",
        scan_type="both",
        node_id="drone_alpha",
    )


@pytest.fixture
def completed_session():
    """Completed scan session fixture."""
    return ScanSession(
        session_id="20251225_100000",
        start_time=datetime(2025, 12, 25, 10, 0, 0, tzinfo=timezone.utc),
        end_time=datetime(2025, 12, 25, 10, 30, 0, tzinfo=timezone.utc),
        status=ScanStatus.STOPPED,
        property_id="TEST-FACILITY",
        wifi_device_count=42,
        bt_device_count=15,
    )


# =============================================================================
# FIXTURES - WIFI DEVICES
# =============================================================================

@pytest.fixture
def sample_wifi_ap():
    """Sample WiFi access point fixture."""
    return WiFiDevice(
        device_key="wifi_key_001",
        bssid="AA:BB:CC:DD:EE:FF",
        essid="TestNetwork",
        device_type=DeviceType.AP,
        channel=6,
        frequency=2437,
        signal_dbm=-45,
        encryption="WPA2",
        manufacturer="Cisco",
        packets_total=1000,
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
        gps_lat=51.5074,
        gps_lon=-0.1278,
        gps_alt=30.0,
        gps_valid=True,
        fingerprint_hash="abc123def456",
        session_id="20251225_120000",
    )


@pytest.fixture
def sample_wifi_client():
    """Sample WiFi client fixture."""
    return WiFiDevice(
        device_key="wifi_key_002",
        bssid="11:22:33:44:55:66",
        essid=None,  # Clients may not have ESSID
        device_type=DeviceType.CLIENT,
        channel=1,
        frequency=2412,
        signal_dbm=-65,
        encryption=None,
        manufacturer="Apple",
        packets_total=50,
        gps_lat=51.5080,
        gps_lon=-0.1280,
        gps_valid=True,
        session_id="20251225_120000",
    )


@pytest.fixture
def randomized_mac_device():
    """WiFi device with randomized MAC."""
    return WiFiDevice(
        device_key="wifi_key_003",
        bssid="DA:A1:19:00:00:01",  # Locally administered MAC
        essid=None,
        device_type=DeviceType.CLIENT,
        signal_dbm=-70,
        session_id="20251225_120000",
    )


# =============================================================================
# FIXTURES - BLUETOOTH DEVICES
# =============================================================================

@pytest.fixture
def sample_bt_classic():
    """Sample Bluetooth Classic device fixture."""
    return BTDevice(
        device_key="bt_key_001",
        mac_address="AA:BB:CC:DD:EE:01",
        device_name="iPhone",
        device_type=BTDeviceType.CLASSIC,
        device_class="0x7a020c",
        rssi=-55,
        manufacturer="Apple",
        service_uuids=["0x1105", "0x1106"],
        gps_lat=51.5074,
        gps_lon=-0.1278,
        gps_valid=True,
        session_id="20251225_120000",
    )


@pytest.fixture
def sample_bt_ble():
    """Sample Bluetooth LE device fixture."""
    return BTDevice(
        device_key="bt_key_002",
        mac_address="AA:BB:CC:DD:EE:02",
        device_name="Mi Band",
        device_type=BTDeviceType.BLE,
        rssi=-75,
        manufacturer="Xiaomi",
        service_uuids=["0x180d", "0x180f"],  # Heart Rate, Battery
        gps_lat=51.5075,
        gps_lon=-0.1279,
        gps_valid=True,
        session_id="20251225_120000",
    )


# =============================================================================
# FIXTURES - DATABASE
# =============================================================================

@pytest.fixture
def temp_db_path():
    """Temporary database file path."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        yield f.name
    # Cleanup
    try:
        os.unlink(f.name)
    except OSError:
        pass


@pytest.fixture
def temp_db(temp_db_path, tmp_path):
    """Initialized temporary database."""
    from core.database import Database
    backup_dir = tmp_path / "buffer"
    backup_dir.mkdir(exist_ok=True)
    db = Database(temp_db_path, backup_dir=str(backup_dir))
    db.initialize_schema()
    yield db
    db.close()


# =============================================================================
# FIXTURES - CONFIG
# =============================================================================

@pytest.fixture
def sample_config():
    """Sample configuration dictionary."""
    return {
        "general": {
            "node_id": "drone_alpha",
            "property_id": "TEST-FACILITY",
            "operator": "test_user",
            "data_dir": "/tmp/airdump_test",
            "log_level": "DEBUG",
        },
        "kismet": {
            "host": "localhost",
            "port": 2501,
            "username": "kismet",
            "password": "kismet",
            "poll_interval": 2.0,
        },
        "gps": {
            "host": "localhost",
            "port": 2947,
            "poll_interval": 1.0,
            "fix_timeout": 30,
            "min_satellites": 4,
        },
        "capture": {
            "enabled": True,
            "interface": "wlan0mon",
            "output_dir": "/tmp/airdump_test/pcap",
            "rotate_size_mb": 100,
        },
        "channel_hopping": {
            "mode": "adaptive",
            "fast_hop": {
                "channels_24ghz": [1, 6, 11],
                "dwell_ms": 150,
            },
            "slow_hop": {
                "channels_24ghz": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
                "dwell_ms": 750,
            },
        },
    }


@pytest.fixture
def temp_config_file(sample_config):
    """Temporary config file."""
    import yaml
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        yaml.dump(sample_config, f)
        yield f.name
    try:
        os.unlink(f.name)
    except OSError:
        pass


# =============================================================================
# FIXTURES - MOCK KISMET
# =============================================================================

@pytest.fixture
def mock_kismet_devices():
    """Mock Kismet device data."""
    return [
        {
            "kismet.device.base.macaddr": "AA:BB:CC:DD:EE:FF",
            "kismet.device.base.name": "TestAP",
            "kismet.device.base.channel": "6",
            "kismet.device.base.signal": {
                "kismet.common.signal.last_signal": -45,
            },
            "kismet.device.base.first_time": 1735120000,
            "kismet.device.base.last_time": 1735121000,
            "kismet.device.base.packets.total": 1000,
            "kismet.device.base.crypt": "WPA2",
            "kismet.device.base.manuf": "Cisco",
            "kismet.device.base.type": "Wi-Fi AP",
            "kismet.device.base.key": "wifi_key_001",
        },
        {
            "kismet.device.base.macaddr": "11:22:33:44:55:66",
            "kismet.device.base.name": "",
            "kismet.device.base.channel": "1",
            "kismet.device.base.signal": {
                "kismet.common.signal.last_signal": -65,
            },
            "kismet.device.base.first_time": 1735120500,
            "kismet.device.base.last_time": 1735121000,
            "kismet.device.base.packets.total": 50,
            "kismet.device.base.manuf": "Apple",
            "kismet.device.base.type": "Wi-Fi Client",
            "kismet.device.base.key": "wifi_key_002",
        },
    ]


@pytest.fixture
def mock_kismet_response():
    """Mock Kismet API response."""
    return {
        "kismet.system.version.major": "2023",
        "kismet.system.version.minor": "07",
        "kismet.system.timestamp.sec": 1735121000,
        "kismet.system.devices.count": 2,
    }


# =============================================================================
# FIXTURES - MOCK GPS
# =============================================================================

@pytest.fixture
def mock_gps_response():
    """Mock gpsd response."""
    return {
        "class": "TPV",
        "mode": 3,
        "lat": 51.5074,
        "lon": -0.1278,
        "alt": 30.0,
        "speed": 0.5,
        "track": 90.0,
        "time": "2025-12-25T12:00:00.000Z",
    }


# =============================================================================
# FIXTURES - WHITELIST
# =============================================================================

@pytest.fixture
def sample_whitelist():
    """Sample known devices whitelist."""
    return {
        "devices": [
            {
                "identifier": "AA:BB:CC:DD:EE:FF",
                "match_type": "mac",
                "name": "Office AP",
                "category": "infrastructure",
                "notes": "Main building access point",
            },
            {
                "identifier": "00:1A:2B",
                "match_type": "oui",
                "name": "Company Devices",
                "category": "corporate",
            },
            {
                "identifier": "CorpWiFi",
                "match_type": "ssid",
                "name": "Corporate Network",
                "category": "infrastructure",
            },
        ]
    }


@pytest.fixture
def temp_whitelist_file(sample_whitelist):
    """Temporary whitelist file."""
    import json
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(sample_whitelist, f)
        yield f.name
    try:
        os.unlink(f.name)
    except OSError:
        pass


# =============================================================================
# FIXTURES - TEMP DIRECTORIES
# =============================================================================

@pytest.fixture
def temp_data_dir():
    """Temporary data directory."""
    with tempfile.TemporaryDirectory() as d:
        yield d


@pytest.fixture
def temp_log_dir():
    """Temporary log directory."""
    with tempfile.TemporaryDirectory() as d:
        yield d


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def create_mock_wifi_device(
    mac: str = "AA:BB:CC:DD:EE:FF",
    ssid: str = "TestNetwork",
    rssi: int = -50,
) -> WiFiDevice:
    """Helper to create mock WiFi device."""
    return WiFiDevice(
        device_key=f"key_{mac}",
        bssid=mac,
        essid=ssid,
        device_type=DeviceType.AP,
        signal_dbm=rssi,
        session_id="test_session",
    )


def create_mock_bt_device(
    mac: str = "AA:BB:CC:DD:EE:FF",
    name: str = "TestDevice",
    rssi: int = -60,
) -> BTDevice:
    """Helper to create mock BT device."""
    return BTDevice(
        device_key=f"key_{mac}",
        mac_address=mac,
        device_name=name,
        device_type=BTDeviceType.BLE,
        rssi=rssi,
        session_id="test_session",
    )
