"""
Project Airdump - Mock Data

Mock data for testing without real hardware.
"""

import json
from datetime import datetime, timezone


# =============================================================================
# MOCK KISMET RESPONSES
# =============================================================================

MOCK_KISMET_STATUS = {
    "kismet.system.version.major": "2023",
    "kismet.system.version.minor": "07",
    "kismet.system.version.tiny": "R1",
    "kismet.system.timestamp.sec": 1735120000,
    "kismet.system.timestamp.usec": 0,
    "kismet.system.devices.count": 5,
    "kismet.system.memory.rss": 256000000,
    "kismet.system.uptime": 3600,
}

MOCK_KISMET_WIFI_DEVICES = [
    {
        "kismet.device.base.key": "wifi_ap_001",
        "kismet.device.base.macaddr": "AA:BB:CC:DD:EE:FF",
        "kismet.device.base.name": "CorporateWiFi",
        "kismet.device.base.type": "Wi-Fi AP",
        "kismet.device.base.channel": "6",
        "kismet.device.base.frequency": 2437000,
        "kismet.device.base.signal": {
            "kismet.common.signal.last_signal": -45,
            "kismet.common.signal.max_signal": -40,
            "kismet.common.signal.min_signal": -60,
        },
        "kismet.device.base.first_time": 1735120000,
        "kismet.device.base.last_time": 1735121000,
        "kismet.device.base.packets.total": 5000,
        "kismet.device.base.crypt": "WPA2",
        "kismet.device.base.manuf": "Cisco",
        "dot11.device": {
            "dot11.device.last_beaconed_ssid": "CorporateWiFi",
            "dot11.device.num_clients": 10,
        },
    },
    {
        "kismet.device.base.key": "wifi_ap_002",
        "kismet.device.base.macaddr": "11:22:33:44:55:66",
        "kismet.device.base.name": "GuestWiFi",
        "kismet.device.base.type": "Wi-Fi AP",
        "kismet.device.base.channel": "11",
        "kismet.device.base.frequency": 2462000,
        "kismet.device.base.signal": {
            "kismet.common.signal.last_signal": -55,
        },
        "kismet.device.base.first_time": 1735120100,
        "kismet.device.base.last_time": 1735121000,
        "kismet.device.base.packets.total": 2000,
        "kismet.device.base.crypt": "WPA2",
        "kismet.device.base.manuf": "Ubiquiti",
    },
    {
        "kismet.device.base.key": "wifi_client_001",
        "kismet.device.base.macaddr": "DA:A1:19:00:11:22",
        "kismet.device.base.name": "",
        "kismet.device.base.type": "Wi-Fi Client",
        "kismet.device.base.channel": "6",
        "kismet.device.base.signal": {
            "kismet.common.signal.last_signal": -65,
        },
        "kismet.device.base.first_time": 1735120500,
        "kismet.device.base.last_time": 1735121000,
        "kismet.device.base.packets.total": 100,
        "kismet.device.base.manuf": "Apple",
        "dot11.device": {
            "dot11.device.probed_ssid_map": [
                {"dot11.probedssid.ssid": "HomeWiFi"},
                {"dot11.probedssid.ssid": "WorkWiFi"},
            ],
        },
    },
]

MOCK_KISMET_BT_DEVICES = [
    {
        "kismet.device.base.key": "bt_classic_001",
        "kismet.device.base.macaddr": "AA:BB:CC:DD:EE:01",
        "kismet.device.base.name": "iPhone",
        "kismet.device.base.type": "BR/EDR",
        "kismet.device.base.signal": {
            "kismet.common.signal.last_signal": -55,
        },
        "kismet.device.base.first_time": 1735120200,
        "kismet.device.base.last_time": 1735121000,
        "kismet.device.base.manuf": "Apple",
        "bluetooth.device": {
            "bluetooth.device.deviceclass": 7864332,
        },
    },
    {
        "kismet.device.base.key": "bt_ble_001",
        "kismet.device.base.macaddr": "AA:BB:CC:DD:EE:02",
        "kismet.device.base.name": "Mi Band 6",
        "kismet.device.base.type": "BTLE",
        "kismet.device.base.signal": {
            "kismet.common.signal.last_signal": -75,
        },
        "kismet.device.base.first_time": 1735120300,
        "kismet.device.base.last_time": 1735121000,
        "kismet.device.base.manuf": "Xiaomi",
    },
]

MOCK_KISMET_DATASOURCES = [
    {
        "kismet.datasource.name": "wlan0mon",
        "kismet.datasource.uuid": "source-uuid-001",
        "kismet.datasource.type": "linuxwifi",
        "kismet.datasource.interface": "wlan0mon",
        "kismet.datasource.running": True,
        "kismet.datasource.hopping": True,
        "kismet.datasource.channel": "6",
        "kismet.datasource.packets": 10000,
    },
]

MOCK_KISMET_GPS = {
    "kismet.common.location.valid": True,
    "kismet.common.location.lat": 51.5074,
    "kismet.common.location.lon": -0.1278,
    "kismet.common.location.alt": 30.0,
    "kismet.common.location.speed": 0.5,
    "kismet.common.location.fix": 3,
}


# =============================================================================
# MOCK GPS RESPONSES
# =============================================================================

MOCK_GPSD_TPV = {
    "class": "TPV",
    "device": "/dev/ttyUSB0",
    "mode": 3,
    "time": "2025-12-25T12:00:00.000Z",
    "ept": 0.005,
    "lat": 51.5074,
    "lon": -0.1278,
    "alt": 30.0,
    "epx": 5.0,
    "epy": 5.0,
    "epv": 10.0,
    "track": 90.0,
    "speed": 0.5,
    "climb": 0.0,
}

MOCK_GPSD_SKY = {
    "class": "SKY",
    "device": "/dev/ttyUSB0",
    "time": "2025-12-25T12:00:00.000Z",
    "hdop": 1.2,
    "pdop": 1.8,
    "vdop": 1.5,
    "nSat": 12,
    "uSat": 8,
    "satellites": [
        {"PRN": 1, "el": 45, "az": 90, "ss": 40, "used": True},
        {"PRN": 3, "el": 60, "az": 180, "ss": 42, "used": True},
        {"PRN": 6, "el": 30, "az": 270, "ss": 35, "used": True},
        {"PRN": 11, "el": 75, "az": 45, "ss": 45, "used": True},
        {"PRN": 14, "el": 20, "az": 120, "ss": 30, "used": True},
        {"PRN": 17, "el": 55, "az": 300, "ss": 38, "used": True},
        {"PRN": 19, "el": 40, "az": 150, "ss": 36, "used": True},
        {"PRN": 22, "el": 65, "az": 240, "ss": 41, "used": True},
    ],
}

MOCK_GPSD_NO_FIX = {
    "class": "TPV",
    "device": "/dev/ttyUSB0",
    "mode": 1,  # No fix
    "time": "2025-12-25T12:00:00.000Z",
}


# =============================================================================
# MOCK PCAP / TSHARK DATA
# =============================================================================

MOCK_PROBE_REQUEST = {
    "wlan.fc.type_subtype": "4",  # Probe Request
    "wlan.sa": "DA:A1:19:00:11:22",
    "wlan.ssid": "HomeWiFi",
    "wlan.ht.capabilities": "0x016e",
    "wlan.vht.capabilities": "0x00000000",
    "wlan.tag.number": ["221", "221"],  # Vendor IEs
    "wlan.tag.oui": ["00:17:f2", "00:50:f2"],
    "frame.time_epoch": "1735120500.000000",
}

MOCK_BEACON_FRAME = {
    "wlan.fc.type_subtype": "8",  # Beacon
    "wlan.bssid": "AA:BB:CC:DD:EE:FF",
    "wlan.ssid": "CorporateWiFi",
    "wlan.ds.current_channel": "6",
    "wlan.rsn.capabilities": "0x000c",
    "wlan.ht.capabilities": "0x106e",
    "frame.time_epoch": "1735120000.000000",
}


# =============================================================================
# MOCK FINGERPRINT DATA
# =============================================================================

MOCK_WIFI_FINGERPRINT = {
    "hash": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    "mac": "DA:A1:19:00:11:22",
    "probed_ssids": ["HomeWiFi", "WorkWiFi", "CoffeeShop"],
    "supported_rates": [1.0, 2.0, 5.5, 11.0, 6.0, 9.0, 12.0, 18.0],
    "ht_capabilities": "0x016e",
    "vht_capabilities": None,
    "vendor_ies": ["00:17:f2", "00:50:f2"],
    "is_randomized_mac": True,
    "confidence": 0.85,
}

MOCK_BT_FINGERPRINT = {
    "hash": "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3",
    "mac": "AA:BB:CC:DD:EE:01",
    "device_name": "iPhone",
    "device_class": 7864332,
    "service_uuids": ["0x1105", "0x1106", "0x111f"],
    "manufacturer_id": 76,
    "is_ble": False,
    "is_classic": True,
    "confidence": 0.92,
}


# =============================================================================
# MOCK ANALYSIS RESULTS
# =============================================================================

MOCK_ANALYSIS_RESULT = {
    "session_id": "20251225_120000",
    "analysis_time": "2025-12-25T12:30:00+00:00",
    "total_wifi_devices": 3,
    "total_bt_devices": 2,
    "unknown_devices": 2,
    "known_devices": 3,
    "suspicious_devices": 1,
    "unknown_wifi": [
        {
            "mac": "DA:A1:19:00:11:22",
            "type": "client",
            "rssi": -65,
        },
    ],
    "unknown_bt": [
        {
            "mac": "AA:BB:CC:DD:EE:02",
            "name": "Mi Band 6",
            "rssi": -75,
        },
    ],
    "suspicious": [
        {
            "mac": "DA:A1:19:00:11:22",
            "suspicious_reason": "Randomized MAC address",
        },
    ],
    "alerts": [
        {
            "type": "suspicious_wifi",
            "mac": "DA:A1:19:00:11:22",
            "reason": "Randomized MAC address",
            "timestamp": "2025-12-25T12:30:00+00:00",
        },
    ],
}


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def get_mock_kismet_response(endpoint: str) -> dict:
    """Get mock response for Kismet endpoint."""
    endpoints = {
        "/system/status.json": MOCK_KISMET_STATUS,
        "/devices/all_devices.json": MOCK_KISMET_WIFI_DEVICES + MOCK_KISMET_BT_DEVICES,
        "/phy/phy80211/devices.json": MOCK_KISMET_WIFI_DEVICES,
        "/phy/BTLE/devices.json": MOCK_KISMET_BT_DEVICES,
        "/datasource/all_sources.json": MOCK_KISMET_DATASOURCES,
        "/gps/location.json": MOCK_KISMET_GPS,
    }
    return endpoints.get(endpoint, {})


def get_mock_gps_response(with_fix: bool = True) -> dict:
    """Get mock GPS response."""
    return MOCK_GPSD_TPV if with_fix else MOCK_GPSD_NO_FIX


def create_mock_wifi_devices(count: int = 5) -> list:
    """Generate multiple mock WiFi devices."""
    devices = []
    for i in range(count):
        mac = f"AA:BB:CC:DD:EE:{i:02X}"
        devices.append({
            "kismet.device.base.key": f"wifi_{i:03d}",
            "kismet.device.base.macaddr": mac,
            "kismet.device.base.name": f"Device_{i}",
            "kismet.device.base.type": "Wi-Fi AP" if i % 3 == 0 else "Wi-Fi Client",
            "kismet.device.base.channel": str((i % 11) + 1),
            "kismet.device.base.signal": {
                "kismet.common.signal.last_signal": -40 - (i * 5),
            },
            "kismet.device.base.first_time": 1735120000 + (i * 100),
            "kismet.device.base.last_time": 1735121000,
            "kismet.device.base.packets.total": 1000 - (i * 100),
        })
    return devices


def create_mock_bt_devices(count: int = 3) -> list:
    """Generate multiple mock BT devices."""
    devices = []
    for i in range(count):
        mac = f"11:22:33:44:55:{i:02X}"
        devices.append({
            "kismet.device.base.key": f"bt_{i:03d}",
            "kismet.device.base.macaddr": mac,
            "kismet.device.base.name": f"BTDevice_{i}",
            "kismet.device.base.type": "BTLE" if i % 2 == 0 else "BR/EDR",
            "kismet.device.base.signal": {
                "kismet.common.signal.last_signal": -50 - (i * 10),
            },
            "kismet.device.base.first_time": 1735120000 + (i * 200),
            "kismet.device.base.last_time": 1735121000,
        })
    return devices
