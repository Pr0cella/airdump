"""
Project Airdump - Core Models Tests

Unit tests for all data models in core/models.py.
"""

import pytest
import json
from datetime import datetime, timezone
from dataclasses import asdict

from core.models import (
    GPSPosition, ScanSession, WiFiDevice, BTDevice,
    FingerprintSignature,
    DeviceType, BTDeviceType, ScanStatus, GPSFixQuality,
)
from analysis.analyzer import AnalysisResult


class TestGPSPosition:
    """Tests for GPSPosition data class."""
    
    def test_create_valid_gps_position(self, sample_gps_position):
        """Test creating a valid GPS position."""
        assert sample_gps_position.latitude == 51.5074
        assert sample_gps_position.longitude == -0.1278
        assert sample_gps_position.altitude == 30.0
        assert sample_gps_position.gps_valid is True
        assert sample_gps_position.fix_quality == GPSFixQuality.FIX_3D
        
    def test_create_no_fix_position(self, no_fix_gps_position):
        """Test GPS position without fix."""
        assert no_fix_gps_position.latitude is None
        assert no_fix_gps_position.longitude is None
        assert no_fix_gps_position.gps_valid is False
        assert no_fix_gps_position.fix_quality == GPSFixQuality.NONE
        
    def test_gps_position_to_dict(self, sample_gps_position):
        """Test GPS position serialization."""
        data = sample_gps_position.to_dict()
        assert data["latitude"] == 51.5074
        assert data["longitude"] == -0.1278
        assert data["fix_quality"] == 3
        assert "timestamp" in data
        
    def test_gps_position_from_dict(self):
        """Test GPS position deserialization."""
        data = {
            "latitude": 52.0,
            "longitude": -1.0,
            "altitude": 100.0,
            "fix_quality": 3,
            "satellites": 10,
            "timestamp": "2025-12-25T12:00:00",
            "gps_valid": True,
        }
        pos = GPSPosition.from_dict(data)
        assert pos.latitude == 52.0
        assert pos.longitude == -1.0
        assert pos.fix_quality == GPSFixQuality.FIX_3D
        
    def test_gps_position_default_values(self):
        """Test GPS position default values."""
        pos = GPSPosition()
        assert pos.latitude is None
        assert pos.longitude is None
        assert pos.fix_quality == GPSFixQuality.NONE
        assert pos.satellites == 0
        assert pos.gps_valid is False


class TestScanSession:
    """Tests for ScanSession data class."""
    
    def test_create_scan_session(self, sample_session):
        """Test creating a scan session."""
        assert sample_session.session_id == "20251225_120000"
        assert sample_session.status == ScanStatus.RUNNING
        assert sample_session.property_id == "TEST-FACILITY"
        assert sample_session.end_time is None
        
    def test_completed_session(self, completed_session):
        """Test completed scan session."""
        assert completed_session.status == ScanStatus.STOPPED
        assert completed_session.end_time is not None
        assert completed_session.wifi_device_count == 42
        assert completed_session.bt_device_count == 15
        
    def test_session_to_dict(self, sample_session):
        """Test session serialization."""
        data = sample_session.to_dict()
        assert data["session_id"] == "20251225_120000"
        assert data["status"] == "running"
        assert data["end_time"] is None
        
    def test_session_default_status(self):
        """Test default session status."""
        session = ScanSession(session_id="test")
        assert session.status == ScanStatus.STARTING
        assert session.wifi_device_count == 0
        assert session.bt_device_count == 0


class TestDeviceType:
    """Tests for DeviceType enum."""
    
    def test_device_types(self):
        """Test all device types exist."""
        assert DeviceType.AP.value == "ap"
        assert DeviceType.CLIENT.value == "client"
        assert DeviceType.BRIDGE.value == "bridge"
        assert DeviceType.ADHOC.value == "adhoc"
        assert DeviceType.UNKNOWN.value == "unknown"
        
    def test_device_type_from_string(self):
        """Test creating device type from string."""
        assert DeviceType("ap") == DeviceType.AP
        assert DeviceType("client") == DeviceType.CLIENT


class TestWiFiDevice:
    """Tests for WiFiDevice data class."""
    
    def test_create_wifi_ap(self, sample_wifi_ap):
        """Test creating WiFi access point."""
        assert sample_wifi_ap.bssid == "AA:BB:CC:DD:EE:FF"
        assert sample_wifi_ap.essid == "TestNetwork"
        assert sample_wifi_ap.device_type == DeviceType.AP
        assert sample_wifi_ap.signal_dbm == -45
        assert sample_wifi_ap.encryption == "WPA2"
        
    def test_create_wifi_client(self, sample_wifi_client):
        """Test creating WiFi client."""
        assert sample_wifi_client.device_type == DeviceType.CLIENT
        assert sample_wifi_client.essid is None
        
    def test_wifi_device_to_dict(self, sample_wifi_ap):
        """Test WiFi device serialization."""
        data = sample_wifi_ap.to_dict()
        assert data["bssid"] == "AA:BB:CC:DD:EE:FF"
        assert data["device_type"] == "ap"
        assert "first_seen" in data
        assert "last_seen" in data
        
    def test_wifi_device_to_json_line(self, sample_wifi_ap):
        """Test WiFi device JSON-lines format."""
        json_line = sample_wifi_ap.to_json_line("drone_alpha")
        data = json.loads(json_line)
        assert data["type"] == "wifi"
        assert data["mac"] == "AA:BB:CC:DD:EE:FF"
        assert data["ssid"] == "TestNetwork"
        assert data["node"] == "drone_alpha"
        
    def test_wifi_device_gps_fields(self, sample_wifi_ap):
        """Test WiFi device GPS fields."""
        assert sample_wifi_ap.gps_lat == 51.5074
        assert sample_wifi_ap.gps_lon == -0.1278
        assert sample_wifi_ap.gps_valid is True
        
    def test_wifi_device_default_values(self):
        """Test WiFi device default values."""
        device = WiFiDevice(device_key="key", bssid="AA:BB:CC:DD:EE:FF")
        assert device.device_type == DeviceType.UNKNOWN
        assert device.signal_dbm is None
        assert device.is_known is False
        assert device.is_duplicate is False
        assert device.seen_by_nodes == []


class TestBTDevice:
    """Tests for BTDevice data class."""
    
    def test_create_bt_classic(self, sample_bt_classic):
        """Test creating Bluetooth Classic device."""
        assert sample_bt_classic.mac_address == "AA:BB:CC:DD:EE:01"
        assert sample_bt_classic.device_name == "iPhone"
        assert sample_bt_classic.device_type == BTDeviceType.CLASSIC
        
    def test_create_bt_ble(self, sample_bt_ble):
        """Test creating Bluetooth LE device."""
        assert sample_bt_ble.device_type == BTDeviceType.BLE
        assert "0x180d" in sample_bt_ble.service_uuids
        
    def test_bt_device_to_dict(self, sample_bt_classic):
        """Test BT device serialization."""
        data = sample_bt_classic.to_dict()
        assert data["mac_address"] == "AA:BB:CC:DD:EE:01"
        assert data["device_type"] == "classic"
        assert data["service_uuids"] == ["0x1105", "0x1106"]
        
    def test_bt_device_to_json_line(self, sample_bt_ble):
        """Test BT device JSON-lines format."""
        json_line = sample_bt_ble.to_json_line("drone_beta")
        data = json.loads(json_line)
        assert data["type"] == "bt"
        assert data["name"] == "Mi Band"
        assert data["node"] == "drone_beta"
        
    def test_bt_device_default_values(self):
        """Test BT device default values."""
        device = BTDevice(device_key="key", mac_address="AA:BB:CC:DD:EE:FF")
        assert device.device_type == BTDeviceType.UNKNOWN
        assert device.service_uuids == []
        assert device.is_known is False


class TestBTDeviceType:
    """Tests for BTDeviceType enum."""
    
    def test_bt_device_types(self):
        """Test all BT device types exist."""
        assert BTDeviceType.CLASSIC.value == "classic"
        assert BTDeviceType.BLE.value == "ble"
        assert BTDeviceType.DUAL.value == "dual"
        assert BTDeviceType.UNKNOWN.value == "unknown"


class TestScanStatus:
    """Tests for ScanStatus enum."""
    
    def test_scan_statuses(self):
        """Test all scan statuses exist."""
        assert ScanStatus.RUNNING.value == "running"
        assert ScanStatus.STOPPED.value == "stopped"
        assert ScanStatus.ERROR.value == "error"
        assert ScanStatus.STARTING.value == "starting"
        assert ScanStatus.STOPPING.value == "stopping"


class TestGPSFixQuality:
    """Tests for GPSFixQuality enum."""
    
    def test_fix_qualities(self):
        """Test all fix quality values."""
        assert GPSFixQuality.NONE.value == 0
        assert GPSFixQuality.FIX_2D.value == 2
        assert GPSFixQuality.FIX_3D.value == 3


class TestFingerprintSignature:
    """Tests for FingerprintSignature data class."""
    
    def test_create_fingerprint_signature(self):
        """Test creating fingerprint signature."""
        sig = FingerprintSignature(
            fingerprint_hash="abc123",
            device_type="smartphone",
            device_model="iPhone 14",
            os_version="iOS 17",
            confidence=0.95,
            identifiers={"vendor_ie": "00:17:f2"},
        )
        assert sig.fingerprint_hash == "abc123"
        assert sig.confidence == 0.95
        
    def test_fingerprint_default_values(self):
        """Test fingerprint default values."""
        sig = FingerprintSignature(fingerprint_hash="abc", device_type="unknown")
        assert sig.confidence == 0.0
        assert sig.identifiers == {}


class TestAnalysisResult:
    """Tests for AnalysisResult data class."""
    
    def test_create_analysis_result(self):
        """Test creating analysis result."""
        result = AnalysisResult(
            session_id="20251225_120000",
            analysis_time=datetime.now(timezone.utc),
        )
        assert result.session_id == "20251225_120000"
        assert result.total_wifi_devices == 0
        assert result.unknown_devices == 0
        
    def test_analysis_result_to_dict(self):
        """Test analysis result serialization."""
        result = AnalysisResult(
            session_id="20251225_120000",
            analysis_time=datetime.now(timezone.utc),
            total_wifi_devices=10,
            total_bt_devices=5,
            unknown_devices=3,
        )
        data = result.to_dict()
        assert data["session_id"] == "20251225_120000"
        assert data["summary"]["total_wifi_devices"] == 10
        assert "analysis_time" in data


class TestDeviceSerializationRoundtrip:
    """Test serialization/deserialization roundtrip."""
    
    def test_wifi_device_roundtrip(self, sample_wifi_ap):
        """Test WiFi device can be serialized and matches original."""
        data = sample_wifi_ap.to_dict()
        # Verify key fields are preserved
        assert data["bssid"] == sample_wifi_ap.bssid
        assert data["essid"] == sample_wifi_ap.essid
        assert data["signal_dbm"] == sample_wifi_ap.signal_dbm
        
    def test_bt_device_roundtrip(self, sample_bt_classic):
        """Test BT device can be serialized and matches original."""
        data = sample_bt_classic.to_dict()
        assert data["mac_address"] == sample_bt_classic.mac_address
        assert data["device_name"] == sample_bt_classic.device_name


class TestSwarmFields:
    """Test swarm-related fields on devices."""
    
    def test_wifi_swarm_fields(self, sample_wifi_ap):
        """Test WiFi device swarm fields."""
        sample_wifi_ap.is_duplicate = True
        sample_wifi_ap.duplicate_of_id = 42
        sample_wifi_ap.seen_by_nodes = ["drone_alpha", "drone_beta"]
        
        data = sample_wifi_ap.to_dict()
        assert data["is_duplicate"] is True
        assert data["seen_by_nodes"] == ["drone_alpha", "drone_beta"]
        
    def test_bt_swarm_fields(self, sample_bt_classic):
        """Test BT device swarm fields."""
        sample_bt_classic.node_id = "drone_gamma"
        sample_bt_classic.seen_by_nodes = ["drone_gamma"]
        
        data = sample_bt_classic.to_dict()
        assert data["seen_by_nodes"] == ["drone_gamma"]
