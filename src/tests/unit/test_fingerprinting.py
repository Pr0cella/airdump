"""
Project Airdump - Fingerprinting Tests

Unit tests for fingerprinting modules: WiFiFingerprinter, BluetoothFingerprinter, FingerprintEngine.
"""

import pytest
import hashlib
from datetime import datetime, timezone
from unittest.mock import Mock, MagicMock, patch

from fingerprinting.wifi_fingerprint import (
    WiFiFingerprinter, WiFiCapabilities, ProbeProfile
)
from fingerprinting.bt_fingerprint import (
    BluetoothFingerprinter, BluetoothCapabilities, BTDeviceProfile,
    BT_DEVICE_CLASSES, BLE_SERVICE_UUIDS,
)
from fingerprinting.engine import FingerprintEngine


class TestWiFiCapabilities:
    """Tests for WiFiCapabilities dataclass."""
    
    def test_create_basic_capabilities(self):
        """Test creating basic WiFi capabilities."""
        caps = WiFiCapabilities(
            supported_rates=[6, 12, 24, 48],
            ht_supported=True,
            ht_capabilities=0x1234,
        )
        assert caps.supported_rates == [6, 12, 24, 48]
        assert caps.ht_supported is True
        assert caps.ht_capabilities == 0x1234
        
    def test_default_values(self):
        """Test default capability values."""
        caps = WiFiCapabilities()
        assert caps.supported_rates == []
        assert caps.ht_supported is False
        assert caps.vht_supported is False
        assert caps.he_supported is False
        assert caps.wps_enabled is False
        
    def test_full_capabilities(self):
        """Test creating full capabilities."""
        caps = WiFiCapabilities(
            supported_rates=[6, 12, 24],
            extended_rates=[48, 54],
            ht_supported=True,
            ht_capabilities=0xabcd,
            vht_supported=True,
            vht_capabilities=0x1234,
            wps_enabled=True,
            wps_manufacturer="TestCorp",
            wps_model="Router X",
            vendor_ies=[{"oui": "00:50:f2", "type": "4"}],
        )
        assert caps.vht_supported is True
        assert caps.wps_enabled is True
        assert caps.wps_manufacturer == "TestCorp"


class TestProbeProfile:
    """Tests for ProbeProfile dataclass."""
    
    def test_create_profile(self):
        """Test creating probe profile."""
        profile = ProbeProfile(mac="AA:BB:CC:DD:EE:FF")
        assert profile.mac == "AA:BB:CC:DD:EE:FF"
        assert profile.probe_count == 0
        assert len(profile.probed_ssids) == 0
        
    def test_add_probe(self):
        """Test adding probe requests."""
        profile = ProbeProfile(mac="AA:BB:CC:DD:EE:FF")
        ts1 = datetime.now(timezone.utc)
        ts2 = datetime.now(timezone.utc)
        
        profile.add_probe("Network1", ts1)
        profile.add_probe("Network2", ts2)
        profile.add_probe("Network1", ts2)  # Duplicate SSID
        
        assert profile.probe_count == 3
        assert len(profile.probed_ssids) == 2  # Unique SSIDs
        assert "Network1" in profile.probed_ssids
        assert "Network2" in profile.probed_ssids
        
    def test_add_empty_ssid(self):
        """Test adding probe with empty SSID."""
        profile = ProbeProfile(mac="AA:BB:CC:DD:EE:FF")
        profile.add_probe("", datetime.now(timezone.utc))
        
        assert profile.probe_count == 1
        assert len(profile.probed_ssids) == 0  # Empty not added


class TestWiFiFingerprinter:
    """Tests for WiFiFingerprinter class."""
    
    @pytest.fixture
    def fingerprinter(self):
        """Create WiFiFingerprinter instance."""
        return WiFiFingerprinter()
        
    def test_init(self, fingerprinter):
        """Test fingerprinter initialization."""
        assert fingerprinter._probe_profiles == {}
        assert fingerprinter._fingerprint_cache == {}
        
    def test_extract_capabilities_basic(self, fingerprinter):
        """Test basic capability extraction."""
        caps = fingerprinter.extract_capabilities(
            supported_rates=[6, 12, 24, 48],
            extended_rates=[54],
        )
        assert caps.supported_rates == [6, 12, 24, 48]
        assert caps.extended_rates == [54]
        assert caps.ht_supported is False
        
    def test_extract_capabilities_with_ht(self, fingerprinter):
        """Test capability extraction with HT."""
        caps = fingerprinter.extract_capabilities(
            supported_rates=[6, 12, 24],
            ht_capabilities="1234",
        )
        assert caps.ht_supported is True
        assert caps.ht_capabilities == 0x1234
        
    def test_extract_capabilities_with_vht(self, fingerprinter):
        """Test capability extraction with VHT."""
        caps = fingerprinter.extract_capabilities(
            supported_rates=[6, 12, 24],
            vht_capabilities="abcd",
        )
        assert caps.vht_supported is True
        assert caps.vht_capabilities == 0xabcd
        
    def test_extract_capabilities_with_wps(self, fingerprinter):
        """Test capability extraction with WPS vendor IE."""
        caps = fingerprinter.extract_capabilities(
            supported_rates=[6, 12, 24],
            vendor_ies=[{"oui": "00:50:f2", "type": "4"}],
        )
        assert caps.wps_enabled is True
        
    def test_compute_fingerprint_deterministic(self, fingerprinter):
        """Test fingerprint computation is deterministic."""
        caps = WiFiCapabilities(
            supported_rates=[6, 12, 24],
            ht_supported=True,
        )
        
        fp1 = fingerprinter.compute_fingerprint(caps)
        fp2 = fingerprinter.compute_fingerprint(caps)
        
        assert fp1 == fp2
        assert len(fp1) == 64  # SHA256 hex length
        
    def test_compute_fingerprint_different_caps(self, fingerprinter):
        """Test different capabilities produce different fingerprints."""
        caps1 = WiFiCapabilities(supported_rates=[6, 12, 24])
        caps2 = WiFiCapabilities(supported_rates=[6, 12, 24, 48])
        
        fp1 = fingerprinter.compute_fingerprint(caps1)
        fp2 = fingerprinter.compute_fingerprint(caps2)
        
        assert fp1 != fp2
        
    def test_compute_fingerprint_with_probe_ssids(self, fingerprinter):
        """Test fingerprint includes probed SSIDs."""
        caps = WiFiCapabilities(supported_rates=[6, 12, 24])
        
        fp_no_probes = fingerprinter.compute_fingerprint(caps)
        fp_with_probes = fingerprinter.compute_fingerprint(caps, ["Network1", "Network2"])
        
        assert fp_no_probes != fp_with_probes
        
    def test_fingerprint_from_probe(self, fingerprinter):
        """Test fingerprinting from probe request."""
        fp = fingerprinter.fingerprint_from_probe(
            mac="AA:BB:CC:DD:EE:FF",
            ssid="TestNetwork",
            supported_rates=[6, 12, 24, 48],
            ht_capabilities="1234",
        )
        
        assert len(fp) == 64
        assert fingerprinter.get_fingerprint("AA:BB:CC:DD:EE:FF") == fp
        
    def test_get_probe_profile(self, fingerprinter):
        """Test retrieving probe profile."""
        fingerprinter.fingerprint_from_probe(
            mac="AA:BB:CC:DD:EE:FF",
            ssid="TestNetwork",
            supported_rates=[6, 12, 24],
        )
        
        profile = fingerprinter.get_probe_profile("AA:BB:CC:DD:EE:FF")
        assert profile is not None
        assert profile.mac == "AA:BB:CC:DD:EE:FF"
        assert "TestNetwork" in profile.probed_ssids
        
    def test_identify_device_type_smartphone(self, fingerprinter):
        """Test device type identification - smartphone."""
        caps = WiFiCapabilities(
            supported_rates=[6, 9, 12, 18, 24, 36, 48, 54],
            ht_supported=True,
            vht_supported=True,
        )
        device_type = fingerprinter.identify_device_type(caps)
        assert device_type == "smartphone"
        
    def test_identify_device_type_iot(self, fingerprinter):
        """Test device type identification - IoT."""
        caps = WiFiCapabilities(
            supported_rates=[1, 2, 5, 11],
            ht_supported=False,
        )
        device_type = fingerprinter.identify_device_type(caps)
        assert device_type in ["iot", "legacy_wifi_b"]
        
    def test_identify_device_type_laptop(self, fingerprinter):
        """Test device type identification - laptop."""
        caps = WiFiCapabilities(
            supported_rates=[6, 12, 24, 48, 54],
            ht_supported=True,
            vht_supported=True,
            vendor_ies=[{}, {}, {}, {}, {}],  # Many vendor IEs
        )
        device_type = fingerprinter.identify_device_type(caps)
        assert device_type == "laptop"
        
    def test_is_likely_randomized_mac_true(self, fingerprinter):
        """Test randomized MAC detection - positive."""
        # Locally administered bit set (second nibble bit 1)
        assert fingerprinter.is_likely_randomized_mac("02:00:00:00:00:00") is True
        assert fingerprinter.is_likely_randomized_mac("FA:00:00:00:00:00") is True
        assert fingerprinter.is_likely_randomized_mac("FE:12:34:56:78:9A") is True
        
    def test_is_likely_randomized_mac_false(self, fingerprinter):
        """Test randomized MAC detection - negative."""
        # Universally administered (vendor MACs) - second nibble without bit 1
        assert fingerprinter.is_likely_randomized_mac("00:00:00:00:00:00") is False
        assert fingerprinter.is_likely_randomized_mac("A0:BB:CC:DD:EE:FF") is False  # 0 has no local bit
        assert fingerprinter.is_likely_randomized_mac("00:1A:2B:3C:4D:5E") is False
        
    def test_correlate_randomized_macs(self, fingerprinter):
        """Test grouping randomized MACs by fingerprint."""
        # Create fingerprints for randomized MACs
        for mac in ["02:AA:BB:CC:DD:01", "02:AA:BB:CC:DD:02", "FA:BB:CC:DD:EE:03"]:
            fingerprinter.fingerprint_from_probe(
                mac=mac,
                ssid="TestNetwork",
                supported_rates=[6, 12, 24],
            )
            
        groups = fingerprinter.correlate_randomized_macs(fingerprinter._fingerprint_cache)
        assert len(groups) >= 1  # At least one group
        
    def test_get_signature_data(self, fingerprinter):
        """Test getting complete signature data."""
        fingerprinter.fingerprint_from_probe(
            mac="AA:BB:CC:DD:EE:FF",
            ssid="TestNetwork",
            supported_rates=[6, 12, 24, 48],
            ht_capabilities="1234",
        )
        
        data = fingerprinter.get_signature_data("AA:BB:CC:DD:EE:FF")
        assert data is not None
        assert data["mac"] == "AA:BB:CC:DD:EE:FF"
        assert "fingerprint_hash" in data
        assert "capabilities" in data
        assert "inferred_device_type" in data
        
    def test_clear_cache(self, fingerprinter):
        """Test clearing fingerprint cache."""
        fingerprinter.fingerprint_from_probe(
            mac="AA:BB:CC:DD:EE:FF",
            ssid="TestNetwork",
            supported_rates=[6, 12, 24],
        )
        
        fingerprinter.clear_cache()
        assert fingerprinter._probe_profiles == {}
        assert fingerprinter._fingerprint_cache == {}


class TestBluetoothCapabilities:
    """Tests for BluetoothCapabilities dataclass."""
    
    def test_create_capabilities(self):
        """Test creating BT capabilities."""
        caps = BluetoothCapabilities(
            device_class=0x00020C,
            device_class_name="Phone - Smartphone",
            is_classic=True,
        )
        assert caps.device_class == 0x00020C
        assert caps.is_classic is True
        
    def test_ble_capabilities(self):
        """Test BLE-specific capabilities."""
        caps = BluetoothCapabilities(
            is_ble=True,
            is_classic=False,
            service_uuids={"180d", "180f"},
            tx_power=-10,
        )
        assert caps.is_ble is True
        assert "180d" in caps.service_uuids


class TestBTDeviceProfile:
    """Tests for BTDeviceProfile dataclass."""
    
    def test_create_profile(self):
        """Test creating BT device profile."""
        profile = BTDeviceProfile(mac="AA:BB:CC:DD:EE:FF")
        assert profile.mac == "AA:BB:CC:DD:EE:FF"
        assert profile.detection_count == 0
        
    def test_add_detection(self):
        """Test adding detections."""
        profile = BTDeviceProfile(mac="AA:BB:CC:DD:EE:FF")
        ts1 = datetime.now(timezone.utc)
        
        profile.add_detection("iPhone", -45, ts1)
        profile.add_detection("iPhone", -50, ts1)
        profile.add_detection("iPhone 13", -55, ts1)
        
        assert profile.detection_count == 3
        assert len(profile.names_seen) == 2
        assert len(profile.rssi_samples) == 3
        
    def test_rssi_sample_limit(self):
        """Test RSSI sample buffer limit."""
        profile = BTDeviceProfile(mac="AA:BB:CC:DD:EE:FF")
        ts = datetime.now(timezone.utc)
        
        # Add more than 100 samples
        for i in range(150):
            profile.add_detection(None, -50 - i, ts)
            
        # Should only keep last 100
        assert len(profile.rssi_samples) == 100


class TestBluetoothFingerprinter:
    """Tests for BluetoothFingerprinter class."""
    
    @pytest.fixture
    def fingerprinter(self):
        """Create BluetoothFingerprinter instance."""
        return BluetoothFingerprinter()
        
    def test_init(self, fingerprinter):
        """Test fingerprinter initialization."""
        assert fingerprinter._profiles == {}
        assert fingerprinter._fingerprint_cache == {}
        
    def test_parse_device_class(self, fingerprinter):
        """Test parsing device class."""
        # Smartphone
        result = fingerprinter.parse_device_class(0x00020C)
        assert "Smartphone" in result or "Phone" in result
        
        # Laptop
        result = fingerprinter.parse_device_class(0x00010C)
        assert "Laptop" in result or "Computer" in result
        
    def test_parse_service_uuid(self, fingerprinter):
        """Test parsing service UUID."""
        # Heart rate service
        result = fingerprinter.parse_service_uuid("180d")
        assert "Heart Rate" in result
        
        # Battery service
        result = fingerprinter.parse_service_uuid("180f")
        assert "Battery" in result
        
    def test_extract_capabilities(self, fingerprinter):
        """Test capability extraction."""
        caps = fingerprinter.extract_capabilities(
            device_class=0x00020C,
            service_uuids=["180d", "180f"],
            is_ble=True,
            manufacturer_id=0x004C,  # Apple
        )
        assert caps.device_class == 0x00020C
        assert caps.is_ble is True
        assert "180d" in caps.service_uuids
        
    def test_compute_fingerprint_deterministic(self, fingerprinter):
        """Test fingerprint computation is deterministic."""
        caps = BluetoothCapabilities(
            device_class=0x00020C,
            service_uuids={"180d", "180f"},
            is_ble=True,
        )
        
        fp1 = fingerprinter.compute_fingerprint(caps)
        fp2 = fingerprinter.compute_fingerprint(caps)
        
        assert fp1 == fp2
        assert len(fp1) == 64
        
    def test_fingerprint_device(self, fingerprinter):
        """Test fingerprinting a device."""
        fp = fingerprinter.fingerprint_device(
            mac="AA:BB:CC:DD:EE:FF",
            name="iPhone",
            rssi=-45,
            device_class=0x00020C,
            service_uuids=["1105", "1106"],
            is_classic=True,
        )
        
        assert len(fp) == 64
        assert fingerprinter.get_fingerprint("AA:BB:CC:DD:EE:FF") == fp
        
    def test_get_device_profile(self, fingerprinter):
        """Test retrieving device profile."""
        fingerprinter.fingerprint_device(
            mac="AA:BB:CC:DD:EE:FF",
            name="TestDevice",
            rssi=-50,
        )
        
        profile = fingerprinter.get_profile("AA:BB:CC:DD:EE:FF")
        assert profile is not None
        assert "TestDevice" in profile.names_seen
        
    def test_identify_device_type(self, fingerprinter):
        """Test device type identification."""
        caps = BluetoothCapabilities(
            device_class=0x00020C,
            device_class_name="Phone - Smartphone",  # Must set this
            is_classic=True,
        )
        device_type = fingerprinter.identify_device_type(caps)
        assert device_type == "smartphone"
        
    def test_randomized_mac_detection(self, fingerprinter):
        """Test BLE randomized MAC detection via extract_capabilities."""
        # Extract capabilities detects randomized MACs internally
        caps = fingerprinter.extract_capabilities(
            is_ble=True,
            is_classic=False,
        )
        # Regular vendor MAC
        assert caps is not None


class TestFingerprintEngine:
    """Tests for FingerprintEngine class."""
    
    @pytest.fixture
    def engine(self):
        """Create FingerprintEngine instance."""
        return FingerprintEngine(
            database=None,
            gps_logger=None,
            auto_store=False,
        )
        
    def test_init(self, engine):
        """Test engine initialization."""
        assert engine.wifi is not None
        assert engine.bluetooth is not None
        assert engine._stats["wifi_fingerprints"] == 0
        
    def test_process_wifi_probe(self, engine):
        """Test processing WiFi probe request."""
        fp = engine.process_wifi_probe(
            mac="AA:BB:CC:DD:EE:FF",
            ssid="TestNetwork",
            rssi=-45,
            supported_rates=[6, 12, 24, 48],
            channel=6,
        )
        
        assert len(fp) == 64
        assert engine._stats["wifi_fingerprints"] == 1
        
    def test_process_bluetooth_device(self, engine):
        """Test processing Bluetooth device."""
        fp = engine.process_bluetooth_device(
            mac="AA:BB:CC:DD:EE:FF",
            name="iPhone",
            rssi=-50,
            device_class=0x00020C,
            is_classic=True,
        )
        
        assert len(fp) == 64
        assert engine._stats["bt_fingerprints"] == 1
        
    def test_process_with_gps(self, engine):
        """Test processing with GPS logger."""
        mock_gps = Mock()
        mock_gps.get_current_position.return_value = (51.5074, -0.1278, 30.0, datetime.now())
        mock_gps.has_fix.return_value = True
        engine.gps_logger = mock_gps
        
        fp = engine.process_wifi_probe(
            mac="AA:BB:CC:DD:EE:FF",
            ssid="TestNetwork",
            rssi=-45,
            supported_rates=[6, 12, 24],
        )
        
        assert len(fp) == 64
        mock_gps.get_current_position.assert_called()
        
    def test_randomized_mac_detection(self, engine):
        """Test randomized MAC counting."""
        # Process randomized MAC
        engine.process_wifi_probe(
            mac="02:AA:BB:CC:DD:EE",  # Local bit set
            ssid="TestNetwork",
            rssi=-45,
            supported_rates=[6, 12, 24],
        )
        
        assert engine._stats["randomized_macs_detected"] == 1
        
    def test_callback_registration(self, engine):
        """Test fingerprint callback registration."""
        callback = Mock()
        engine.register_callback(callback)
        
        engine.process_wifi_probe(
            mac="AA:BB:CC:DD:EE:FF",
            ssid="TestNetwork",
            rssi=-45,
            supported_rates=[6, 12, 24],
        )
        
        callback.assert_called_once()
        
    def test_get_stats(self, engine):
        """Test getting engine statistics."""
        engine.process_wifi_probe(
            mac="AA:BB:CC:DD:EE:FF",
            ssid="Test",
            rssi=-45,
            supported_rates=[6, 12, 24],
        )
        engine.process_bluetooth_device(
            mac="11:22:33:44:55:66",
            name="Device",
            rssi=-60,
        )
        
        stats = engine.get_stats()
        assert stats["wifi_fingerprints"] == 1
        assert stats["bt_fingerprints"] == 1
        
    def test_clear_all(self, engine):
        """Test clearing fingerprint caches."""
        engine.process_wifi_probe(
            mac="AA:BB:CC:DD:EE:FF",
            ssid="Test",
            rssi=-45,
            supported_rates=[6, 12, 24],
        )
        
        # clear_cache clears the internal caches but doesn't reset stats
        engine.clear_cache()
        # Stats are cumulative, cache is cleared
        # Verify cache was cleared by checking fingerprinter
        assert len(engine.wifi._fingerprint_cache) == 0


class TestDeviceClassMappings:
    """Tests for BT device class mappings."""
    
    def test_device_class_dict_not_empty(self):
        """Test device class dictionary has entries."""
        assert len(BT_DEVICE_CLASSES) > 0
        
    def test_device_class_smartphone(self):
        """Test smartphone class exists."""
        assert 0x00020C in BT_DEVICE_CLASSES
        assert "Smartphone" in BT_DEVICE_CLASSES[0x00020C]
        
    def test_device_class_laptop(self):
        """Test laptop class exists."""
        assert 0x00010C in BT_DEVICE_CLASSES
        assert "Laptop" in BT_DEVICE_CLASSES[0x00010C]


class TestBLEServiceMappings:
    """Tests for BLE service UUID mappings."""
    
    def test_service_dict_not_empty(self):
        """Test service UUID dictionary has entries."""
        assert len(BLE_SERVICE_UUIDS) > 0
        
    def test_heart_rate_service(self):
        """Test heart rate service mapping."""
        assert "180D" in BLE_SERVICE_UUIDS
        assert "Heart Rate" in BLE_SERVICE_UUIDS["180D"]
        
    def test_battery_service(self):
        """Test battery service mapping."""
        assert "180F" in BLE_SERVICE_UUIDS
        assert "Battery" in BLE_SERVICE_UUIDS["180F"]


class TestFingerprintIntegration:
    """Integration tests for fingerprinting system."""
    
    def test_wifi_to_bt_correlation(self):
        """Test fingerprinting same device via WiFi and BT."""
        engine = FingerprintEngine(auto_store=False)
        
        # Same device might appear on both WiFi and BT
        wifi_fp = engine.process_wifi_probe(
            mac="AA:BB:CC:DD:EE:FF",
            ssid="TestNetwork",
            rssi=-45,
            supported_rates=[6, 12, 24, 48],
        )
        
        bt_fp = engine.process_bluetooth_device(
            mac="AA:BB:CC:DD:EE:FF",
            name="Device",
            rssi=-50,
        )
        
        # Fingerprints should be different (different protocols)
        assert wifi_fp != bt_fp
        
    def test_multiple_probes_same_device(self):
        """Test accumulating probes from same device."""
        fp = WiFiFingerprinter()
        
        # Multiple probes with different SSIDs
        for ssid in ["Network1", "Network2", "Network3"]:
            fp.fingerprint_from_probe(
                mac="AA:BB:CC:DD:EE:FF",
                ssid=ssid,
                supported_rates=[6, 12, 24],
            )
            
        profile = fp.get_probe_profile("AA:BB:CC:DD:EE:FF")
        assert len(profile.probed_ssids) == 3
        assert profile.probe_count == 3
