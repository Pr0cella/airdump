"""
Project Airdump - Scanner Tests

Unit tests for scanner modules: KismetController, GPSLogger, TsharkCapture.
"""

import pytest
import time
import json
import threading
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock, Mock

# Import scanner modules
from scanners.kismet_controller import KismetController, KismetDevice, ChannelHopper
from scanners.gps_logger import GPSLogger, GPSPosition


class TestKismetDevice:
    """Tests for KismetDevice dataclass."""
    
    def test_create_wifi_device(self):
        """Test creating WiFi Kismet device."""
        device = KismetDevice(
            mac="AA:BB:CC:DD:EE:FF",
            device_type="wifi",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            channel=6,
            rssi=-45,
            ssid="TestNetwork",
            encryption="WPA2",
        )
        assert device.mac == "AA:BB:CC:DD:EE:FF"
        assert device.device_type == "wifi"
        assert device.ssid == "TestNetwork"
        
    def test_create_bluetooth_device(self):
        """Test creating Bluetooth Kismet device."""
        device = KismetDevice(
            mac="11:22:33:44:55:66",
            device_type="bluetooth",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            rssi=-60,
            bt_name="iPhone",
            bt_type="classic",
        )
        assert device.device_type == "bluetooth"
        assert device.bt_name == "iPhone"
        
    def test_to_dict(self):
        """Test serialization to dict."""
        device = KismetDevice(
            mac="AA:BB:CC:DD:EE:FF",
            device_type="wifi",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            ssid="TestSSID",
            packets=100,
        )
        data = device.to_dict()
        assert data["mac"] == "AA:BB:CC:DD:EE:FF"
        assert data["ssid"] == "TestSSID"
        assert data["packets"] == 100
        assert "first_seen" in data
        
    def test_default_values(self):
        """Test default field values."""
        device = KismetDevice(
            mac="AA:BB:CC:DD:EE:FF",
            device_type="wifi",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        assert device.rssi == -100
        assert device.channel == 0
        assert device.probe_ssids == []


class TestKismetController:
    """Tests for KismetController class."""
    
    @pytest.fixture
    def controller(self):
        """Create KismetController instance."""
        return KismetController(
            host="localhost",
            port=2501,
            username="kismet",
            password="kismet",
            poll_interval=1.0,
        )
        
    def test_init(self, controller):
        """Test controller initialization."""
        assert controller.base_url == "http://localhost:2501"
        assert controller.poll_interval == 1.0
        assert controller._running is False
        assert controller._devices == {}
        
    @patch("requests.Session.get")
    def test_check_connection_success(self, mock_get, controller):
        """Test successful connection check."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "ok"}
        mock_response.content = b'{"status": "ok"}'
        mock_get.return_value = mock_response
        
        result = controller.check_connection()
        assert result is True
        
    @patch("requests.Session.get")
    def test_check_connection_failed(self, mock_get, controller):
        """Test failed connection check."""
        import requests
        mock_get.side_effect = requests.exceptions.ConnectionError()
        
        result = controller.check_connection()
        assert result is False
        
    @patch("requests.Session.get")
    def test_get_system_status(self, mock_get, controller, mock_kismet_response):
        """Test getting system status."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_kismet_response
        mock_response.content = b'{"status": "ok"}'
        mock_get.return_value = mock_response
        
        status = controller.get_system_status()
        assert status is not None
        
    @patch("requests.Session.get")
    def test_get_datasources(self, mock_get, controller):
        """Test getting data sources."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"uuid": "abc-123", "name": "wlan0mon", "running": True}
        ]
        mock_response.content = b'[{"uuid": "abc-123"}]'
        mock_get.return_value = mock_response
        
        sources = controller.get_datasources()
        assert len(sources) == 1
        assert sources[0]["uuid"] == "abc-123"
        
    @patch("requests.Session.post")
    def test_set_channel(self, mock_post, controller):
        """Test setting channel on datasource."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {}
        mock_response.content = b'{}'
        mock_post.return_value = mock_response
        
        result = controller.set_channel("source-uuid", "6")
        assert result is True
        
    @patch("requests.Session.post")
    def test_set_hop_channels(self, mock_post, controller):
        """Test setting channel hop list."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {}
        mock_response.content = b'{}'
        mock_post.return_value = mock_response
        
        result = controller.set_hop_channels(
            "source-uuid",
            ["1", "6", "11"],
            rate=5.0,
        )
        assert result is True
        mock_post.assert_called_once()
        
    def test_parse_device_wifi(self, controller):
        """Test parsing WiFi device from Kismet API response."""
        raw = {
            "kismet.device.base.macaddr": "AA:BB:CC:DD:EE:FF",
            "kismet.device.base.type": "Wi-Fi Device",
            "kismet.device.base.first_time": 1735142400,
            "kismet.device.base.last_time": 1735142500,
            "kismet.device.base.channel": 6,
            "kismet.device.base.frequency": 2437,
            "kismet.device.base.signal/kismet.common.signal.last_signal": -45,
            "kismet.device.base.manuf": "Apple",
            "kismet.device.base.packets.total": 150,
            "dot11.device": {
                "dot11.device.last_beaconed_ssid": "TestNetwork",
            },
        }
        
        device = controller._parse_device(raw)
        assert device.mac == "AA:BB:CC:DD:EE:FF"
        assert device.device_type == "wifi"
        assert device.channel == 6
        assert device.rssi == -45
        assert device.ssid == "TestNetwork"
        
    def test_parse_device_bluetooth(self, controller):
        """Test parsing Bluetooth device from Kismet API response."""
        raw = {
            "kismet.device.base.macaddr": "11:22:33:44:55:66",
            "kismet.device.base.type": "BR/EDR",
            "kismet.device.base.first_time": 1735142400,
            "kismet.device.base.last_time": 1735142500,
            "kismet.device.base.name": "iPhone",
            "kismet.device.base.signal/kismet.common.signal.last_signal": -60,
        }
        
        device = controller._parse_device(raw)
        assert device.mac == "11:22:33:44:55:66"
        assert device.device_type == "bluetooth"
        assert device.bt_type == "classic"
        assert device.bt_name == "iPhone"
        
    def test_parse_device_ble(self, controller):
        """Test parsing BLE device."""
        raw = {
            "kismet.device.base.macaddr": "77:88:99:AA:BB:CC",
            "kismet.device.base.type": "BTLE",
            "kismet.device.base.first_time": 1735142400,
            "kismet.device.base.last_time": 1735142500,
            "kismet.device.base.name": "Mi Band",
        }
        
        device = controller._parse_device(raw)
        assert device.device_type == "bluetooth"
        assert device.bt_type == "ble"
        
    def test_get_all_devices(self, controller):
        """Test getting all tracked devices."""
        # Add some devices manually
        device1 = KismetDevice(
            mac="AA:BB:CC:DD:EE:FF",
            device_type="wifi",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        device2 = KismetDevice(
            mac="11:22:33:44:55:66",
            device_type="bluetooth",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        
        controller._devices["AA:BB:CC:DD:EE:FF"] = device1
        controller._devices["11:22:33:44:55:66"] = device2
        
        devices = controller.get_all_devices()
        assert len(devices) == 2
        
    def test_get_device_by_mac(self, controller):
        """Test getting device by MAC address."""
        device = KismetDevice(
            mac="AA:BB:CC:DD:EE:FF",
            device_type="wifi",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        controller._devices["AA:BB:CC:DD:EE:FF"] = device
        
        found = controller.get_device("aa:bb:cc:dd:ee:ff")  # lowercase
        assert found is not None
        assert found.mac == "AA:BB:CC:DD:EE:FF"
        
    def test_get_device_count(self, controller):
        """Test device counting."""
        controller._devices["AA:BB:CC:DD:EE:FF"] = KismetDevice(
            mac="AA:BB:CC:DD:EE:FF",
            device_type="wifi",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        controller._devices["11:22:33:44:55:66"] = KismetDevice(
            mac="11:22:33:44:55:66",
            device_type="bluetooth",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        
        counts = controller.get_device_count()
        assert counts["wifi"] == 1
        assert counts["bluetooth"] == 1
        assert counts["total"] == 2
        
    def test_register_callback(self, controller):
        """Test callback registration."""
        callback = Mock()
        controller.register_new_device_callback(callback)
        assert callback in controller._new_device_callbacks
        
    def test_clear_devices(self, controller):
        """Test clearing device list."""
        controller._devices["AA:BB:CC:DD:EE:FF"] = Mock()
        controller._last_poll_time = time.time()
        
        controller.clear_devices()
        assert controller._devices == {}
        assert controller._last_poll_time is None


class TestChannelHopper:
    """Tests for ChannelHopper class."""
    
    @pytest.fixture
    def hopper(self):
        """Create ChannelHopper with mocked Kismet."""
        mock_kismet = Mock()
        return ChannelHopper(kismet=mock_kismet)
        
    def test_init(self, hopper):
        """Test hopper initialization."""
        assert hopper._mode == "adaptive"
        assert len(hopper.CHANNELS_24GHZ) == 11
        assert len(hopper.CHANNELS_5GHZ) == 25
        
    def test_set_mode_fast(self, hopper):
        """Test setting fast hop mode."""
        hopper.set_mode("fast")
        assert hopper._mode == "fast"
        
    def test_set_mode_slow(self, hopper):
        """Test setting slow hop mode."""
        hopper.set_mode("slow")
        assert hopper._mode == "slow"
        
    def test_set_mode_adaptive(self, hopper):
        """Test setting adaptive hop mode."""
        hopper.set_mode("adaptive")
        assert hopper._mode == "adaptive"
        
    def test_set_mode_invalid(self, hopper):
        """Test setting invalid mode."""
        result = hopper.set_mode("invalid")
        assert result is False
        assert hopper._mode == "adaptive"  # unchanged
        
    def test_set_active_source(self, hopper):
        """Test setting active data source."""
        hopper.set_active_source("uuid-123")
        assert hopper._active_source == "uuid-123"
        
    def test_lock_channel(self, hopper):
        """Test locking to specific channel."""
        hopper._active_source = "uuid-123"
        hopper.kismet.set_channel.return_value = True
        
        result = hopper.lock_channel("6")
        assert result is True
        assert hopper._mode == "lock"
        hopper.kismet.set_channel.assert_called_once_with("uuid-123", "6")
        
    def test_lock_channel_no_source(self, hopper):
        """Test channel lock fails without active source."""
        result = hopper.lock_channel("6")
        assert result is False


class TestGPSPosition:
    """Tests for GPSPosition dataclass from GPS logger."""
    
    def test_create_valid_position(self):
        """Test creating valid GPS position."""
        pos = GPSPosition(
            latitude=51.5074,
            longitude=-0.1278,
            altitude=30.0,
            timestamp=datetime.now(timezone.utc),
            speed=5.0,
            heading=90.0,
            hdop=1.5,
            fix_quality=1,
            satellites=10,
            valid=True,
        )
        assert pos.latitude == 51.5074
        assert pos.valid is True
        
    def test_to_tuple(self):
        """Test position tuple conversion."""
        ts = datetime.now(timezone.utc)
        pos = GPSPosition(
            latitude=51.5074,
            longitude=-0.1278,
            altitude=30.0,
            timestamp=ts,
            valid=True,
        )
        result = pos.to_tuple()
        assert result == (51.5074, -0.1278, 30.0, ts)
        
    def test_to_dict(self):
        """Test position dict conversion."""
        pos = GPSPosition(
            latitude=51.5074,
            longitude=-0.1278,
            altitude=30.0,
            timestamp=datetime.now(timezone.utc),
            valid=True,
        )
        data = pos.to_dict()
        assert data["latitude"] == 51.5074
        assert data["valid"] is True
        assert "timestamp" in data
        
    def test_invalid_position(self):
        """Test creating invalid position."""
        pos = GPSPosition.invalid()
        assert pos.valid is False
        assert pos.latitude == 0.0
        assert pos.longitude == 0.0


class TestGPSLogger:
    """Tests for GPSLogger class."""
    
    @pytest.fixture
    def gps_logger(self):
        """Create GPSLogger instance."""
        return GPSLogger(
            host="localhost",
            port=2947,
            poll_interval=1.0,
            min_hdop=10.0,
            min_satellites=4,
        )
        
    def test_init(self, gps_logger):
        """Test logger initialization."""
        assert gps_logger.host == "localhost"
        assert gps_logger.port == 2947
        assert gps_logger._running is False
        assert gps_logger._connected is False
        
    def test_get_current_position_no_fix(self, gps_logger):
        """Test getting position without fix."""
        lat, lon, alt, ts = gps_logger.get_current_position()
        assert lat == 0.0
        assert lon == 0.0
        assert alt == 0.0
        
    def test_get_position_no_data(self, gps_logger):
        """Test getting position object when no data."""
        pos = gps_logger.get_position()
        assert pos is None
        
    def test_has_fix_false(self, gps_logger):
        """Test has_fix when no fix."""
        assert gps_logger.has_fix() is False
        
    def test_has_fix_true(self, gps_logger):
        """Test has_fix with valid position."""
        gps_logger._current_position = GPSPosition(
            latitude=51.5074,
            longitude=-0.1278,
            altitude=30.0,
            timestamp=datetime.now(timezone.utc),
            valid=True,
        )
        assert gps_logger.has_fix() is True
        
    def test_get_stats(self, gps_logger):
        """Test getting GPS statistics."""
        stats = gps_logger.get_stats()
        assert "connected" in stats
        assert "running" in stats
        assert "has_fix" in stats
        assert stats["fix_count"] == 0
        assert stats["no_fix_count"] == 0
        
    def test_register_callback(self, gps_logger):
        """Test callback registration."""
        callback = Mock()
        gps_logger.register_callback(callback)
        assert callback in gps_logger._callbacks
        
    def test_unregister_callback(self, gps_logger):
        """Test callback unregistration."""
        callback = Mock()
        gps_logger.register_callback(callback)
        gps_logger.unregister_callback(callback)
        assert callback not in gps_logger._callbacks
        
    def test_get_history_empty(self, gps_logger):
        """Test getting empty history."""
        history = gps_logger.get_history()
        assert history == []
        
    def test_get_history_with_data(self, gps_logger):
        """Test getting position history."""
        for i in range(5):
            pos = GPSPosition(
                latitude=51.5 + i * 0.001,
                longitude=-0.1,
                altitude=30.0,
                timestamp=datetime.now(timezone.utc),
                valid=True,
            )
            gps_logger._position_history.append(pos)
            
        history = gps_logger.get_history()
        assert len(history) == 5
        
        # Test limited history
        history_limited = gps_logger.get_history(count=3)
        assert len(history_limited) == 3
        
    def test_get_velocity_no_fix(self, gps_logger):
        """Test getting velocity without fix."""
        speed, heading = gps_logger.get_velocity()
        assert speed == 0.0
        assert heading == 0.0
        
    def test_get_velocity_with_fix(self, gps_logger):
        """Test getting velocity with valid fix."""
        gps_logger._current_position = GPSPosition(
            latitude=51.5074,
            longitude=-0.1278,
            altitude=30.0,
            timestamp=datetime.now(timezone.utc),
            speed=10.5,
            heading=180.0,
            valid=True,
        )
        speed, heading = gps_logger.get_velocity()
        assert speed == 10.5
        assert heading == 180.0
        
    def test_estimate_channel_hop_mode_stationary(self, gps_logger):
        """Test hop mode estimation when stationary."""
        gps_logger._current_position = GPSPosition(
            latitude=51.5074,
            longitude=-0.1278,
            altitude=30.0,
            timestamp=datetime.now(timezone.utc),
            speed=0.5,
            valid=True,
        )
        mode = gps_logger.estimate_channel_hop_mode()
        assert mode == "slow"
        
    def test_estimate_channel_hop_mode_moving(self, gps_logger):
        """Test hop mode estimation when moving."""
        gps_logger._current_position = GPSPosition(
            latitude=51.5074,
            longitude=-0.1278,
            altitude=30.0,
            timestamp=datetime.now(timezone.utc),
            speed=10.0,
            valid=True,
        )
        mode = gps_logger.estimate_channel_hop_mode()
        assert mode == "fast"
        
    @patch("scanners.gps_logger.GPSD_AVAILABLE", False)
    def test_connect_no_gpsd(self, gps_logger):
        """Test connect fails without gpsd."""
        result = gps_logger.connect()
        assert result is False


class TestTsharkCapture:
    """Tests for TsharkCapture class."""
    
    def test_probe_request_dataclass(self):
        """Test ProbeRequest dataclass."""
        from scanners.tshark_capture import ProbeRequest
        
        probe = ProbeRequest(
            source_mac="AA:BB:CC:DD:EE:FF",
            timestamp=datetime.now(timezone.utc),
            ssid="TestNetwork",
            channel=6,
            rssi=-45,
            supported_rates=[6, 12, 24, 48],
            ht_capabilities="HT40",
        )
        assert probe.source_mac == "AA:BB:CC:DD:EE:FF"
        assert probe.supported_rates == [6, 12, 24, 48]
        
    def test_beacon_frame_dataclass(self):
        """Test BeaconFrame dataclass."""
        from scanners.tshark_capture import BeaconFrame
        
        beacon = BeaconFrame(
            bssid="AA:BB:CC:DD:EE:FF",
            timestamp=datetime.now(timezone.utc),
            ssid="MyNetwork",
            channel=11,
            rssi=-50,
            encryption="WPA2",
        )
        assert beacon.bssid == "AA:BB:CC:DD:EE:FF"
        assert beacon.encryption == "WPA2"
        assert beacon.beacon_interval == 100  # default
        
    def test_capture_session_dataclass(self):
        """Test CaptureSession dataclass."""
        from scanners.tshark_capture import CaptureSession
        
        session = CaptureSession(
            session_id="20251225_120000",
            interface="wlan0mon",
            output_file="/tmp/capture.pcap",
            start_time=datetime.now(timezone.utc),
            filter_expr="wlan type mgt",
        )
        assert session.session_id == "20251225_120000"
        assert session.packet_count == 0


class TestScannerIntegration:
    """Integration tests for scanner coordination."""
    
    def test_kismet_gps_coordination(self):
        """Test Kismet and GPS can be used together."""
        # This tests that imports and basic instances work together
        kismet = KismetController()
        gps = GPSLogger()
        
        # Create channel hopper with both
        hopper = ChannelHopper(kismet=kismet, gps_logger=gps)
        
        assert hopper.kismet is kismet
        assert hopper.gps_logger is gps
        
    def test_device_callback_with_gps(self):
        """Test device callback includes GPS data."""
        kismet = KismetController()
        gps = GPSLogger()
        
        # Set up mock GPS position
        gps._current_position = GPSPosition(
            latitude=51.5074,
            longitude=-0.1278,
            altitude=30.0,
            timestamp=datetime.now(timezone.utc),
            valid=True,
        )
        
        captured_devices = []
        
        def on_new_device(device):
            pos = gps.get_current_position()
            captured_devices.append({
                "device": device,
                "gps": pos,
            })
            
        kismet.register_new_device_callback(on_new_device)
        
        # Simulate device discovery
        test_device = KismetDevice(
            mac="AA:BB:CC:DD:EE:FF",
            device_type="wifi",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        
        # Trigger callback manually
        for cb in kismet._new_device_callbacks:
            cb(test_device)
            
        assert len(captured_devices) == 1
        assert captured_devices[0]["gps"][0] == 51.5074  # latitude


class TestThreadSafety:
    """Tests for thread safety in scanners."""
    
    def test_kismet_device_access_thread_safe(self):
        """Test concurrent device access is thread-safe."""
        kismet = KismetController()
        
        def add_devices():
            for i in range(100):
                device = KismetDevice(
                    mac=f"AA:BB:CC:DD:{i:02d}:FF",
                    device_type="wifi",
                    first_seen=datetime.now(timezone.utc),
                    last_seen=datetime.now(timezone.utc),
                )
                with kismet._lock:
                    kismet._devices[device.mac] = device
                    
        def read_devices():
            for _ in range(100):
                devices = kismet.get_all_devices()
                _ = len(devices)
                
        threads = []
        for _ in range(5):
            threads.append(threading.Thread(target=add_devices))
            threads.append(threading.Thread(target=read_devices))
            
        for t in threads:
            t.start()
        for t in threads:
            t.join()
            
        # Should complete without errors
        assert len(kismet._devices) > 0
        
    def test_gps_position_access_thread_safe(self):
        """Test concurrent GPS position access is thread-safe."""
        gps = GPSLogger()
        
        def update_position():
            for i in range(100):
                pos = GPSPosition(
                    latitude=51.5 + i * 0.0001,
                    longitude=-0.1,
                    altitude=30.0,
                    timestamp=datetime.now(timezone.utc),
                    valid=True,
                )
                with gps._lock:
                    gps._current_position = pos
                    gps._position_history.append(pos)
                    
        def read_position():
            for _ in range(100):
                _ = gps.get_current_position()
                _ = gps.has_fix()
                
        threads = []
        for _ in range(5):
            threads.append(threading.Thread(target=update_position))
            threads.append(threading.Thread(target=read_position))
            
        for t in threads:
            t.start()
        for t in threads:
            t.join()
            
        # Should complete without errors
        assert len(gps._position_history) > 0
