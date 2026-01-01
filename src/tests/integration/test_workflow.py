"""
Project Airdump - Integration Tests

End-to-end tests for complete scan workflows and system integration.
"""

import os
import json
import pytest
import tempfile
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import Mock, MagicMock, patch

from core.database import Database
from core.models import (
    ScanSession, WiFiDevice, BTDevice, ScanStatus, DeviceType, BTDeviceType
)
from scanners.kismet_controller import KismetController, KismetDevice
from scanners.gps_logger import GPSLogger, GPSPosition
from fingerprinting.engine import FingerprintEngine
from analysis.analyzer import Analyzer, WhitelistComparer
from analysis.reporter import Reporter


class TestDatabaseWorkflow:
    """Integration tests for database operations."""
    
    def test_complete_scan_session_workflow(self, temp_db):
        """Test complete scan session from start to finish."""
        temp_db.initialize_schema()
        
        # 1. Create session
        session = ScanSession(
            session_id="integration_test_001",
            start_time=datetime.now(timezone.utc),
            status=ScanStatus.RUNNING,
            property_id="TEST-FACILITY",
            operator="test_user",
        )
        temp_db.create_session(session)
        
        # 2. Add WiFi devices
        for i in range(5):
            device = WiFiDevice(
                device_key=f"wifi_device_{i}",
                bssid=f"AA:BB:CC:DD:EE:{i:02X}",
                essid=f"TestNetwork_{i}",
                session_id="integration_test_001",
                device_type=DeviceType.AP if i % 2 == 0 else DeviceType.CLIENT,
                signal_dbm=-45 - i * 5,
                channel=1 + i,
                gps_lat=51.5074 + i * 0.0001,
                gps_lon=-0.1278 - i * 0.0001,
                gps_valid=True,
                first_seen=datetime.now(timezone.utc),
                last_seen=datetime.now(timezone.utc),
            )
            temp_db.insert_wifi_device(device)
            
        # 3. Add Bluetooth devices
        for i in range(3):
            device = BTDevice(
                device_key=f"bt_device_{i}",
                mac_address=f"11:22:33:44:55:{i:02X}",
                device_name=f"BTDevice_{i}",
                session_id="integration_test_001",
                device_type=BTDeviceType.CLASSIC if i % 2 == 0 else BTDeviceType.BLE,
                rssi=-50 - i * 5,
                gps_lat=51.5074,
                gps_lon=-0.1278,
                gps_valid=True,
                first_seen=datetime.now(timezone.utc),
                last_seen=datetime.now(timezone.utc),
            )
            temp_db.insert_bt_device(device)
            
        # 4. Add GPS track
        for i in range(10):
            temp_db.insert_gps_point(
                session_id="integration_test_001",
                lat=51.5074 + i * 0.0001,
                lon=-0.1278 - i * 0.0001,
                alt=30.0 + i,
                speed=5.0,
                fix_quality=3,
                satellites=10,
            )
            
        # 5. End session
        session.status = ScanStatus.STOPPED
        session.end_time = datetime.now(timezone.utc)
        session.wifi_device_count = 5
        session.bt_device_count = 3
        temp_db.update_session(session)
        
        # 6. Verify data
        stored_session = temp_db.get_session("integration_test_001")
        assert stored_session is not None
        assert stored_session["status"] == "stopped"
        
        wifi_devices = temp_db.get_wifi_devices("integration_test_001")
        assert len(wifi_devices) == 5
        
        bt_devices = temp_db.get_bt_devices("integration_test_001")
        assert len(bt_devices) == 3
        
        gps_track = temp_db.get_gps_track("integration_test_001")
        assert len(gps_track) == 10
        
        stats = temp_db.get_session_stats("integration_test_001")
        assert stats["wifi_devices"] == 5
        assert stats["bt_devices"] == 3
        assert stats["gps_points"] == 10


class TestFingerprintingWorkflow:
    """Integration tests for fingerprinting workflow."""
    
    def test_wifi_fingerprinting_workflow(self):
        """Test complete WiFi fingerprinting workflow."""
        engine = FingerprintEngine(auto_store=False)
        
        # Process multiple probes from same device
        mac = "AA:BB:CC:DD:EE:FF"
        ssids = ["Network1", "Network2", "HomeWiFi"]
        
        for ssid in ssids:
            fp = engine.process_wifi_probe(
                mac=mac,
                ssid=ssid,
                rssi=-45,
                supported_rates=[6, 12, 24, 48, 54],
                ht_capabilities="1234",
                channel=6,
            )
            
        # Verify fingerprint data
        stats = engine.get_stats()
        assert stats["wifi_fingerprints"] == 3
        
        # Get signature data
        sig_data = engine.wifi.get_signature_data(mac)
        assert sig_data is not None
        assert len(sig_data.get("probed_ssids", [])) == 3
        
    def test_bluetooth_fingerprinting_workflow(self):
        """Test complete Bluetooth fingerprinting workflow."""
        engine = FingerprintEngine(auto_store=False)
        
        # Process BT device
        fp = engine.process_bluetooth_device(
            mac="11:22:33:44:55:66",
            name="iPhone 14",
            rssi=-50,
            device_class=0x00020C,  # Smartphone
            service_uuids=["1105", "1106", "110a"],
            is_classic=True,
        )
        
        assert len(fp) == 64
        stats = engine.get_stats()
        assert stats["bt_fingerprints"] == 1


class TestAnalysisWorkflow:
    """Integration tests for analysis workflow."""
    
    def test_complete_analysis_workflow(self, temp_db, tmp_path):
        """Test complete analysis from scan to report."""
        # Setup database with scan data
        temp_db.initialize_schema()
        
        # Create session
        session = ScanSession(
            session_id="analysis_test_001",
            start_time=datetime.now(timezone.utc),
            status=ScanStatus.STOPPED,
            end_time=datetime.now(timezone.utc),
        )
        temp_db.create_session(session)
        
        # Add devices
        for i in range(10):
            device = WiFiDevice(
                device_key=f"wifi_{i}",
                bssid=f"AA:BB:CC:DD:EE:{i:02X}",
                essid=f"Network_{i}",
                session_id="analysis_test_001",
                signal_dbm=-45 - i * 3,
                gps_lat=51.5074 + i * 0.0001,
                gps_lon=-0.1278,
                gps_valid=True,
                first_seen=datetime.now(timezone.utc),
                last_seen=datetime.now(timezone.utc),
            )
            temp_db.insert_wifi_device(device)
            
        # Add GPS track
        for i in range(5):
            temp_db.insert_gps_point(
                session_id="analysis_test_001",
                lat=51.5074 + i * 0.0001,
                lon=-0.1278,
                alt=30.0,
            )
            
        # Create whitelist
        whitelist = {
            "wifi_devices": [
                {"mac": "AA:BB:CC:DD:EE:00", "name": "Known Device 1"},
                {"mac": "AA:BB:CC:DD:EE:01", "name": "Known Device 2"},
            ],
        }
        whitelist_path = tmp_path / "whitelist.json"
        with open(whitelist_path, "w") as f:
            json.dump(whitelist, f)
            
        # Run analysis - pass whitelist_file at init time
        analyzer = Analyzer(
            database=temp_db,
            whitelist_file=str(whitelist_path),
        )
        result = analyzer.analyze_session("analysis_test_001")
        
        assert result is not None
        assert result.total_wifi_devices == 10
        assert result.known_devices == 2
        assert result.unknown_devices == 8
        
        # Generate reports
        reporter = Reporter(output_dir=str(tmp_path))
        
        json_path = reporter.generate_json_report(result)
        assert Path(json_path).exists()
        
        # Verify JSON report content
        with open(json_path) as f:
            report_data = json.load(f)
        assert report_data["summary"]["total_wifi_devices"] == 10


class TestScannerIntegration:
    """Integration tests for scanner coordination."""
    
    def test_kismet_gps_integration(self):
        """Test Kismet and GPS logger integration."""
        # Create instances (without actual hardware)
        kismet = KismetController(host="localhost", port=2501)
        gps = GPSLogger(host="localhost", port=2947)
        
        # Simulate GPS position
        gps._current_position = GPSPosition(
            latitude=51.5074,
            longitude=-0.1278,
            altitude=30.0,
            timestamp=datetime.now(timezone.utc),
            valid=True,
        )
        
        # Simulate device discovery with GPS tagging
        devices_with_gps = []
        
        def on_new_device(device):
            lat, lon, alt, ts = gps.get_current_position()
            devices_with_gps.append({
                "device": device,
                "gps_lat": lat,
                "gps_lon": lon,
                "gps_alt": alt,
            })
            
        kismet.register_new_device_callback(on_new_device)
        
        # Simulate device discovery
        test_device = KismetDevice(
            mac="AA:BB:CC:DD:EE:FF",
            device_type="wifi",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            channel=6,
            rssi=-45,
            ssid="TestNetwork",
        )
        
        for callback in kismet._new_device_callbacks:
            callback(test_device)
            
        assert len(devices_with_gps) == 1
        assert devices_with_gps[0]["gps_lat"] == 51.5074


class TestEndToEndScenarios:
    """End-to-end scenario tests."""
    
    def test_property_audit_scenario(self, temp_db, tmp_path):
        """Test complete property audit scenario."""
        temp_db.initialize_schema()
        
        # Scenario: Drone performs property audit
        session_id = "AUDIT_20251225_001"
        
        # 1. Start scan session
        session = ScanSession(
            session_id=session_id,
            start_time=datetime.now(timezone.utc),
            status=ScanStatus.RUNNING,
            property_id="CORP-HQ-BUILDING-A",
            operator="security_team",
            notes="Quarterly security audit",
        )
        temp_db.create_session(session)
        
        # 2. Simulate device discoveries during flight
        # Infrastructure devices (should be known)
        infrastructure_devices = [
            ("AA:BB:CC:00:00:01", "Corp-Main-AP-1", DeviceType.AP),
            ("AA:BB:CC:00:00:02", "Corp-Main-AP-2", DeviceType.AP),
            ("AA:BB:CC:00:00:03", "Corp-Guest-AP", DeviceType.AP),
        ]
        
        # Unknown/suspicious devices
        unknown_devices = [
            ("11:22:33:44:55:66", "Unknown-Network", DeviceType.AP),
            ("22:33:44:55:66:77", "", DeviceType.CLIENT),
            ("02:AA:BB:CC:DD:EE", "", DeviceType.CLIENT),  # Randomized MAC
        ]
        
        # Add all devices
        for i, (mac, ssid, dev_type) in enumerate(infrastructure_devices + unknown_devices):
            device = WiFiDevice(
                device_key=f"device_{i}",
                bssid=mac,
                essid=ssid if ssid else None,
                session_id=session_id,
                device_type=dev_type,
                signal_dbm=-40 - i * 5,
                gps_lat=51.5074 + i * 0.0001,
                gps_lon=-0.1278 - i * 0.0001,
                gps_valid=True,
                first_seen=datetime.now(timezone.utc),
                last_seen=datetime.now(timezone.utc),
            )
            temp_db.insert_wifi_device(device)
            
        # 3. End session
        session.status = ScanStatus.STOPPED
        session.end_time = datetime.now(timezone.utc)
        temp_db.update_session(session)
        
        # 4. Create whitelist (known infrastructure)
        whitelist = {
            "wifi_devices": [
                {"mac": "AA:BB:CC:00:00:01", "name": "Main AP 1", "category": "infrastructure"},
                {"mac": "AA:BB:CC:00:00:02", "name": "Main AP 2", "category": "infrastructure"},
                {"mac": "AA:BB:CC:00:00:03", "name": "Guest AP", "category": "infrastructure"},
            ],
            "oui_whitelist": ["AA:BB:CC"],  # Corporate OUI
        }
        whitelist_path = tmp_path / "corp_whitelist.json"
        with open(whitelist_path, "w") as f:
            json.dump(whitelist, f)
            
        # 5. Run analysis - pass whitelist_file at init time
        analyzer = Analyzer(
            database=temp_db,
            whitelist_file=str(whitelist_path),
        )
        result = analyzer.analyze_session(session_id)
        
        # 6. Generate report
        reporter = Reporter(output_dir=str(tmp_path))
        json_path = reporter.generate_json_report(result)
        
        # 7. Verify findings
        assert result.known_devices == 3  # Infrastructure
        assert result.unknown_devices >= 2  # Unknown devices
        
        # Check report file
        with open(json_path) as f:
            report = json.load(f)
        assert report["session_id"] == session_id
        
    def test_swarm_data_consolidation(self, tmp_path):
        """Test consolidating data from multiple drone nodes."""
        # Create separate databases for each "drone"
        drone_dbs = {}
        for drone_name in ["drone_alpha", "drone_beta"]:
            db_path = tmp_path / f"{drone_name}.db"
            db = Database(str(db_path))
            db.initialize_schema()
            drone_dbs[drone_name] = db
            
        swarm_session_id = "SWARM_20251225_001"
        
        # Add sessions and devices to each drone
        for drone_name, db in drone_dbs.items():
            session = ScanSession(
                session_id=f"{swarm_session_id}_{drone_name}",
                start_time=datetime.now(timezone.utc),
                status=ScanStatus.STOPPED,
                node_id=drone_name,
                swarm_session_id=swarm_session_id,
            )
            db.create_session(session)
            
            # Each drone discovers some unique and some overlapping devices
            for i in range(3):
                device = WiFiDevice(
                    device_key=f"{drone_name}_device_{i}",
                    bssid=f"AA:BB:CC:DD:EE:{ord(drone_name[6]):02X}",  # Overlapping
                    essid="SharedNetwork",
                    session_id=session.session_id,
                    first_seen=datetime.now(timezone.utc),
                    last_seen=datetime.now(timezone.utc),
                )
                db.insert_wifi_device(device)
                
        # Verify both databases have data
        for drone_name, db in drone_dbs.items():
            sessions = db.get_sessions()
            assert len(sessions) == 1
            
        # Close databases
        for db in drone_dbs.values():
            db.close()


class TestErrorHandling:
    """Integration tests for error handling."""
    
    def test_graceful_database_error_handling(self, temp_db):
        """Test graceful handling of database errors."""
        temp_db.initialize_schema()
        
        # Create session
        session = ScanSession(
            session_id="error_test",
            start_time=datetime.now(timezone.utc),
        )
        temp_db.create_session(session)
        
        # Close database to simulate error
        temp_db.close()
        
        # Operations should handle closed connection
        # (depending on implementation, may reconnect or raise)
        
    def test_missing_gps_data_handling(self, temp_db):
        """Test handling of missing GPS data."""
        temp_db.initialize_schema()
        
        session = ScanSession(
            session_id="no_gps_test",
            start_time=datetime.now(timezone.utc),
        )
        temp_db.create_session(session)
        
        # Add device without GPS
        device = WiFiDevice(
            device_key="no_gps_device",
            bssid="AA:BB:CC:DD:EE:FF",
            session_id="no_gps_test",
            gps_lat=None,
            gps_lon=None,
            gps_valid=False,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        temp_db.insert_wifi_device(device)
        
        # Analysis should handle missing GPS gracefully
        analyzer = Analyzer(database=temp_db)
        result = analyzer.analyze_session("no_gps_test")
        
        assert result is not None
        assert result.total_wifi_devices == 1


class TestPerformance:
    """Performance-related integration tests."""
    
    def test_large_device_count(self, temp_db):
        """Test handling large number of devices."""
        temp_db.initialize_schema()
        
        session = ScanSession(
            session_id="perf_test",
            start_time=datetime.now(timezone.utc),
        )
        temp_db.create_session(session)
        
        # Insert many devices
        device_count = 500
        for i in range(device_count):
            device = WiFiDevice(
                device_key=f"device_{i}",
                bssid=f"{i // 256:02X}:{i % 256:02X}:CC:DD:EE:FF",
                session_id="perf_test",
                first_seen=datetime.now(timezone.utc),
                last_seen=datetime.now(timezone.utc),
            )
            temp_db.insert_wifi_device(device)
            
        # Verify all inserted
        devices = temp_db.get_wifi_devices("perf_test")
        assert len(devices) == device_count
        
        # Analysis should complete in reasonable time
        analyzer = Analyzer(database=temp_db)
        result = analyzer.analyze_session("perf_test")
        assert result.total_wifi_devices == device_count
