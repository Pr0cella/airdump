"""
Project Airdump - Database Tests

Unit tests for the Database class in core/database.py.
"""

import os
import json
import pytest
import tempfile
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch, MagicMock

from core.database import Database, SCHEMA
from core.models import (
    ScanSession, WiFiDevice, BTDevice, FingerprintSignature,
    PcapFile, DJIFlight, DJIPhoto, SwarmSession,
    DeviceType, BTDeviceType, ScanStatus,
)


class TestDatabaseConnection:
    """Tests for database connection management."""
    
    def test_connect_creates_file(self, temp_db):
        """Test connection creates database file."""
        temp_db.connect()
        assert temp_db.db_path.exists()
        
    def test_connect_reuses_connection(self, temp_db):
        """Test subsequent connects return same connection."""
        conn1 = temp_db.connect()
        conn2 = temp_db.connect()
        assert conn1 is conn2
        
    def test_close_connection(self, temp_db):
        """Test closing database connection."""
        temp_db.connect()
        temp_db.close()
        assert temp_db._connection is None
        
    def test_row_factory_dict_access(self, temp_db):
        """Test row factory provides dict-like access."""
        temp_db.initialize_schema()
        conn = temp_db.connect()
        conn.execute("INSERT INTO scan_sessions (session_id, start_time, status) VALUES (?, ?, ?)",
                     ("test_session", "2025-01-01T00:00:00", "running"))
        conn.commit()
        row = conn.execute("SELECT * FROM scan_sessions WHERE session_id = ?", ("test_session",)).fetchone()
        assert row["session_id"] == "test_session"
        
    def test_initialize_schema(self, temp_db):
        """Test schema initialization."""
        temp_db.initialize_schema()
        conn = temp_db.connect()
        # Verify tables exist
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        table_names = [t["name"] for t in tables]
        assert "scan_sessions" in table_names
        assert "wifi_devices" in table_names
        assert "bt_devices" in table_names
        assert "gps_track" in table_names


class TestTransactionContext:
    """Tests for transaction context manager."""
    
    def test_transaction_commit(self, temp_db):
        """Test successful transaction commits."""
        temp_db.initialize_schema()
        with temp_db.transaction() as conn:
            conn.execute(
                "INSERT INTO scan_sessions (session_id, start_time, status) VALUES (?, ?, ?)",
                ("tx_test", "2025-01-01T00:00:00", "running")
            )
        # Verify committed
        row = temp_db.connect().execute(
            "SELECT * FROM scan_sessions WHERE session_id = ?", ("tx_test",)
        ).fetchone()
        assert row is not None
        
    def test_transaction_rollback_on_error(self, temp_db):
        """Test failed transaction rolls back."""
        temp_db.initialize_schema()
        try:
            with temp_db.transaction() as conn:
                conn.execute(
                    "INSERT INTO scan_sessions (session_id, start_time, status) VALUES (?, ?, ?)",
                    ("rollback_test", "2025-01-01T00:00:00", "running")
                )
                raise ValueError("Intentional error")
        except ValueError:
            pass
        # Verify rolled back
        row = temp_db.connect().execute(
            "SELECT * FROM scan_sessions WHERE session_id = ?", ("rollback_test",)
        ).fetchone()
        assert row is None


class TestScanSessions:
    """Tests for scan session operations."""
    
    def test_create_session(self, temp_db, sample_session):
        """Test creating a scan session."""
        temp_db.initialize_schema()
        row_id = temp_db.create_session(sample_session)
        assert row_id > 0
        
    def test_get_session(self, temp_db, sample_session):
        """Test retrieving a session by ID."""
        temp_db.initialize_schema()
        temp_db.create_session(sample_session)
        session = temp_db.get_session(sample_session.session_id)
        assert session is not None
        assert session["session_id"] == sample_session.session_id
        assert session["property_id"] == sample_session.property_id
        
    def test_get_latest_session(self, temp_db):
        """Test retrieving the most recent session."""
        temp_db.initialize_schema()
        # Create sessions with different times
        import time
        for i in range(3):
            session = ScanSession(
                session_id=f"session_{i}",
                start_time=datetime.now(timezone.utc),
                status=ScanStatus.RUNNING,
            )
            temp_db.create_session(session)
            time.sleep(0.01)  # Ensure different timestamps
        
        latest = temp_db.get_latest_session()
        assert latest is not None
        assert latest["session_id"] == "session_2"  # Last created
        
    def test_get_latest_session_empty_db(self, temp_db):
        """Test get_latest_session returns None on empty database."""
        temp_db.initialize_schema()
        latest = temp_db.get_latest_session()
        assert latest is None
        
    def test_get_nonexistent_session(self, temp_db):
        """Test retrieving non-existent session returns None."""
        temp_db.initialize_schema()
        session = temp_db.get_session("nonexistent")
        assert session is None
        
    def test_get_sessions_list(self, temp_db):
        """Test getting list of sessions."""
        temp_db.initialize_schema()
        # Create multiple sessions
        for i in range(5):
            session = ScanSession(
                session_id=f"session_{i}",
                start_time=datetime.now(timezone.utc),
                status=ScanStatus.RUNNING,
            )
            temp_db.create_session(session)
        sessions = temp_db.get_sessions(limit=10)
        assert len(sessions) == 5
        
    def test_end_session(self, temp_db, sample_session):
        """Test ending a session."""
        temp_db.initialize_schema()
        temp_db.create_session(sample_session)
        end_time = datetime.now(timezone.utc)
        temp_db.end_session(sample_session.session_id, end_time)
        session = temp_db.get_session(sample_session.session_id)
        assert session["end_time"] is not None
        
    def test_update_session(self, temp_db, sample_session):
        """Test updating session values."""
        temp_db.initialize_schema()
        temp_db.create_session(sample_session)
        
        sample_session.status = ScanStatus.STOPPED
        sample_session.wifi_device_count = 10
        sample_session.bt_device_count = 5
        sample_session.end_time = datetime.now(timezone.utc)
        temp_db.update_session(sample_session)
        
        session = temp_db.get_session(sample_session.session_id)
        assert session["status"] == "stopped"
        assert session["wifi_device_count"] == 10


class TestWiFiDevices:
    """Tests for WiFi device operations."""
    
    def test_insert_wifi_device(self, temp_db, sample_session, sample_wifi_ap):
        """Test inserting a WiFi device."""
        temp_db.initialize_schema()
        temp_db.create_session(sample_session)
        sample_wifi_ap.session_id = sample_session.session_id
        result = temp_db.insert_wifi_device(sample_wifi_ap)
        assert result is True
        
    def test_get_wifi_devices(self, temp_db, sample_session, sample_wifi_ap):
        """Test getting WiFi devices for session."""
        temp_db.initialize_schema()
        temp_db.create_session(sample_session)
        sample_wifi_ap.session_id = sample_session.session_id
        temp_db.insert_wifi_device(sample_wifi_ap)
        
        devices = temp_db.get_wifi_devices(sample_session.session_id)
        assert len(devices) == 1
        assert devices[0]["bssid"] == sample_wifi_ap.bssid
        
    def test_wifi_device_update_on_duplicate(self, temp_db, sample_session, sample_wifi_ap):
        """Test that duplicate device updates instead of inserting."""
        temp_db.initialize_schema()
        temp_db.create_session(sample_session)
        sample_wifi_ap.session_id = sample_session.session_id
        
        # Insert first time
        temp_db.insert_wifi_device(sample_wifi_ap)
        
        # Update signal and insert again
        sample_wifi_ap.signal_dbm = -30
        sample_wifi_ap.packets_total = 100
        temp_db.insert_wifi_device(sample_wifi_ap)
        
        devices = temp_db.get_wifi_devices(sample_session.session_id)
        assert len(devices) == 1  # Should still be 1
        assert devices[0]["signal_dbm"] == -30
        assert devices[0]["packets_total"] == 100
        
    def test_get_wifi_device_by_bssid(self, temp_db, sample_session, sample_wifi_ap):
        """Test getting WiFi device by BSSID."""
        temp_db.initialize_schema()
        temp_db.create_session(sample_session)
        sample_wifi_ap.session_id = sample_session.session_id
        temp_db.insert_wifi_device(sample_wifi_ap)
        
        device = temp_db.get_wifi_device_by_bssid(
            sample_session.session_id,
            sample_wifi_ap.bssid
        )
        assert device is not None
        assert device["essid"] == sample_wifi_ap.essid
        
    def test_get_wifi_unknown_only(self, temp_db, sample_session, sample_wifi_ap):
        """Test filtering for unknown devices only."""
        temp_db.initialize_schema()
        temp_db.create_session(sample_session)
        
        # Insert known device
        sample_wifi_ap.session_id = sample_session.session_id
        sample_wifi_ap.is_known = True
        temp_db.insert_wifi_device(sample_wifi_ap)
        
        # Insert unknown device
        unknown = WiFiDevice(
            device_key="unknown_key",
            bssid="11:22:33:44:55:66",
            session_id=sample_session.session_id,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            is_known=False,
        )
        temp_db.insert_wifi_device(unknown)
        
        all_devices = temp_db.get_wifi_devices(sample_session.session_id)
        unknown_devices = temp_db.get_wifi_devices(sample_session.session_id, unknown_only=True)
        
        assert len(all_devices) == 2
        assert len(unknown_devices) == 1
        
    def test_update_wifi_known_status(self, temp_db, sample_session, sample_wifi_ap):
        """Test updating device known status."""
        temp_db.initialize_schema()
        temp_db.create_session(sample_session)
        sample_wifi_ap.session_id = sample_session.session_id
        temp_db.insert_wifi_device(sample_wifi_ap)
        
        devices = temp_db.get_wifi_devices(sample_session.session_id)
        device_id = devices[0]["id"]
        
        temp_db.update_wifi_known_status(device_id, True, "Office Router")
        
        updated = temp_db.get_wifi_device_by_bssid(
            sample_session.session_id,
            sample_wifi_ap.bssid
        )
        assert updated["is_known"] == 1
        assert updated["identified_as"] == "Office Router"


class TestBluetoothDevices:
    """Tests for Bluetooth device operations."""
    
    def test_insert_bt_device(self, temp_db, sample_session, sample_bt_classic):
        """Test inserting a Bluetooth device."""
        temp_db.initialize_schema()
        temp_db.create_session(sample_session)
        sample_bt_classic.session_id = sample_session.session_id
        result = temp_db.insert_bt_device(sample_bt_classic)
        assert result is True
        
    def test_get_bt_devices(self, temp_db, sample_session, sample_bt_classic, sample_bt_ble):
        """Test getting Bluetooth devices for session."""
        temp_db.initialize_schema()
        temp_db.create_session(sample_session)
        
        sample_bt_classic.session_id = sample_session.session_id
        sample_bt_ble.session_id = sample_session.session_id
        temp_db.insert_bt_device(sample_bt_classic)
        temp_db.insert_bt_device(sample_bt_ble)
        
        devices = temp_db.get_bt_devices(sample_session.session_id)
        assert len(devices) == 2
        
    def test_bt_device_update_on_duplicate(self, temp_db, sample_session, sample_bt_classic):
        """Test BT device update on duplicate."""
        temp_db.initialize_schema()
        temp_db.create_session(sample_session)
        sample_bt_classic.session_id = sample_session.session_id
        
        temp_db.insert_bt_device(sample_bt_classic)
        
        sample_bt_classic.rssi = -40
        sample_bt_classic.device_name = "Updated iPhone"
        temp_db.insert_bt_device(sample_bt_classic)
        
        devices = temp_db.get_bt_devices(sample_session.session_id)
        assert len(devices) == 1
        assert devices[0]["rssi"] == -40


class TestGPSTrack:
    """Tests for GPS track operations."""
    
    def test_insert_gps_point(self, temp_db, sample_session):
        """Test inserting GPS point."""
        temp_db.initialize_schema()
        temp_db.create_session(sample_session)
        
        temp_db.insert_gps_point(
            session_id=sample_session.session_id,
            lat=51.5074,
            lon=-0.1278,
            alt=30.0,
            speed=5.0,
            fix_quality=3,
            satellites=10,
        )
        
        track = temp_db.get_gps_track(sample_session.session_id)
        assert len(track) == 1
        assert track[0]["latitude"] == 51.5074
        
    def test_get_gps_track_ordered(self, temp_db, sample_session):
        """Test GPS track is ordered by timestamp."""
        temp_db.initialize_schema()
        temp_db.create_session(sample_session)
        
        # Insert points in reverse order
        for i in range(5, 0, -1):
            temp_db.insert_gps_point(
                session_id=sample_session.session_id,
                lat=51.5 + i * 0.001,
                lon=-0.1,
                alt=30.0,
                timestamp=datetime(2025, 1, 1, 12, i, 0),
            )
            
        track = temp_db.get_gps_track(sample_session.session_id)
        # Should be ordered by timestamp ascending
        assert track[0]["latitude"] < track[-1]["latitude"]


class TestFingerprintSignatures:
    """Tests for fingerprint signature operations."""
    
    def test_insert_signature(self, temp_db):
        """Test inserting fingerprint signature."""
        temp_db.initialize_schema()
        sig = FingerprintSignature(
            fingerprint_hash="abc123hash",
            device_type="smartphone",
            device_model="iPhone 14",
            confidence=0.95,
            first_seen=datetime.now(timezone.utc),
        )
        result = temp_db.insert_signature(sig)
        assert result is True
        
    def test_get_signature(self, temp_db):
        """Test getting signature by hash."""
        temp_db.initialize_schema()
        sig = FingerprintSignature(
            fingerprint_hash="lookup_hash",
            device_type="laptop",
            device_model="MacBook Pro",
            confidence=0.85,
            first_seen=datetime.now(timezone.utc),
        )
        temp_db.insert_signature(sig)
        
        retrieved = temp_db.get_signature("lookup_hash")
        assert retrieved is not None
        assert retrieved["device_model"] == "MacBook Pro"
        
    def test_signature_times_seen_increment(self, temp_db):
        """Test times_seen increments on duplicate."""
        temp_db.initialize_schema()
        sig = FingerprintSignature(
            fingerprint_hash="dup_hash",
            device_type="phone",
            first_seen=datetime.now(timezone.utc),
        )
        
        temp_db.insert_signature(sig)
        temp_db.insert_signature(sig)
        temp_db.insert_signature(sig)
        
        retrieved = temp_db.get_signature("dup_hash")
        assert retrieved["times_seen"] == 3
        
    def test_get_all_signatures(self, temp_db):
        """Test getting all signatures."""
        temp_db.initialize_schema()
        for i in range(3):
            sig = FingerprintSignature(
                fingerprint_hash=f"hash_{i}",
                device_type="device",
                first_seen=datetime.now(timezone.utc),
            )
            temp_db.insert_signature(sig)
            
        signatures = temp_db.get_all_signatures()
        assert len(signatures) == 3


class TestPcapFiles:
    """Tests for pcap file operations."""
    
    def test_insert_pcap(self, temp_db, sample_session):
        """Test inserting pcap record."""
        temp_db.initialize_schema()
        temp_db.create_session(sample_session)
        
        pcap = PcapFile(
            session_id=sample_session.session_id,
            filename="capture_001.pcap",
            start_time=datetime.now(timezone.utc),
            file_size=1024 * 1024,
            packet_count=5000,
        )
        temp_db.insert_pcap(pcap)
        
        pcaps = temp_db.get_pcaps(sample_session.session_id)
        assert len(pcaps) == 1
        assert pcaps[0]["filename"] == "capture_001.pcap"


class TestDJIIntegration:
    """Tests for DJI flight integration."""
    
    def test_insert_dji_flight(self, temp_db, sample_session):
        """Test inserting DJI flight record."""
        temp_db.initialize_schema()
        temp_db.create_session(sample_session)
        
        flight = DJIFlight(
            session_id=sample_session.session_id,
            flight_log_file="DJI_0001.txt",
            start_time=datetime.now(timezone.utc),
            duration_seconds=600,
            max_altitude_m=50.0,
        )
        flight_id = temp_db.insert_dji_flight(flight)
        assert flight_id > 0
        
    def test_insert_dji_photo(self, temp_db, sample_session):
        """Test inserting DJI photo record."""
        temp_db.initialize_schema()
        temp_db.create_session(sample_session)
        
        photo = DJIPhoto(
            session_id=sample_session.session_id,
            filename="DJI_0001.JPG",
            timestamp=datetime.now(timezone.utc),
            gps_lat=51.5074,
            gps_lon=-0.1278,
            gps_alt=50.0,
        )
        temp_db.insert_dji_photo(photo)
        # No get method, just verify no error
        
    def test_update_device_gps(self, temp_db, sample_session, sample_wifi_ap):
        """Test updating device GPS from DJI data."""
        temp_db.initialize_schema()
        temp_db.create_session(sample_session)
        sample_wifi_ap.session_id = sample_session.session_id
        temp_db.insert_wifi_device(sample_wifi_ap)
        
        devices = temp_db.get_wifi_devices(sample_session.session_id)
        device_id = devices[0]["id"]
        
        temp_db.update_device_gps(device_id, 51.6, -0.2, 45.0, device_type="wifi")
        
        updated = temp_db.get_wifi_device_by_bssid(
            sample_session.session_id,
            sample_wifi_ap.bssid
        )
        assert updated["gps_lat"] == 51.6
        assert updated["gps_lon"] == -0.2


class TestSwarmSessions:
    """Tests for swarm session operations."""
    
    def test_create_swarm_session(self, temp_db):
        """Test creating a swarm session."""
        temp_db.initialize_schema()
        swarm = SwarmSession(
            swarm_session_id="SWARM_20251225_001",
            start_time=datetime.now(timezone.utc),
            controller_id="controller_laptop",
            property_id="FACILITY-A",
        )
        swarm_id = temp_db.create_swarm_session(swarm)
        assert swarm_id > 0


class TestSpatialQueries:
    """Tests for spatial/GPS queries."""
    
    def test_get_devices_near(self, temp_db, sample_session):
        """Test finding devices near a point."""
        temp_db.initialize_schema()
        temp_db.create_session(sample_session)
        
        # Insert devices at various locations
        locations = [
            (51.5074, -0.1278),  # Center
            (51.5075, -0.1279),  # ~15m away
            (51.5084, -0.1278),  # ~111m away
        ]
        
        for i, (lat, lon) in enumerate(locations):
            device = WiFiDevice(
                device_key=f"key_{i}",
                bssid=f"AA:BB:CC:DD:EE:{i:02d}",
                session_id=sample_session.session_id,
                gps_lat=lat,
                gps_lon=lon,
                gps_valid=True,
                first_seen=datetime.now(timezone.utc),
                last_seen=datetime.now(timezone.utc),
            )
            temp_db.insert_wifi_device(device)
            
        # Find devices within 50m of center
        nearby = temp_db.get_devices_near(51.5074, -0.1278, 50)
        assert len(nearby) >= 2  # Should find first two


class TestSessionStatistics:
    """Tests for session statistics."""
    
    def test_get_session_stats(self, temp_db, sample_session, sample_wifi_ap, sample_bt_classic):
        """Test getting session statistics."""
        temp_db.initialize_schema()
        temp_db.create_session(sample_session)
        
        # Add some devices
        sample_wifi_ap.session_id = sample_session.session_id
        sample_bt_classic.session_id = sample_session.session_id
        temp_db.insert_wifi_device(sample_wifi_ap)
        temp_db.insert_bt_device(sample_bt_classic)
        
        # Add GPS points
        for i in range(5):
            temp_db.insert_gps_point(
                session_id=sample_session.session_id,
                lat=51.5 + i * 0.001,
                lon=-0.1,
                alt=30.0,
            )
            
        stats = temp_db.get_session_stats(sample_session.session_id)
        assert stats["wifi_devices"] == 1
        assert stats["bt_devices"] == 1
        assert stats["gps_points"] == 5


class TestBufferRecovery:
    """Tests for buffer/recovery functionality."""
    
    def test_buffer_to_file(self, temp_db):
        """Test buffering data to file."""
        data = {"test": "data", "value": 123}
        temp_db._buffer_to_file("test", data)
        
        buffer_files = list(temp_db.backup_dir.glob("buffer_test_*.jsonl"))
        assert len(buffer_files) == 1
        
        with open(buffer_files[0]) as f:
            line = f.readline()
            assert json.loads(line) == data
            
    def test_flush_buffer(self, temp_db, sample_session):
        """Test flush buffer commits pending writes."""
        temp_db.initialize_schema()
        temp_db.create_session(sample_session)
        temp_db.flush_buffer()  # Should not raise


class TestReadOnlyMode:
    """Tests for read-only database access."""
    
    def test_readonly_wal_graceful(self, temp_db):
        """Test read-only database handles WAL pragma gracefully."""
        temp_db.initialize_schema()
        temp_db.close()
        
        # Reopen - WAL should work or be skipped
        temp_db.connect()
        # Should not raise


class TestEdgeCases:
    """Tests for edge cases and error handling."""
    
    def test_empty_session_no_devices(self, temp_db, sample_session):
        """Test getting devices from empty session."""
        temp_db.initialize_schema()
        temp_db.create_session(sample_session)
        
        devices = temp_db.get_wifi_devices(sample_session.session_id)
        assert devices == []
        
    def test_duplicate_session_id_fails(self, temp_db, sample_session):
        """Test duplicate session ID raises error."""
        temp_db.initialize_schema()
        temp_db.create_session(sample_session)
        
        with pytest.raises(sqlite3.IntegrityError):
            temp_db.create_session(sample_session)
