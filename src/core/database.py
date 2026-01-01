"""
Project Airdump - Database Layer

SQLite/SQLCipher database operations for storing scan data.
"""

import sqlite3
import json
import time
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any, Union
from contextlib import contextmanager

from .models import (
    ScanSession,
    WiFiDevice,
    BTDevice,
    FingerprintSignature,
    PcapFile,
    DJIFlight,
    DJIPhoto,
    SwarmSession,
    DeviceType,
    BTDeviceType,
)

logger = logging.getLogger(__name__)


# Database schema
SCHEMA = """
-- Scan sessions
CREATE TABLE IF NOT EXISTS scan_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT UNIQUE NOT NULL,
    start_time DATETIME NOT NULL,
    end_time DATETIME,
    status TEXT DEFAULT 'starting',
    property_id TEXT,
    operator TEXT,
    scan_type TEXT DEFAULT 'both',
    notes TEXT,
    node_id TEXT,
    swarm_session_id TEXT,
    wifi_device_count INTEGER DEFAULT 0,
    bt_device_count INTEGER DEFAULT 0
);

-- WiFi devices
CREATE TABLE IF NOT EXISTS wifi_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    device_key TEXT NOT NULL,
    bssid TEXT NOT NULL,
    essid TEXT,
    device_type TEXT DEFAULT 'unknown',
    channel INTEGER,
    frequency INTEGER,
    signal_dbm INTEGER,
    encryption TEXT,
    manufacturer TEXT,
    packets_total INTEGER DEFAULT 0,
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL,
    gps_lat REAL,
    gps_lon REAL,
    gps_alt REAL,
    gps_valid BOOLEAN DEFAULT FALSE,
    fingerprint_hash TEXT,
    fingerprint_data JSON,
    is_known BOOLEAN DEFAULT FALSE,
    identified_as TEXT,
    is_duplicate BOOLEAN DEFAULT FALSE,
    duplicate_of_id INTEGER,
    seen_by_nodes JSON,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(session_id)
);

-- Bluetooth devices
CREATE TABLE IF NOT EXISTS bt_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    device_key TEXT NOT NULL,
    mac_address TEXT NOT NULL,
    device_name TEXT,
    device_type TEXT DEFAULT 'unknown',
    device_class TEXT,
    rssi INTEGER,
    manufacturer TEXT,
    service_uuids JSON,
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL,
    gps_lat REAL,
    gps_lon REAL,
    gps_alt REAL,
    gps_valid BOOLEAN DEFAULT FALSE,
    fingerprint_hash TEXT,
    fingerprint_data JSON,
    is_known BOOLEAN DEFAULT FALSE,
    identified_as TEXT,
    is_duplicate BOOLEAN DEFAULT FALSE,
    duplicate_of_id INTEGER,
    seen_by_nodes JSON,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(session_id)
);

-- GPS track log
CREATE TABLE IF NOT EXISTS gps_track (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    timestamp DATETIME NOT NULL,
    latitude REAL,
    longitude REAL,
    altitude REAL,
    speed REAL,
    track REAL,
    fix_quality INTEGER,
    hdop REAL,
    satellites INTEGER,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(session_id)
);

-- Device fingerprint signatures
CREATE TABLE IF NOT EXISTS fingerprint_signatures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint_hash TEXT UNIQUE NOT NULL,
    device_type TEXT NOT NULL,
    device_model TEXT,
    os_version TEXT,
    confidence REAL DEFAULT 0.0,
    identifiers JSON,
    first_seen DATETIME NOT NULL,
    times_seen INTEGER DEFAULT 1,
    notes TEXT
);

-- Packet capture files
CREATE TABLE IF NOT EXISTS pcap_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    filename TEXT NOT NULL,
    start_time DATETIME NOT NULL,
    end_time DATETIME,
    file_size INTEGER DEFAULT 0,
    packet_count INTEGER DEFAULT 0,
    encrypted BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(session_id)
);

-- DJI flight logs
CREATE TABLE IF NOT EXISTS dji_flights (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    flight_log_file TEXT NOT NULL,
    start_time DATETIME,
    end_time DATETIME,
    duration_seconds INTEGER DEFAULT 0,
    distance_meters REAL DEFAULT 0.0,
    max_altitude_m REAL DEFAULT 0.0,
    max_speed_ms REAL DEFAULT 0.0,
    home_lat REAL,
    home_lon REAL,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(session_id)
);

-- DJI GPS track (high resolution)
CREATE TABLE IF NOT EXISTS dji_gps_track (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    flight_id INTEGER NOT NULL,
    timestamp DATETIME NOT NULL,
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

-- DJI photos
CREATE TABLE IF NOT EXISTS dji_photos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    filename TEXT NOT NULL,
    timestamp DATETIME NOT NULL,
    gps_lat REAL,
    gps_lon REAL,
    gps_alt REAL,
    linked_device_id INTEGER,
    distance_to_device_m REAL,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(session_id)
);

-- Swarm sessions
CREATE TABLE IF NOT EXISTS swarm_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    swarm_session_id TEXT UNIQUE NOT NULL,
    start_time DATETIME NOT NULL,
    end_time DATETIME,
    controller_id TEXT,
    property_id TEXT,
    notes TEXT
);

-- Create indexes for common queries
CREATE INDEX IF NOT EXISTS idx_wifi_session ON wifi_devices(session_id);
CREATE INDEX IF NOT EXISTS idx_wifi_bssid ON wifi_devices(bssid);
CREATE INDEX IF NOT EXISTS idx_wifi_fingerprint ON wifi_devices(fingerprint_hash);
CREATE INDEX IF NOT EXISTS idx_bt_session ON bt_devices(session_id);
CREATE INDEX IF NOT EXISTS idx_bt_mac ON bt_devices(mac_address);
CREATE INDEX IF NOT EXISTS idx_gps_session ON gps_track(session_id);
CREATE INDEX IF NOT EXISTS idx_gps_timestamp ON gps_track(timestamp);
"""


class Database:
    """SQLite/SQLCipher database handler."""
    
    def __init__(
        self,
        db_path: str,
        encryption_key: Optional[str] = None,
        backup_dir: Optional[str] = None,
    ):
        """
        Initialize database connection.
        
        Args:
            db_path: Path to SQLite database file
            encryption_key: Optional SQLCipher encryption key
            backup_dir: Directory for buffering failed writes
        """
        self.db_path = Path(db_path)
        self.encryption_key = encryption_key
        self.backup_dir = Path(backup_dir) if backup_dir else Path("/tmp/airdump_buffer")
        self._connection: Optional[sqlite3.Connection] = None
        
        # Ensure directories exist
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        
    def connect(self) -> sqlite3.Connection:
        """Create database connection."""
        if self._connection is not None:
            return self._connection
            
        try:
            # Try SQLCipher if encryption key provided
            if self.encryption_key:
                try:
                    from pysqlcipher3 import dbapi2 as sqlcipher
                    self._connection = sqlcipher.connect(str(self.db_path))
                    self._connection.execute(f"PRAGMA key = '{self.encryption_key}'")
                    logger.info("Connected with SQLCipher encryption")
                except ImportError:
                    logger.warning("SQLCipher not available, using standard SQLite")
                    self._connection = sqlite3.connect(str(self.db_path))
            else:
                self._connection = sqlite3.connect(str(self.db_path))
                
            # Enable foreign keys and WAL mode (may fail for read-only access)
            self._connection.execute("PRAGMA foreign_keys = ON")
            try:
                self._connection.execute("PRAGMA journal_mode = WAL")
            except sqlite3.OperationalError:
                # Read-only database, skip WAL mode
                pass
            
            # Row factory for dict-like access
            self._connection.row_factory = sqlite3.Row
            
            return self._connection
            
        except Exception as e:
            logger.error(f"Database connection failed: {e}")
            raise
            
    def close(self):
        """Close database connection."""
        if self._connection:
            self._connection.close()
            self._connection = None
            logger.info("Database connection closed")
            
    @contextmanager
    def transaction(self):
        """Context manager for transactions."""
        conn = self.connect()
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error(f"Transaction failed, rolled back: {e}")
            raise
            
    def initialize_schema(self):
        """Create database schema."""
        conn = self.connect()
        conn.executescript(SCHEMA)
        conn.commit()
        logger.info("Database schema initialized")
        
    # =========================================================================
    # SCAN SESSIONS
    # =========================================================================
    
    def create_session(self, session: ScanSession) -> int:
        """Create a new scan session."""
        with self.transaction() as conn:
            cursor = conn.execute(
                """
                INSERT INTO scan_sessions 
                (session_id, start_time, status, property_id, operator, scan_type, notes, node_id, swarm_session_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session.session_id,
                    session.start_time.isoformat(),
                    session.status.value if hasattr(session.status, 'value') else session.status,
                    session.property_id,
                    session.operator,
                    session.scan_type,
                    session.notes,
                    session.node_id,
                    session.swarm_session_id,
                )
            )
            logger.info(f"Created session: {session.session_id}")
            return cursor.lastrowid
            
    def end_session(self, session_id: str, end_time: Optional[datetime] = None):
        """Mark session as ended."""
        end_time = end_time or datetime.utcnow()
        with self.transaction() as conn:
            conn.execute(
                "UPDATE scan_sessions SET end_time = ? WHERE session_id = ?",
                (end_time.isoformat(), session_id)
            )
            logger.info(f"Ended session: {session_id}")
    
    def update_session(self, session: ScanSession):
        """Update session with current values."""
        with self.transaction() as conn:
            conn.execute(
                """
                UPDATE scan_sessions 
                SET end_time = ?, status = ?, wifi_device_count = ?, bt_device_count = ?
                WHERE session_id = ?
                """,
                (
                    session.end_time.isoformat() if session.end_time else None,
                    session.status.value if hasattr(session.status, 'value') else session.status,
                    session.wifi_device_count,
                    session.bt_device_count,
                    session.session_id,
                )
            )
            logger.info(f"Updated session: {session.session_id}")
    
    def flush_buffer(self):
        """Flush any pending writes to database."""
        # Commit any pending transaction
        if self._connection:
            self._connection.commit()
        logger.debug("Database buffer flushed")
            
    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session by ID."""
        conn = self.connect()
        row = conn.execute(
            "SELECT * FROM scan_sessions WHERE session_id = ?",
            (session_id,)
        ).fetchone()
        return dict(row) if row else None
    
    def get_latest_session(self) -> Optional[Dict[str, Any]]:
        """Get the most recent scan session."""
        conn = self.connect()
        row = conn.execute(
            "SELECT * FROM scan_sessions ORDER BY start_time DESC LIMIT 1"
        ).fetchone()
        return dict(row) if row else None
        
    def get_sessions(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent sessions."""
        conn = self.connect()
        rows = conn.execute(
            "SELECT * FROM scan_sessions ORDER BY start_time DESC LIMIT ?",
            (limit,)
        ).fetchall()
        return [dict(row) for row in rows]
        
    # =========================================================================
    # WIFI DEVICES
    # =========================================================================
    
    def insert_wifi_device(self, device: WiFiDevice, retries: int = 3) -> bool:
        """Insert or update WiFi device with retry logic."""
        for attempt in range(retries):
            try:
                return self._do_insert_wifi(device)
            except sqlite3.Error as e:
                logger.warning(f"WiFi insert failed (attempt {attempt + 1}): {e}")
                time.sleep(0.1 * (attempt + 1))
                
        # All retries failed - buffer to file
        logger.error("WiFi insert failed, buffering to file")
        self._buffer_to_file("wifi", device.to_dict())
        return False
        
    def _do_insert_wifi(self, device: WiFiDevice) -> bool:
        """Actual WiFi device insert/update."""
        with self.transaction() as conn:
            # Check if device exists in this session
            existing = conn.execute(
                """
                SELECT id, packets_total FROM wifi_devices 
                WHERE session_id = ? AND device_key = ?
                """,
                (device.session_id, device.device_key)
            ).fetchone()
            
            if existing:
                # Update existing device
                conn.execute(
                    """
                    UPDATE wifi_devices SET
                        essid = COALESCE(?, essid),
                        channel = COALESCE(?, channel),
                        frequency = COALESCE(?, frequency),
                        signal_dbm = ?,
                        encryption = COALESCE(?, encryption),
                        packets_total = ?,
                        last_seen = ?,
                        gps_lat = ?,
                        gps_lon = ?,
                        gps_alt = ?,
                        gps_valid = ?,
                        fingerprint_hash = COALESCE(?, fingerprint_hash),
                        fingerprint_data = COALESCE(?, fingerprint_data)
                    WHERE id = ?
                    """,
                    (
                        device.essid,
                        device.channel,
                        device.frequency,
                        device.signal_dbm,
                        device.encryption,
                        device.packets_total,
                        device.last_seen.isoformat(),
                        device.gps_lat,
                        device.gps_lon,
                        device.gps_alt,
                        device.gps_valid,
                        device.fingerprint_hash,
                        json.dumps(device.fingerprint_data) if device.fingerprint_data else None,
                        existing["id"],
                    )
                )
            else:
                # Insert new device
                conn.execute(
                    """
                    INSERT INTO wifi_devices
                    (session_id, device_key, bssid, essid, device_type, channel, frequency,
                     signal_dbm, encryption, manufacturer, packets_total, first_seen, last_seen,
                     gps_lat, gps_lon, gps_alt, gps_valid, fingerprint_hash, fingerprint_data,
                     is_known, identified_as, seen_by_nodes)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        device.session_id,
                        device.device_key,
                        device.bssid,
                        device.essid,
                        device.device_type.value,
                        device.channel,
                        device.frequency,
                        device.signal_dbm,
                        device.encryption,
                        device.manufacturer,
                        device.packets_total,
                        device.first_seen.isoformat(),
                        device.last_seen.isoformat(),
                        device.gps_lat,
                        device.gps_lon,
                        device.gps_alt,
                        device.gps_valid,
                        device.fingerprint_hash,
                        json.dumps(device.fingerprint_data) if device.fingerprint_data else None,
                        device.is_known,
                        device.identified_as,
                        json.dumps(device.seen_by_nodes),
                    )
                )
            return True
            
    def get_wifi_devices(
        self,
        session_id: str,
        unknown_only: bool = False,
    ) -> List[Dict[str, Any]]:
        """Get WiFi devices for a session."""
        conn = self.connect()
        query = "SELECT * FROM wifi_devices WHERE session_id = ?"
        params: List[Any] = [session_id]
        
        if unknown_only:
            query += " AND is_known = FALSE"
            
        rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]
        
    def get_wifi_device_by_bssid(
        self,
        session_id: str,
        bssid: str,
    ) -> Optional[Dict[str, Any]]:
        """Get WiFi device by BSSID."""
        conn = self.connect()
        row = conn.execute(
            "SELECT * FROM wifi_devices WHERE session_id = ? AND bssid = ?",
            (session_id, bssid)
        ).fetchone()
        return dict(row) if row else None
        
    def update_wifi_known_status(
        self,
        device_id: int,
        is_known: bool,
        identified_as: Optional[str] = None,
    ):
        """Update device known status."""
        with self.transaction() as conn:
            conn.execute(
                "UPDATE wifi_devices SET is_known = ?, identified_as = ? WHERE id = ?",
                (is_known, identified_as, device_id)
            )
            
    # =========================================================================
    # BLUETOOTH DEVICES
    # =========================================================================
    
    def insert_bt_device(self, device: BTDevice, retries: int = 3) -> bool:
        """Insert or update Bluetooth device with retry logic."""
        for attempt in range(retries):
            try:
                return self._do_insert_bt(device)
            except sqlite3.Error as e:
                logger.warning(f"BT insert failed (attempt {attempt + 1}): {e}")
                time.sleep(0.1 * (attempt + 1))
                
        logger.error("BT insert failed, buffering to file")
        self._buffer_to_file("bt", device.to_dict())
        return False
        
    def _do_insert_bt(self, device: BTDevice) -> bool:
        """Actual Bluetooth device insert/update."""
        with self.transaction() as conn:
            existing = conn.execute(
                """
                SELECT id FROM bt_devices 
                WHERE session_id = ? AND device_key = ?
                """,
                (device.session_id, device.device_key)
            ).fetchone()
            
            if existing:
                conn.execute(
                    """
                    UPDATE bt_devices SET
                        device_name = COALESCE(?, device_name),
                        device_class = COALESCE(?, device_class),
                        rssi = ?,
                        service_uuids = COALESCE(?, service_uuids),
                        last_seen = ?,
                        gps_lat = ?,
                        gps_lon = ?,
                        gps_alt = ?,
                        gps_valid = ?,
                        fingerprint_hash = COALESCE(?, fingerprint_hash),
                        fingerprint_data = COALESCE(?, fingerprint_data)
                    WHERE id = ?
                    """,
                    (
                        device.device_name,
                        device.device_class,
                        device.rssi,
                        json.dumps(device.service_uuids),
                        device.last_seen.isoformat(),
                        device.gps_lat,
                        device.gps_lon,
                        device.gps_alt,
                        device.gps_valid,
                        device.fingerprint_hash,
                        json.dumps(device.fingerprint_data) if device.fingerprint_data else None,
                        existing["id"],
                    )
                )
            else:
                conn.execute(
                    """
                    INSERT INTO bt_devices
                    (session_id, device_key, mac_address, device_name, device_type, device_class,
                     rssi, manufacturer, service_uuids, first_seen, last_seen,
                     gps_lat, gps_lon, gps_alt, gps_valid, fingerprint_hash, fingerprint_data,
                     is_known, identified_as, seen_by_nodes)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        device.session_id,
                        device.device_key,
                        device.mac_address,
                        device.device_name,
                        device.device_type.value,
                        device.device_class,
                        device.rssi,
                        device.manufacturer,
                        json.dumps(device.service_uuids),
                        device.first_seen.isoformat(),
                        device.last_seen.isoformat(),
                        device.gps_lat,
                        device.gps_lon,
                        device.gps_alt,
                        device.gps_valid,
                        device.fingerprint_hash,
                        json.dumps(device.fingerprint_data) if device.fingerprint_data else None,
                        device.is_known,
                        device.identified_as,
                        json.dumps(device.seen_by_nodes),
                    )
                )
            return True
            
    def get_bt_devices(
        self,
        session_id: str,
        unknown_only: bool = False,
    ) -> List[Dict[str, Any]]:
        """Get Bluetooth devices for a session."""
        conn = self.connect()
        query = "SELECT * FROM bt_devices WHERE session_id = ?"
        params: List[Any] = [session_id]
        
        if unknown_only:
            query += " AND is_known = FALSE"
            
        rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]
        
    # =========================================================================
    # GPS TRACK
    # =========================================================================
    
    def insert_gps_point(
        self,
        session_id: str,
        lat: Optional[float],
        lon: Optional[float],
        alt: Optional[float],
        speed: Optional[float] = None,
        track: Optional[float] = None,
        fix_quality: int = 0,
        hdop: Optional[float] = None,
        satellites: int = 0,
        timestamp: Optional[datetime] = None,
    ):
        """Insert GPS track point."""
        timestamp = timestamp or datetime.utcnow()
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO gps_track
                (session_id, timestamp, latitude, longitude, altitude, speed, track, fix_quality, hdop, satellites)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (session_id, timestamp.isoformat(), lat, lon, alt, speed, track, fix_quality, hdop, satellites)
            )
            
    def get_gps_track(self, session_id: str) -> List[Dict[str, Any]]:
        """Get GPS track for session."""
        conn = self.connect()
        rows = conn.execute(
            "SELECT * FROM gps_track WHERE session_id = ? ORDER BY timestamp",
            (session_id,)
        ).fetchall()
        return [dict(row) for row in rows]
        
    # =========================================================================
    # FINGERPRINT SIGNATURES
    # =========================================================================
    
    def insert_signature(self, sig: FingerprintSignature) -> bool:
        """Insert or update fingerprint signature."""
        with self.transaction() as conn:
            existing = conn.execute(
                "SELECT id, times_seen FROM fingerprint_signatures WHERE fingerprint_hash = ?",
                (sig.fingerprint_hash,)
            ).fetchone()
            
            if existing:
                conn.execute(
                    "UPDATE fingerprint_signatures SET times_seen = ? WHERE id = ?",
                    (existing["times_seen"] + 1, existing["id"])
                )
            else:
                conn.execute(
                    """
                    INSERT INTO fingerprint_signatures
                    (fingerprint_hash, device_type, device_model, os_version, confidence, identifiers, first_seen, notes)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        sig.fingerprint_hash,
                        sig.device_type,
                        sig.device_model,
                        sig.os_version,
                        sig.confidence,
                        json.dumps(sig.identifiers),
                        sig.first_seen.isoformat(),
                        sig.notes,
                    )
                )
            return True
            
    def get_signature(self, fingerprint_hash: str) -> Optional[Dict[str, Any]]:
        """Get signature by hash."""
        conn = self.connect()
        row = conn.execute(
            "SELECT * FROM fingerprint_signatures WHERE fingerprint_hash = ?",
            (fingerprint_hash,)
        ).fetchone()
        return dict(row) if row else None
        
    def get_all_signatures(self) -> List[Dict[str, Any]]:
        """Get all fingerprint signatures."""
        conn = self.connect()
        rows = conn.execute("SELECT * FROM fingerprint_signatures").fetchall()
        return [dict(row) for row in rows]
        
    # =========================================================================
    # PCAP FILES
    # =========================================================================
    
    def insert_pcap(self, pcap: PcapFile):
        """Insert pcap file record."""
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO pcap_files
                (session_id, filename, start_time, end_time, file_size, packet_count, encrypted)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    pcap.session_id,
                    pcap.filename,
                    pcap.start_time.isoformat(),
                    pcap.end_time.isoformat() if pcap.end_time else None,
                    pcap.file_size,
                    pcap.packet_count,
                    pcap.encrypted,
                )
            )
            
    def get_pcaps(self, session_id: str) -> List[Dict[str, Any]]:
        """Get pcap files for session."""
        conn = self.connect()
        rows = conn.execute(
            "SELECT * FROM pcap_files WHERE session_id = ?",
            (session_id,)
        ).fetchall()
        return [dict(row) for row in rows]
        
    # =========================================================================
    # DJI INTEGRATION
    # =========================================================================
    
    def insert_dji_flight(self, flight: DJIFlight) -> int:
        """Insert DJI flight record."""
        with self.transaction() as conn:
            cursor = conn.execute(
                """
                INSERT INTO dji_flights
                (session_id, flight_log_file, start_time, end_time, duration_seconds,
                 distance_meters, max_altitude_m, max_speed_ms, home_lat, home_lon)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    flight.session_id,
                    flight.flight_log_file,
                    flight.start_time.isoformat() if flight.start_time else None,
                    flight.end_time.isoformat() if flight.end_time else None,
                    flight.duration_seconds,
                    flight.distance_meters,
                    flight.max_altitude_m,
                    flight.max_speed_ms,
                    flight.home_lat,
                    flight.home_lon,
                )
            )
            return cursor.lastrowid
            
    def insert_dji_photo(self, photo: DJIPhoto):
        """Insert DJI photo record."""
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO dji_photos
                (session_id, filename, timestamp, gps_lat, gps_lon, gps_alt, linked_device_id, distance_to_device_m)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    photo.session_id,
                    photo.filename,
                    photo.timestamp.isoformat(),
                    photo.gps_lat,
                    photo.gps_lon,
                    photo.gps_alt,
                    photo.linked_device_id,
                    photo.distance_to_device_m,
                )
            )
            
    def update_device_gps(
        self,
        device_id: int,
        lat: float,
        lon: float,
        alt: float,
        gps_source: str = "dji_upgraded",
        device_type: str = "wifi",
    ):
        """Update device GPS coordinates (for DJI upgrade)."""
        table = "wifi_devices" if device_type == "wifi" else "bt_devices"
        with self.transaction() as conn:
            conn.execute(
                f"UPDATE {table} SET gps_lat = ?, gps_lon = ?, gps_alt = ?, gps_valid = TRUE WHERE id = ?",
                (lat, lon, alt, device_id)
            )
            
    # =========================================================================
    # SWARM
    # =========================================================================
    
    def create_swarm_session(self, swarm: SwarmSession) -> int:
        """Create swarm session."""
        with self.transaction() as conn:
            cursor = conn.execute(
                """
                INSERT INTO swarm_sessions
                (swarm_session_id, start_time, controller_id, property_id, notes)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    swarm.swarm_session_id,
                    swarm.start_time.isoformat(),
                    swarm.controller_id,
                    swarm.property_id,
                    swarm.notes,
                )
            )
            return cursor.lastrowid
            
    def get_devices_near(
        self,
        lat: float,
        lon: float,
        radius_m: float,
        session_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get devices within radius of a point (simple Euclidean approximation)."""
        # Rough conversion: 1 degree ≈ 111km at equator
        deg_radius = radius_m / 111000.0
        
        conn = self.connect()
        query = """
            SELECT *, 
                   (gps_lat - ?) * (gps_lat - ?) + (gps_lon - ?) * (gps_lon - ?) as dist_sq
            FROM wifi_devices
            WHERE gps_lat BETWEEN ? AND ?
              AND gps_lon BETWEEN ? AND ?
        """
        params: List[Any] = [
            lat, lat, lon, lon,
            lat - deg_radius, lat + deg_radius,
            lon - deg_radius, lon + deg_radius,
        ]
        
        if session_id:
            query += " AND session_id = ?"
            params.append(session_id)
            
        query += " ORDER BY dist_sq"
        
        rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]
        
    # =========================================================================
    # STATISTICS
    # =========================================================================
    
    def get_session_stats(self, session_id: str) -> Dict[str, Any]:
        """Get statistics for a session."""
        conn = self.connect()
        
        wifi_count = conn.execute(
            "SELECT COUNT(*) as count FROM wifi_devices WHERE session_id = ?",
            (session_id,)
        ).fetchone()["count"]
        
        wifi_unknown = conn.execute(
            "SELECT COUNT(*) as count FROM wifi_devices WHERE session_id = ? AND is_known = FALSE",
            (session_id,)
        ).fetchone()["count"]
        
        bt_count = conn.execute(
            "SELECT COUNT(*) as count FROM bt_devices WHERE session_id = ?",
            (session_id,)
        ).fetchone()["count"]
        
        bt_unknown = conn.execute(
            "SELECT COUNT(*) as count FROM bt_devices WHERE session_id = ? AND is_known = FALSE",
            (session_id,)
        ).fetchone()["count"]
        
        gps_points = conn.execute(
            "SELECT COUNT(*) as count FROM gps_track WHERE session_id = ?",
            (session_id,)
        ).fetchone()["count"]
        
        return {
            "wifi_devices": wifi_count,
            "wifi_unknown": wifi_unknown,
            "bt_devices": bt_count,
            "bt_unknown": bt_unknown,
            "gps_points": gps_points,
        }
        
    # =========================================================================
    # BUFFER/RECOVERY
    # =========================================================================
    
    def _buffer_to_file(self, record_type: str, data: Dict[str, Any]):
        """Buffer failed record to JSON file."""
        buffer_file = self.backup_dir / f"buffer_{record_type}_{int(time.time())}.jsonl"
        with open(buffer_file, "a") as f:
            f.write(json.dumps(data) + "\n")
        logger.info(f"Buffered {record_type} record to {buffer_file}")
        
    def import_buffered_records(self) -> int:
        """Import buffered records back into database."""
        imported = 0
        for buffer_file in self.backup_dir.glob("buffer_*.jsonl"):
            record_type = buffer_file.stem.split("_")[1]
            
            with open(buffer_file, "r") as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        if record_type == "wifi":
                            device = WiFiDevice(**data)
                            if self._do_insert_wifi(device):
                                imported += 1
                        elif record_type == "bt":
                            device = BTDevice(**data)
                            if self._do_insert_bt(device):
                                imported += 1
                    except Exception as e:
                        logger.error(f"Failed to import buffered record: {e}")
                        
            # Remove successfully processed buffer
            buffer_file.unlink()
            logger.info(f"Imported buffered records from {buffer_file}")
            
        return imported
