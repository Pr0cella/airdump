"""
Project Airdump - Core Data Models

Data classes representing all entities in the system.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum
import json


class DeviceType(Enum):
    """WiFi device types."""
    AP = "ap"
    CLIENT = "client"
    BRIDGE = "bridge"
    ADHOC = "adhoc"
    UNKNOWN = "unknown"


class BTDeviceType(Enum):
    """Bluetooth device types."""
    CLASSIC = "classic"
    BLE = "ble"
    DUAL = "dual"
    UNKNOWN = "unknown"


class ScanStatus(Enum):
    """Scan session status."""
    RUNNING = "running"
    STOPPED = "stopped"
    ERROR = "error"
    STARTING = "starting"
    STOPPING = "stopping"


class GPSFixQuality(Enum):
    """GPS fix quality types."""
    NONE = 0
    FIX_2D = 2
    FIX_3D = 3


@dataclass
class GPSPosition:
    """GPS position data."""
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    altitude: Optional[float] = None
    speed: Optional[float] = None
    track: Optional[float] = None
    fix_quality: GPSFixQuality = GPSFixQuality.NONE
    hdop: Optional[float] = None
    satellites: int = 0
    timestamp: datetime = field(default_factory=datetime.utcnow)
    gps_valid: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "latitude": self.latitude,
            "longitude": self.longitude,
            "altitude": self.altitude,
            "speed": self.speed,
            "track": self.track,
            "fix_quality": self.fix_quality.value,
            "hdop": self.hdop,
            "satellites": self.satellites,
            "timestamp": self.timestamp.isoformat(),
            "gps_valid": self.gps_valid,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GPSPosition":
        return cls(
            latitude=data.get("latitude"),
            longitude=data.get("longitude"),
            altitude=data.get("altitude"),
            speed=data.get("speed"),
            track=data.get("track"),
            fix_quality=GPSFixQuality(data.get("fix_quality", 0)),
            hdop=data.get("hdop"),
            satellites=data.get("satellites", 0),
            timestamp=datetime.fromisoformat(data["timestamp"]) if data.get("timestamp") else datetime.utcnow(),
            gps_valid=data.get("gps_valid", False),
        )


@dataclass
class ScanSession:
    """Represents a scanning session."""
    session_id: str
    start_time: datetime = field(default_factory=datetime.utcnow)
    end_time: Optional[datetime] = None
    status: ScanStatus = ScanStatus.STARTING
    property_id: Optional[str] = None
    operator: Optional[str] = None
    scan_type: str = "both"  # wifi, bluetooth, both
    notes: Optional[str] = None
    node_id: Optional[str] = None  # For swarm mode
    swarm_session_id: Optional[str] = None  # For swarm mode
    wifi_device_count: int = 0
    bt_device_count: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "status": self.status.value,
            "property_id": self.property_id,
            "operator": self.operator,
            "scan_type": self.scan_type,
            "notes": self.notes,
            "node_id": self.node_id,
            "swarm_session_id": self.swarm_session_id,
            "wifi_device_count": self.wifi_device_count,
            "bt_device_count": self.bt_device_count,
        }


@dataclass
class WiFiDevice:
    """Represents a detected WiFi device."""
    # Identifiers
    device_key: str  # Kismet unique key
    bssid: str
    
    # Basic info
    essid: Optional[str] = None
    device_type: DeviceType = DeviceType.UNKNOWN
    channel: Optional[int] = None
    frequency: Optional[int] = None
    
    # Signal
    signal_dbm: Optional[int] = None
    
    # Security
    encryption: Optional[str] = None  # WPA2, WPA3, OWE, Open
    
    # Metadata
    manufacturer: Optional[str] = None
    packets_total: int = 0
    
    # Timestamps
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    
    # GPS
    gps_lat: Optional[float] = None
    gps_lon: Optional[float] = None
    gps_alt: Optional[float] = None
    gps_valid: bool = False
    
    # Fingerprinting
    fingerprint_hash: Optional[str] = None
    fingerprint_data: Optional[Dict[str, Any]] = None
    
    # Analysis
    is_known: bool = False
    identified_as: Optional[str] = None
    
    # Swarm
    session_id: Optional[str] = None
    is_duplicate: bool = False
    duplicate_of_id: Optional[int] = None
    seen_by_nodes: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "device_key": self.device_key,
            "bssid": self.bssid,
            "essid": self.essid,
            "device_type": self.device_type.value,
            "channel": self.channel,
            "frequency": self.frequency,
            "signal_dbm": self.signal_dbm,
            "encryption": self.encryption,
            "manufacturer": self.manufacturer,
            "packets_total": self.packets_total,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "gps_lat": self.gps_lat,
            "gps_lon": self.gps_lon,
            "gps_alt": self.gps_alt,
            "gps_valid": self.gps_valid,
            "fingerprint_hash": self.fingerprint_hash,
            "fingerprint_data": self.fingerprint_data,
            "is_known": self.is_known,
            "identified_as": self.identified_as,
            "session_id": self.session_id,
            "is_duplicate": self.is_duplicate,
            "seen_by_nodes": self.seen_by_nodes,
        }
    
    def to_json_line(self, node_id: str) -> str:
        """Format for JSON-lines streaming."""
        return json.dumps({
            "type": "wifi",
            "mac": self.bssid,
            "ssid": self.essid,
            "rssi": self.signal_dbm,
            "gps": [self.gps_lat, self.gps_lon, self.gps_alt],
            "ts": self.last_seen.isoformat() + "Z",
            "node": node_id,
        })


@dataclass
class BTDevice:
    """Represents a detected Bluetooth device."""
    # Identifiers
    device_key: str  # Kismet unique key
    mac_address: str
    
    # Basic info
    device_name: Optional[str] = None
    device_type: BTDeviceType = BTDeviceType.UNKNOWN
    device_class: Optional[str] = None  # Bluetooth device class
    
    # Signal
    rssi: Optional[int] = None
    
    # Metadata
    manufacturer: Optional[str] = None
    service_uuids: List[str] = field(default_factory=list)
    
    # Timestamps
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    
    # GPS
    gps_lat: Optional[float] = None
    gps_lon: Optional[float] = None
    gps_alt: Optional[float] = None
    gps_valid: bool = False
    
    # Fingerprinting
    fingerprint_hash: Optional[str] = None
    fingerprint_data: Optional[Dict[str, Any]] = None
    
    # Analysis
    is_known: bool = False
    identified_as: Optional[str] = None
    
    # Swarm
    session_id: Optional[str] = None
    is_duplicate: bool = False
    duplicate_of_id: Optional[int] = None
    seen_by_nodes: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "device_key": self.device_key,
            "mac_address": self.mac_address,
            "device_name": self.device_name,
            "device_type": self.device_type.value,
            "device_class": self.device_class,
            "rssi": self.rssi,
            "manufacturer": self.manufacturer,
            "service_uuids": self.service_uuids,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "gps_lat": self.gps_lat,
            "gps_lon": self.gps_lon,
            "gps_alt": self.gps_alt,
            "gps_valid": self.gps_valid,
            "fingerprint_hash": self.fingerprint_hash,
            "fingerprint_data": self.fingerprint_data,
            "is_known": self.is_known,
            "identified_as": self.identified_as,
            "session_id": self.session_id,
            "is_duplicate": self.is_duplicate,
            "seen_by_nodes": self.seen_by_nodes,
        }
    
    def to_json_line(self, node_id: str) -> str:
        """Format for JSON-lines streaming."""
        return json.dumps({
            "type": "bt",
            "mac": self.mac_address,
            "name": self.device_name,
            "rssi": self.rssi,
            "gps": [self.gps_lat, self.gps_lon, self.gps_alt],
            "ts": self.last_seen.isoformat() + "Z",
            "node": node_id,
        })


@dataclass
class FingerprintSignature:
    """Known device fingerprint signature."""
    fingerprint_hash: str
    device_type: str
    device_model: Optional[str] = None
    os_version: Optional[str] = None
    confidence: float = 0.0
    identifiers: Dict[str, Any] = field(default_factory=dict)
    first_seen: datetime = field(default_factory=datetime.utcnow)
    times_seen: int = 1
    notes: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "fingerprint_hash": self.fingerprint_hash,
            "device_type": self.device_type,
            "device_model": self.device_model,
            "os_version": self.os_version,
            "confidence": self.confidence,
            "identifiers": self.identifiers,
            "first_seen": self.first_seen.isoformat(),
            "times_seen": self.times_seen,
            "notes": self.notes,
        }


@dataclass
class PcapFile:
    """Metadata for a packet capture file."""
    filename: str
    session_id: str
    start_time: datetime = field(default_factory=datetime.utcnow)
    end_time: Optional[datetime] = None
    file_size: int = 0
    packet_count: int = 0
    encrypted: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "filename": self.filename,
            "session_id": self.session_id,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "file_size": self.file_size,
            "packet_count": self.packet_count,
            "encrypted": self.encrypted,
        }


@dataclass
class DJIFlight:
    """DJI flight log data."""
    session_id: str
    flight_log_file: str
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration_seconds: int = 0
    distance_meters: float = 0.0
    max_altitude_m: float = 0.0
    max_speed_ms: float = 0.0
    home_lat: Optional[float] = None
    home_lon: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "flight_log_file": self.flight_log_file,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": self.duration_seconds,
            "distance_meters": self.distance_meters,
            "max_altitude_m": self.max_altitude_m,
            "max_speed_ms": self.max_speed_ms,
            "home_lat": self.home_lat,
            "home_lon": self.home_lon,
        }


@dataclass
class DJIPhoto:
    """DJI geo-tagged photo."""
    filename: str
    session_id: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    gps_lat: Optional[float] = None
    gps_lon: Optional[float] = None
    gps_alt: Optional[float] = None
    linked_device_id: Optional[int] = None
    distance_to_device_m: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "filename": self.filename,
            "session_id": self.session_id,
            "timestamp": self.timestamp.isoformat(),
            "gps_lat": self.gps_lat,
            "gps_lon": self.gps_lon,
            "gps_alt": self.gps_alt,
            "linked_device_id": self.linked_device_id,
            "distance_to_device_m": self.distance_to_device_m,
        }


@dataclass
class SwarmSession:
    """Swarm session tracking."""
    swarm_session_id: str
    start_time: datetime = field(default_factory=datetime.utcnow)
    end_time: Optional[datetime] = None
    controller_id: Optional[str] = None
    property_id: Optional[str] = None
    notes: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "swarm_session_id": self.swarm_session_id,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "controller_id": self.controller_id,
            "property_id": self.property_id,
            "notes": self.notes,
        }


@dataclass
class Heartbeat:
    """Swarm node heartbeat message."""
    node_id: str
    status: ScanStatus
    timestamp: datetime = field(default_factory=datetime.utcnow)
    gps_valid: bool = False
    gps_lat: Optional[float] = None
    gps_lon: Optional[float] = None
    wifi_devices_count: int = 0
    bt_devices_count: int = 0
    db_size_mb: float = 0.0
    pcap_size_mb: float = 0.0
    battery_voltage: Optional[float] = None
    uptime_seconds: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "status": self.status.value,
            "timestamp": self.timestamp.isoformat(),
            "gps_valid": self.gps_valid,
            "gps_lat": self.gps_lat,
            "gps_lon": self.gps_lon,
            "wifi_devices_count": self.wifi_devices_count,
            "bt_devices_count": self.bt_devices_count,
            "db_size_mb": self.db_size_mb,
            "pcap_size_mb": self.pcap_size_mb,
            "battery_voltage": self.battery_voltage,
            "uptime_seconds": self.uptime_seconds,
        }
    
    def to_json_line(self) -> str:
        """Format for JSON-lines streaming."""
        return json.dumps({
            "type": "heartbeat",
            "node": self.node_id,
            "status": self.status.value,
            "ts": self.timestamp.isoformat() + "Z",
        })
