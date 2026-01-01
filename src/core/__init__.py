"""
Project Airdump - Core Module

Core functionality including database, models, and utilities.
"""

from .models import (
    DeviceType,
    BTDeviceType,
    ScanStatus,
    GPSFixQuality,
    GPSPosition,
    ScanSession,
    WiFiDevice,
    BTDevice,
    FingerprintSignature,
    PcapFile,
    DJIFlight,
    DJIPhoto,
    SwarmSession,
    Heartbeat,
)

from .database import Database
from .utils import (
    setup_logging,
    load_config,
    generate_session_id,
    normalize_mac,
    haversine_distance,
)
from .encryption import KeyManager, GPGEncryption

__all__ = [
    # Enums
    "DeviceType",
    "BTDeviceType",
    "ScanStatus",
    "GPSFixQuality",
    # Data classes
    "GPSPosition",
    "ScanSession",
    "WiFiDevice",
    "BTDevice",
    "FingerprintSignature",
    "PcapFile",
    "DJIFlight",
    "DJIPhoto",
    "SwarmSession",
    "Heartbeat",
    # Database
    "Database",
    # Utilities
    "setup_logging",
    "load_config",
    "generate_session_id",
    "normalize_mac",
    "haversine_distance",
    # Encryption
    "KeyManager",
    "GPGEncryption",
]
