"""
Project Airdump - Fingerprint Engine

Main fingerprinting orchestrator that coordinates WiFi and Bluetooth
fingerprinting with GPS tagging and database storage.
"""

import logging
import threading
from datetime import datetime
from typing import Optional, List, Dict, Any, Callable

from .wifi_fingerprint import WiFiFingerprinter, WiFiCapabilities
from .bt_fingerprint import BluetoothFingerprinter, BluetoothCapabilities

logger = logging.getLogger(__name__)


class FingerprintEngine:
    """
    Central fingerprinting engine.
    
    Coordinates device fingerprinting across WiFi and Bluetooth,
    correlates with GPS positions, and stores to database.
    """
    
    def __init__(
        self,
        database=None,
        gps_logger=None,
        auto_store: bool = True,
    ):
        """
        Initialize fingerprint engine.
        
        Args:
            database: Database instance for storage
            gps_logger: GPSLogger for position tagging
            auto_store: Automatically store fingerprints to database
        """
        self.database = database
        self.gps_logger = gps_logger
        self.auto_store = auto_store
        
        # Sub-engines
        self.wifi = WiFiFingerprinter()
        self.bluetooth = BluetoothFingerprinter()
        
        self._lock = threading.Lock()
        
        # Callbacks for new fingerprints
        self._callbacks: List[Callable[[str, str, dict], None]] = []
        
        # Statistics
        self._stats = {
            "wifi_fingerprints": 0,
            "bt_fingerprints": 0,
            "unique_wifi_devices": 0,
            "unique_bt_devices": 0,
            "randomized_macs_detected": 0,
        }
        
    def process_wifi_probe(
        self,
        mac: str,
        ssid: str,
        rssi: int,
        supported_rates: List[int] = None,
        ht_capabilities: Optional[str] = None,
        vht_capabilities: Optional[str] = None,
        vendor_ies: List[Dict[str, Any]] = None,
        timestamp: Optional[datetime] = None,
        channel: int = 0,
    ) -> str:
        """
        Process WiFi probe request for fingerprinting.
        
        Args:
            mac: Source MAC address
            ssid: Probed SSID
            rssi: Signal strength
            supported_rates: Supported data rates
            ht_capabilities: HT capabilities
            vht_capabilities: VHT capabilities
            vendor_ies: Vendor-specific IEs
            timestamp: Detection timestamp
            channel: Channel number
            
        Returns:
            Fingerprint hash
        """
        timestamp = timestamp or datetime.utcnow()
        
        # Get GPS position
        gps_pos = None
        gps_valid = False
        if self.gps_logger:
            lat, lon, alt, _ = self.gps_logger.get_current_position()
            if lat != 0 or lon != 0:
                gps_pos = (lat, lon, alt)
                gps_valid = self.gps_logger.has_fix()
                
        with self._lock:
            # Generate fingerprint
            fingerprint = self.wifi.fingerprint_from_probe(
                mac=mac,
                ssid=ssid,
                supported_rates=supported_rates or [],
                ht_capabilities=ht_capabilities,
                vht_capabilities=vht_capabilities,
                vendor_ies=vendor_ies,
                timestamp=timestamp,
            )
            
            self._stats["wifi_fingerprints"] += 1
            
            # Check for randomized MAC
            if self.wifi.is_likely_randomized_mac(mac):
                self._stats["randomized_macs_detected"] += 1
                
            # Get signature data
            sig_data = self.wifi.get_signature_data(mac)
            
            # Store to database
            if self.auto_store and self.database and sig_data:
                self._store_wifi_device(
                    mac=mac,
                    ssid=ssid,
                    rssi=rssi,
                    channel=channel,
                    fingerprint=fingerprint,
                    sig_data=sig_data,
                    gps_pos=gps_pos,
                    gps_valid=gps_valid,
                    timestamp=timestamp,
                )
                
            # Notify callbacks
            for callback in self._callbacks:
                try:
                    callback("wifi", fingerprint, sig_data or {})
                except Exception as e:
                    logger.error(f"Callback error: {e}")
                    
        return fingerprint
        
    def process_bluetooth_device(
        self,
        mac: str,
        name: Optional[str] = None,
        rssi: int = -100,
        device_class: int = 0,
        service_uuids: List[str] = None,
        is_ble: bool = False,
        is_classic: bool = True,
        manufacturer_id: Optional[int] = None,
        manufacturer_data: bytes = None,
        timestamp: Optional[datetime] = None,
    ) -> str:
        """
        Process Bluetooth device for fingerprinting.
        
        Args:
            mac: Device MAC address
            name: Device name
            rssi: Signal strength
            device_class: BT device class
            service_uuids: Service UUIDs
            is_ble: Is BLE device
            is_classic: Is Classic BT device
            manufacturer_id: Manufacturer ID
            manufacturer_data: Raw manufacturer data
            timestamp: Detection timestamp
            
        Returns:
            Fingerprint hash
        """
        timestamp = timestamp or datetime.utcnow()
        
        # Get GPS position
        gps_pos = None
        gps_valid = False
        if self.gps_logger:
            lat, lon, alt, _ = self.gps_logger.get_current_position()
            if lat != 0 or lon != 0:
                gps_pos = (lat, lon, alt)
                gps_valid = self.gps_logger.has_fix()
                
        with self._lock:
            # Generate fingerprint
            fingerprint = self.bluetooth.fingerprint_device(
                mac=mac,
                name=name,
                rssi=rssi,
                device_class=device_class,
                service_uuids=service_uuids,
                is_ble=is_ble,
                is_classic=is_classic,
                manufacturer_id=manufacturer_id,
                manufacturer_data=manufacturer_data,
                timestamp=timestamp,
            )
            
            self._stats["bt_fingerprints"] += 1
            
            # Get signature data
            sig_data = self.bluetooth.get_signature_data(mac)
            
            # Determine BT type
            if is_ble and is_classic:
                bt_type = "dual"
            elif is_ble:
                bt_type = "ble"
            else:
                bt_type = "classic"
                
            # Store to database
            if self.auto_store and self.database and sig_data:
                self._store_bt_device(
                    mac=mac,
                    name=name,
                    rssi=rssi,
                    bt_type=bt_type,
                    device_class=device_class,
                    fingerprint=fingerprint,
                    sig_data=sig_data,
                    gps_pos=gps_pos,
                    gps_valid=gps_valid,
                    timestamp=timestamp,
                )
                
            # Notify callbacks
            for callback in self._callbacks:
                try:
                    callback("bluetooth", fingerprint, sig_data or {})
                except Exception as e:
                    logger.error(f"Callback error: {e}")
                    
        return fingerprint
        
    def _store_wifi_device(
        self,
        mac: str,
        ssid: str,
        rssi: int,
        channel: int,
        fingerprint: str,
        sig_data: dict,
        gps_pos: Optional[tuple],
        gps_valid: bool,
        timestamp: datetime,
    ):
        """Store WiFi device to database."""
        try:
            from core.models import WiFiDevice
            
            device = WiFiDevice(
                mac=mac.upper(),
                ssid=ssid,
                rssi=rssi,
                channel=channel,
                first_seen=timestamp,
                last_seen=timestamp,
                latitude=gps_pos[0] if gps_pos else None,
                longitude=gps_pos[1] if gps_pos else None,
                altitude=gps_pos[2] if gps_pos else None,
                gps_valid=gps_valid,
                packets=1,
                manufacturer=sig_data.get("capabilities", {}).get("manufacturer", ""),
                fingerprint_hash=fingerprint,
                is_client=bool(ssid),  # Has probed SSID = client
            )
            
            self.database.insert_wifi_device(device)
            
        except Exception as e:
            logger.error(f"Failed to store WiFi device: {e}")
            
    def _store_bt_device(
        self,
        mac: str,
        name: Optional[str],
        rssi: int,
        bt_type: str,
        device_class: int,
        fingerprint: str,
        sig_data: dict,
        gps_pos: Optional[tuple],
        gps_valid: bool,
        timestamp: datetime,
    ):
        """Store Bluetooth device to database."""
        try:
            from core.models import BTDevice, BTDeviceType
            
            # Map bt_type string to enum
            type_map = {
                "classic": BTDeviceType.CLASSIC,
                "ble": BTDeviceType.BLE,
                "dual": BTDeviceType.DUAL,
            }
            
            device = BTDevice(
                mac=mac.upper(),
                name=name or "",
                rssi=rssi,
                bt_type=type_map.get(bt_type, BTDeviceType.CLASSIC),
                device_class=device_class,
                first_seen=timestamp,
                last_seen=timestamp,
                latitude=gps_pos[0] if gps_pos else None,
                longitude=gps_pos[1] if gps_pos else None,
                altitude=gps_pos[2] if gps_pos else None,
                gps_valid=gps_valid,
                manufacturer=sig_data.get("capabilities", {}).get("manufacturer_id", ""),
                fingerprint_hash=fingerprint,
            )
            
            self.database.insert_bt_device(device)
            
        except Exception as e:
            logger.error(f"Failed to store BT device: {e}")
            
    def get_wifi_fingerprint(self, mac: str) -> Optional[str]:
        """Get WiFi fingerprint for MAC."""
        return self.wifi.get_fingerprint(mac)
        
    def get_bt_fingerprint(self, mac: str) -> Optional[str]:
        """Get Bluetooth fingerprint for MAC."""
        return self.bluetooth.get_fingerprint(mac)
        
    def get_wifi_signature(self, mac: str) -> Optional[dict]:
        """Get WiFi signature data for MAC."""
        return self.wifi.get_signature_data(mac)
        
    def get_bt_signature(self, mac: str) -> Optional[dict]:
        """Get Bluetooth signature data for MAC."""
        return self.bluetooth.get_signature_data(mac)
        
    def correlate_randomized_macs(self) -> Dict[str, List[str]]:
        """
        Find potentially related randomized MACs.
        
        Returns:
            Dictionary mapping fingerprint -> [MAC list]
        """
        # Get all WiFi fingerprints
        all_fps: Dict[str, str] = {}
        
        # This would need access to internal cache
        # For now, return empty - would be populated from database query
        
        return self.wifi.correlate_randomized_macs(all_fps)
        
    def get_stats(self) -> dict:
        """Get fingerprinting statistics."""
        with self._lock:
            return {
                **self._stats,
                "wifi_cache_size": len(self.wifi._fingerprint_cache),
                "bt_cache_size": len(self.bluetooth._fingerprint_cache),
            }
            
    def register_callback(
        self,
        callback: Callable[[str, str, dict], None],
    ):
        """
        Register callback for new fingerprints.
        
        Callback receives: (device_type, fingerprint_hash, signature_data)
        """
        self._callbacks.append(callback)
        
    def clear_cache(self):
        """Clear fingerprint caches."""
        with self._lock:
            self.wifi.clear_cache()
            self.bluetooth.clear_cache()
            
    def process_kismet_device(self, device) -> Optional[str]:
        """
        Process device from Kismet controller.
        
        Args:
            device: KismetDevice object
            
        Returns:
            Fingerprint hash or None
        """
        if device.device_type == "wifi":
            return self.process_wifi_probe(
                mac=device.mac,
                ssid=device.ssid or "",
                rssi=device.rssi,
                channel=device.channel,
                timestamp=device.last_seen,
            )
        elif device.device_type == "bluetooth":
            return self.process_bluetooth_device(
                mac=device.mac,
                name=device.bt_name,
                rssi=device.rssi,
                is_ble=(device.bt_type == "ble"),
                is_classic=(device.bt_type in ["classic", "dual"]),
                timestamp=device.last_seen,
            )
        return None


class FingerprintMatcher:
    """
    Match fingerprints against known device database.
    
    Used for whitelist comparison and device identification.
    """
    
    def __init__(self, known_fingerprints: Dict[str, dict] = None):
        """
        Initialize matcher.
        
        Args:
            known_fingerprints: Dictionary of fingerprint_hash -> device_info
        """
        self._known = known_fingerprints or {}
        
    def load_from_file(self, filepath: str):
        """Load known fingerprints from JSON file."""
        import json
        from pathlib import Path
        
        path = Path(filepath)
        if path.exists():
            with open(path) as f:
                data = json.load(f)
                self._known = data.get("fingerprints", {})
                
    def add_known(self, fingerprint: str, info: dict):
        """Add known fingerprint."""
        self._known[fingerprint] = info
        
    def match(self, fingerprint: str) -> Optional[dict]:
        """
        Match fingerprint against known database.
        
        Args:
            fingerprint: Fingerprint hash to match
            
        Returns:
            Device info if matched, None otherwise
        """
        return self._known.get(fingerprint)
        
    def is_known(self, fingerprint: str) -> bool:
        """Check if fingerprint is in known database."""
        return fingerprint in self._known
        
    def match_partial(
        self,
        fingerprint: str,
        threshold: float = 0.8,
    ) -> List[tuple]:
        """
        Find partial matches based on feature similarity.
        
        Note: This is a placeholder for more sophisticated matching.
        True partial matching would require storing feature vectors.
        
        Args:
            fingerprint: Fingerprint to match
            threshold: Minimum similarity threshold
            
        Returns:
            List of (fingerprint, info, similarity_score) tuples
        """
        # For SHA256 hashes, we can only do exact matching
        # Partial matching would require different approach
        
        if fingerprint in self._known:
            return [(fingerprint, self._known[fingerprint], 1.0)]
        return []
