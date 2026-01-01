"""
Project Airdump - Analyzer

Post-flight analysis including:
- Whitelist comparison
- Anomaly detection
- Device correlation
- Coverage analysis
"""

import logging
import json
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Set
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class AnalysisResult:
    """Results from scan analysis."""
    
    session_id: str
    analysis_time: datetime
    
    # Device counts
    total_wifi_devices: int = 0
    total_bt_devices: int = 0
    
    # Whitelist results
    known_devices: int = 0
    unknown_devices: int = 0
    suspicious_devices: int = 0
    
    # Device lists
    unknown_wifi: List[dict] = field(default_factory=list)
    unknown_bt: List[dict] = field(default_factory=list)
    suspicious: List[dict] = field(default_factory=list)
    
    # Coverage info
    coverage_area_sqm: float = 0.0
    gps_track_points: int = 0
    
    # Alerts
    alerts: List[dict] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "session_id": self.session_id,
            "analysis_time": self.analysis_time.isoformat(),
            "summary": {
                "total_wifi_devices": self.total_wifi_devices,
                "total_bt_devices": self.total_bt_devices,
                "known_devices": self.known_devices,
                "unknown_devices": self.unknown_devices,
                "suspicious_devices": self.suspicious_devices,
            },
            "coverage": {
                "area_sqm": self.coverage_area_sqm,
                "gps_track_points": self.gps_track_points,
            },
            "unknown_wifi": self.unknown_wifi,
            "unknown_bt": self.unknown_bt,
            "suspicious": self.suspicious,
            "alerts": self.alerts,
        }


@dataclass
class WhitelistEntry:
    """Entry in device whitelist."""
    
    identifier: str  # MAC, OUI prefix, or fingerprint hash
    match_type: str  # "mac", "oui", "fingerprint", "ssid"
    name: str = ""
    category: str = ""
    notes: str = ""
    
    def matches(self, device: dict) -> bool:
        """Check if device matches this whitelist entry."""
        if self.match_type == "mac":
            device_mac = device.get("mac", "").upper()
            return device_mac == self.identifier.upper()
            
        elif self.match_type == "oui":
            device_mac = device.get("mac", "").upper().replace(":", "")
            oui = self.identifier.upper().replace(":", "")
            return device_mac.startswith(oui)
            
        elif self.match_type == "fingerprint":
            return device.get("fingerprint_hash", "") == self.identifier
            
        elif self.match_type == "ssid":
            return device.get("ssid", "") == self.identifier
            
        return False


class WhitelistComparer:
    """
    Compare scan results against device whitelist.
    
    Supports:
    - MAC address matching
    - OUI prefix matching
    - Fingerprint matching
    - SSID matching
    """
    
    def __init__(self, whitelist_file: Optional[str] = None):
        """
        Initialize whitelist comparer.
        
        Args:
            whitelist_file: Path to whitelist JSON file
        """
        self._entries: List[WhitelistEntry] = []
        self._mac_set: Set[str] = set()
        self._oui_set: Set[str] = set()
        self._fingerprint_set: Set[str] = set()
        self._ssid_set: Set[str] = set()
        
        if whitelist_file:
            self.load_whitelist(whitelist_file)
            
    def load_whitelist(self, filepath: str):
        """
        Load whitelist from JSON file.
        
        Expected format:
        {
            "wifi_devices": [{"mac": "...", "name": "...", "category": "..."}],
            "bluetooth_devices": [...],
            "oui_whitelist": ["AA:BB:CC", ...],
            "fingerprint_whitelist": ["hash1", ...],
            "ssid_whitelist": ["SSID1", ...]
        }
        """
        path = Path(filepath)
        if not path.exists():
            logger.warning(f"Whitelist file not found: {filepath}")
            return
            
        try:
            with open(path) as f:
                data = json.load(f)
                
            # Load WiFi devices
            for device in data.get("wifi_devices", []):
                mac = device.get("mac", "").upper()
                if mac:
                    self._entries.append(WhitelistEntry(
                        identifier=mac,
                        match_type="mac",
                        name=device.get("name", ""),
                        category=device.get("category", ""),
                        notes=device.get("notes", ""),
                    ))
                    self._mac_set.add(mac)
                    
            # Load Bluetooth devices
            for device in data.get("bluetooth_devices", []):
                mac = device.get("mac", "").upper()
                if mac:
                    self._entries.append(WhitelistEntry(
                        identifier=mac,
                        match_type="mac",
                        name=device.get("name", ""),
                        category=device.get("category", "bluetooth"),
                        notes=device.get("notes", ""),
                    ))
                    self._mac_set.add(mac)
                    
            # Load OUI prefixes
            for oui in data.get("oui_whitelist", []):
                oui_clean = oui.upper().replace(":", "").replace("-", "")[:6]
                self._entries.append(WhitelistEntry(
                    identifier=oui_clean,
                    match_type="oui",
                    category="oui",
                ))
                self._oui_set.add(oui_clean)
                
            # Load fingerprints
            for fp in data.get("fingerprint_whitelist", []):
                self._entries.append(WhitelistEntry(
                    identifier=fp,
                    match_type="fingerprint",
                    category="fingerprint",
                ))
                self._fingerprint_set.add(fp)
                
            # Load SSIDs
            for ssid in data.get("ssid_whitelist", []):
                self._entries.append(WhitelistEntry(
                    identifier=ssid,
                    match_type="ssid",
                    category="ssid",
                ))
                self._ssid_set.add(ssid)
                
            logger.info(f"Loaded whitelist: {len(self._entries)} entries")
            
        except Exception as e:
            logger.error(f"Failed to load whitelist: {e}")
            
    def is_whitelisted(self, device: dict) -> bool:
        """
        Check if device is whitelisted.
        
        Args:
            device: Device dictionary with mac/bssid, ssid, fingerprint_hash
            
        Returns:
            True if device is whitelisted
        """
        # Get MAC from 'mac' or 'bssid' key (WiFi devices use bssid)
        mac = device.get("mac", device.get("bssid", "")).upper()
        
        # Check exact MAC match
        if mac in self._mac_set:
            return True
            
        # Check OUI prefix match
        mac_clean = mac.replace(":", "").replace("-", "")
        if mac_clean[:6] in self._oui_set:
            return True
            
        # Check fingerprint match
        fingerprint = device.get("fingerprint_hash", "")
        if fingerprint and fingerprint in self._fingerprint_set:
            return True
            
        # Check SSID match (check both 'ssid' and 'essid')
        ssid = device.get("ssid", device.get("essid", ""))
        if ssid and ssid in self._ssid_set:
            return True
            
        return False
        
    def get_whitelist_match(self, device: dict) -> Optional[WhitelistEntry]:
        """
        Get the whitelist entry that matches device.
        
        Args:
            device: Device dictionary
            
        Returns:
            Matching WhitelistEntry or None
        """
        for entry in self._entries:
            if entry.matches(device):
                return entry
        return None
        
    def add_device(
        self,
        mac: str,
        name: str = "",
        category: str = "",
        notes: str = "",
    ):
        """Add device to whitelist."""
        mac = mac.upper()
        entry = WhitelistEntry(
            identifier=mac,
            match_type="mac",
            name=name,
            category=category,
            notes=notes,
        )
        self._entries.append(entry)
        self._mac_set.add(mac)
        
    def save_whitelist(self, filepath: str):
        """Save whitelist to JSON file."""
        data = {
            "wifi_devices": [],
            "bluetooth_devices": [],
            "oui_whitelist": list(self._oui_set),
            "fingerprint_whitelist": list(self._fingerprint_set),
            "ssid_whitelist": list(self._ssid_set),
        }
        
        for entry in self._entries:
            if entry.match_type == "mac":
                device = {
                    "mac": entry.identifier,
                    "name": entry.name,
                    "category": entry.category,
                    "notes": entry.notes,
                }
                if entry.category == "bluetooth":
                    data["bluetooth_devices"].append(device)
                else:
                    data["wifi_devices"].append(device)
                    
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)


class Analyzer:
    """
    Scan data analyzer.
    
    Performs post-flight analysis including:
    - Unknown device detection
    - Suspicious activity identification
    - Coverage calculation
    - Temporal analysis
    """
    
    def __init__(
        self,
        database=None,
        whitelist_file: Optional[str] = None,
    ):
        """
        Initialize analyzer.
        
        Args:
            database: Database instance
            whitelist_file: Path to whitelist file
        """
        self.database = database
        self.whitelist = WhitelistComparer(whitelist_file) if whitelist_file else WhitelistComparer()
        
    def analyze_session(self, session_id: str) -> AnalysisResult:
        """
        Perform full analysis on scan session.
        
        Args:
            session_id: Scan session ID
            
        Returns:
            AnalysisResult object
        """
        result = AnalysisResult(
            session_id=session_id,
            analysis_time=datetime.utcnow(),
        )
        
        if not self.database:
            logger.error("No database connection")
            return result
            
        # Get session data
        session = self.database.get_session(session_id)
        if not session:
            logger.error(f"Session not found: {session_id}")
            return result
            
        # Get WiFi devices
        wifi_devices = self.database.get_wifi_devices(session_id)
        result.total_wifi_devices = len(wifi_devices)
        
        # Get Bluetooth devices
        bt_devices = self.database.get_bt_devices(session_id)
        result.total_bt_devices = len(bt_devices)
        
        # Analyze WiFi devices
        for device in wifi_devices:
            device_dict = device.to_dict() if hasattr(device, 'to_dict') else device
            
            if self.whitelist.is_whitelisted(device_dict):
                result.known_devices += 1
            else:
                result.unknown_devices += 1
                result.unknown_wifi.append(device_dict)
                
                # Check for suspicious indicators
                suspicious = self._check_suspicious_wifi(device_dict)
                if suspicious:
                    result.suspicious_devices += 1
                    result.suspicious.append({
                        **device_dict,
                        "suspicious_reason": suspicious,
                    })
                    result.alerts.append({
                        "type": "suspicious_wifi",
                        "mac": device_dict.get("mac"),
                        "reason": suspicious,
                        "timestamp": datetime.utcnow().isoformat(),
                    })
                    
        # Analyze Bluetooth devices
        for device in bt_devices:
            device_dict = device.to_dict() if hasattr(device, 'to_dict') else device
            
            if self.whitelist.is_whitelisted(device_dict):
                result.known_devices += 1
            else:
                result.unknown_devices += 1
                result.unknown_bt.append(device_dict)
                
                # Check for suspicious indicators
                suspicious = self._check_suspicious_bt(device_dict)
                if suspicious:
                    result.suspicious_devices += 1
                    result.suspicious.append({
                        **device_dict,
                        "suspicious_reason": suspicious,
                    })
                    result.alerts.append({
                        "type": "suspicious_bluetooth",
                        "mac": device_dict.get("mac"),
                        "reason": suspicious,
                        "timestamp": datetime.utcnow().isoformat(),
                    })
                    
        # Get GPS track for coverage analysis
        gps_track = self.database.get_gps_track(session_id)
        result.gps_track_points = len(gps_track) if gps_track else 0
        
        if gps_track:
            result.coverage_area_sqm = self._calculate_coverage_area(gps_track)
            
        return result
        
    def _check_suspicious_wifi(self, device: dict) -> Optional[str]:
        """
        Check for suspicious WiFi device indicators.
        
        Args:
            device: Device dictionary
            
        Returns:
            Reason string if suspicious, None otherwise
        """
        reasons = []
        
        mac = device.get("mac", "").upper()
        ssid = device.get("ssid", "")
        
        # Check for randomized MAC that's probing
        if self._is_randomized_mac(mac) and ssid:
            # Randomized MACs actively probing might be recon
            pass  # This is common, don't flag
            
        # Check for known probe attack SSIDs
        attack_ssids = ["FreeWiFi", "Free WiFi", "xfinitywifi", "attwifi"]
        if ssid in attack_ssids:
            reasons.append(f"Probing for commonly-spoofed SSID: {ssid}")
            
        # Check for enterprise network probing
        if device.get("probed_ssids"):
            probed = device["probed_ssids"]
            # Many corporate SSIDs being probed from single device
            if len(probed) > 10:
                reasons.append(f"Probing many SSIDs ({len(probed)})")
                
        # Very high signal strength (device very close or spoofed)
        rssi = device.get("rssi", -100)
        if rssi > -20:
            reasons.append(f"Unusually strong signal ({rssi} dBm)")
            
        return "; ".join(reasons) if reasons else None
        
    def _check_suspicious_bt(self, device: dict) -> Optional[str]:
        """
        Check for suspicious Bluetooth device indicators.
        
        Args:
            device: Device dictionary
            
        Returns:
            Reason string if suspicious, None otherwise
        """
        reasons = []
        
        name = device.get("name", "")
        device_class = device.get("device_class", 0)
        
        # Check for tracking device patterns
        tracking_names = ["tile", "airtag", "smarttag", "chipolo"]
        name_lower = name.lower()
        for pattern in tracking_names:
            if pattern in name_lower:
                reasons.append(f"Potential tracking device: {name}")
                break
                
        # Unknown BLE device with no name (potential tracker)
        bt_type = device.get("bt_type", "")
        if bt_type == "ble" and not name:
            reasons.append("Unnamed BLE device (potential tracker)")
            
        # Very high signal strength
        rssi = device.get("rssi", -100)
        if rssi > -30:
            reasons.append(f"Very close proximity ({rssi} dBm)")
            
        return "; ".join(reasons) if reasons else None
        
    def _is_randomized_mac(self, mac: str) -> bool:
        """Check if MAC appears randomized."""
        mac_clean = mac.upper().replace(":", "").replace("-", "")
        if len(mac_clean) != 12:
            return False
        try:
            second_nibble = int(mac_clean[1], 16)
            return (second_nibble & 0x02) != 0
        except ValueError:
            return False
            
    def _calculate_coverage_area(self, gps_track: list) -> float:
        """
        Calculate approximate coverage area from GPS track.
        
        Uses convex hull approximation.
        
        Args:
            gps_track: List of GPS positions
            
        Returns:
            Approximate area in square meters
        """
        if len(gps_track) < 3:
            return 0.0
            
        # Extract lat/lon points
        points = []
        for pos in gps_track:
            if hasattr(pos, 'latitude'):
                points.append((pos.latitude, pos.longitude))
            elif isinstance(pos, dict):
                points.append((pos.get('latitude', 0), pos.get('longitude', 0)))
                
        if len(points) < 3:
            return 0.0
            
        # Simple bounding box approximation
        lats = [p[0] for p in points if p[0] != 0]
        lons = [p[1] for p in points if p[1] != 0]
        
        if not lats or not lons:
            return 0.0
            
        lat_range = max(lats) - min(lats)
        lon_range = max(lons) - min(lons)
        
        # Convert to meters (approximate)
        # 1 degree latitude ≈ 111,320 meters
        # 1 degree longitude ≈ 111,320 * cos(latitude) meters
        import math
        avg_lat = sum(lats) / len(lats)
        lat_meters = lat_range * 111320
        lon_meters = lon_range * 111320 * math.cos(math.radians(avg_lat))
        
        return lat_meters * lon_meters
        
    def find_devices_near_location(
        self,
        latitude: float,
        longitude: float,
        radius_m: float = 50.0,
        session_id: Optional[str] = None,
    ) -> Dict[str, list]:
        """
        Find devices detected near a specific location.
        
        Args:
            latitude: Center latitude
            longitude: Center longitude
            radius_m: Search radius in meters
            session_id: Optional session to search
            
        Returns:
            Dictionary with 'wifi' and 'bluetooth' device lists
        """
        if not self.database:
            return {"wifi": [], "bluetooth": []}
            
        wifi = self.database.get_wifi_devices_near(
            latitude, longitude, radius_m, session_id
        )
        bt = self.database.get_bt_devices_near(
            latitude, longitude, radius_m, session_id
        )
        
        return {
            "wifi": [d.to_dict() if hasattr(d, 'to_dict') else d for d in wifi],
            "bluetooth": [d.to_dict() if hasattr(d, 'to_dict') else d for d in bt],
        }
        
    def find_device_appearances(
        self,
        mac: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> List[dict]:
        """
        Find all appearances of a device across sessions.
        
        Args:
            mac: Device MAC address
            start_time: Start of time range
            end_time: End of time range
            
        Returns:
            List of appearance records with timestamps and locations
        """
        # This would query the database for all detections of this MAC
        # across multiple sessions
        appearances = []
        
        if self.database:
            # Get from WiFi
            wifi = self.database.get_wifi_device_by_mac(mac)
            if wifi:
                appearances.append({
                    "type": "wifi",
                    "mac": mac,
                    "first_seen": wifi.first_seen.isoformat() if wifi.first_seen else None,
                    "last_seen": wifi.last_seen.isoformat() if wifi.last_seen else None,
                    "latitude": wifi.latitude,
                    "longitude": wifi.longitude,
                    "ssid": wifi.ssid,
                })
                
            # Get from Bluetooth
            bt = self.database.get_bt_device_by_mac(mac)
            if bt:
                appearances.append({
                    "type": "bluetooth",
                    "mac": mac,
                    "first_seen": bt.first_seen.isoformat() if bt.first_seen else None,
                    "last_seen": bt.last_seen.isoformat() if bt.last_seen else None,
                    "latitude": bt.latitude,
                    "longitude": bt.longitude,
                    "name": bt.name,
                })
                
        return appearances
        
    def get_device_timeline(
        self,
        session_id: str,
        bucket_minutes: int = 5,
    ) -> Dict[str, List[int]]:
        """
        Get device detection timeline bucketed by time.
        
        Args:
            session_id: Scan session ID
            bucket_minutes: Time bucket size
            
        Returns:
            Dictionary with time buckets and device counts
        """
        timeline = {"timestamps": [], "wifi_counts": [], "bt_counts": []}
        
        if not self.database:
            return timeline
            
        session = self.database.get_session(session_id)
        if not session:
            return timeline
            
        # Get session time range
        start = session.start_time
        end = session.end_time or datetime.utcnow()
        
        # Get all devices
        wifi_devices = self.database.get_wifi_devices(session_id)
        bt_devices = self.database.get_bt_devices(session_id)
        
        # Create time buckets
        current = start
        while current < end:
            bucket_end = current + timedelta(minutes=bucket_minutes)
            
            # Count devices in this bucket
            wifi_count = sum(
                1 for d in wifi_devices
                if d.first_seen and current <= d.first_seen < bucket_end
            )
            bt_count = sum(
                1 for d in bt_devices
                if d.first_seen and current <= d.first_seen < bucket_end
            )
            
            timeline["timestamps"].append(current.isoformat())
            timeline["wifi_counts"].append(wifi_count)
            timeline["bt_counts"].append(bt_count)
            
            current = bucket_end
            
        return timeline
