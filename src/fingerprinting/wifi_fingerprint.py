"""
Project Airdump - WiFi Device Fingerprinting

Fingerprint WiFi devices based on:
- Supported rates
- HT/VHT capabilities
- Information Elements
- Probe request patterns
- Vendor-specific IEs
"""

import logging
import hashlib
import json
from datetime import datetime
from typing import Optional, List, Dict, Any, Set, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class WiFiCapabilities:
    """Parsed WiFi capabilities for fingerprinting."""
    
    supported_rates: List[int] = field(default_factory=list)
    extended_rates: List[int] = field(default_factory=list)
    
    # 802.11n HT capabilities
    ht_supported: bool = False
    ht_capabilities: int = 0
    ht_ampdu_params: int = 0
    ht_mcs_set: str = ""
    
    # 802.11ac VHT capabilities
    vht_supported: bool = False
    vht_capabilities: int = 0
    vht_mcs_set: str = ""
    
    # 802.11ax HE capabilities (WiFi 6)
    he_supported: bool = False
    
    # Power management
    power_capability: Tuple[int, int] = (0, 0)  # (min, max) dBm
    
    # Vendor IEs
    vendor_ies: List[Dict[str, Any]] = field(default_factory=list)
    
    # WPS info
    wps_enabled: bool = False
    wps_manufacturer: str = ""
    wps_model: str = ""
    wps_device_name: str = ""


@dataclass
class ProbeProfile:
    """Device probe request behavior profile."""
    
    mac: str
    probed_ssids: Set[str] = field(default_factory=set)
    probe_count: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    
    # Probe timing patterns
    avg_probe_interval: float = 0.0
    probe_burst_size: int = 0
    
    # Capabilities from probes
    capabilities: Optional[WiFiCapabilities] = None
    
    def add_probe(self, ssid: str, timestamp: datetime):
        """Record a probe request."""
        if ssid:
            self.probed_ssids.add(ssid)
        self.probe_count += 1
        if self.first_seen is None:
            self.first_seen = timestamp
        self.last_seen = timestamp


class WiFiFingerprinter:
    """
    WiFi device fingerprinting engine.
    
    Creates unique device fingerprints based on 802.11 protocol features.
    Handles MAC randomization by identifying devices through behavior.
    """
    
    def __init__(self):
        """Initialize WiFi fingerprinter."""
        self._probe_profiles: Dict[str, ProbeProfile] = {}
        self._fingerprint_cache: Dict[str, str] = {}  # MAC -> fingerprint hash
        
    def extract_capabilities(
        self,
        supported_rates: List[int] = None,
        extended_rates: List[int] = None,
        ht_capabilities: Optional[str] = None,
        vht_capabilities: Optional[str] = None,
        vendor_ies: List[Dict[str, Any]] = None,
    ) -> WiFiCapabilities:
        """
        Extract capabilities from raw frame data.
        
        Args:
            supported_rates: List of supported data rates
            extended_rates: List of extended supported rates
            ht_capabilities: HT capabilities field (hex string)
            vht_capabilities: VHT capabilities field (hex string)
            vendor_ies: List of vendor-specific IEs
            
        Returns:
            WiFiCapabilities object
        """
        caps = WiFiCapabilities(
            supported_rates=supported_rates or [],
            extended_rates=extended_rates or [],
            vendor_ies=vendor_ies or [],
        )
        
        # Parse HT capabilities
        if ht_capabilities:
            caps.ht_supported = True
            try:
                caps.ht_capabilities = int(ht_capabilities, 16)
            except (ValueError, TypeError):
                pass
                
        # Parse VHT capabilities
        if vht_capabilities:
            caps.vht_supported = True
            try:
                caps.vht_capabilities = int(vht_capabilities, 16)
            except (ValueError, TypeError):
                pass
                
        # Check for WPS in vendor IEs
        for ie in caps.vendor_ies:
            oui = ie.get("oui", "")
            if oui == "00:50:f2" and ie.get("type") == "4":  # Microsoft WPS
                caps.wps_enabled = True
                # Parse WPS attributes if available
                data = ie.get("data", "")
                self._parse_wps_attributes(caps, data)
                
        return caps
        
    def _parse_wps_attributes(self, caps: WiFiCapabilities, data: str):
        """Parse WPS attributes from vendor IE data."""
        # WPS attribute parsing would go here
        # For now, just mark WPS as enabled
        pass
        
    def compute_fingerprint(
        self,
        capabilities: WiFiCapabilities,
        probe_ssids: Optional[List[str]] = None,
    ) -> str:
        """
        Compute fingerprint hash from capabilities.
        
        Args:
            capabilities: WiFiCapabilities object
            probe_ssids: Optional list of probed SSIDs
            
        Returns:
            SHA256 fingerprint hash
        """
        # Build canonical feature set
        features = {
            "rates": sorted(capabilities.supported_rates + capabilities.extended_rates),
            "ht": capabilities.ht_supported,
            "ht_caps": capabilities.ht_capabilities,
            "vht": capabilities.vht_supported,
            "vht_caps": capabilities.vht_capabilities,
            "he": capabilities.he_supported,
            "wps": capabilities.wps_enabled,
        }
        
        # Add vendor OUIs (sorted for consistency)
        vendor_ouis = sorted(set(
            ie.get("oui", "") for ie in capabilities.vendor_ies
            if ie.get("oui")
        ))
        features["vendor_ouis"] = vendor_ouis
        
        # Optionally include probed SSIDs
        if probe_ssids:
            # Sort and filter empty
            features["probe_ssids"] = sorted(set(s for s in probe_ssids if s))
            
        # Compute hash
        canonical = json.dumps(features, sort_keys=True)
        return hashlib.sha256(canonical.encode()).hexdigest()
        
    def fingerprint_from_probe(
        self,
        mac: str,
        ssid: str,
        supported_rates: List[int],
        ht_capabilities: Optional[str] = None,
        vht_capabilities: Optional[str] = None,
        vendor_ies: List[Dict[str, Any]] = None,
        timestamp: Optional[datetime] = None,
    ) -> str:
        """
        Create/update fingerprint from probe request.
        
        Args:
            mac: Source MAC address
            ssid: Probed SSID
            supported_rates: Supported rates from probe
            ht_capabilities: HT capabilities
            vht_capabilities: VHT capabilities
            vendor_ies: Vendor-specific IEs
            timestamp: Probe timestamp
            
        Returns:
            Fingerprint hash
        """
        timestamp = timestamp or datetime.utcnow()
        mac = mac.upper()
        
        # Get or create probe profile
        if mac not in self._probe_profiles:
            self._probe_profiles[mac] = ProbeProfile(mac=mac)
            
        profile = self._probe_profiles[mac]
        profile.add_probe(ssid, timestamp)
        
        # Extract capabilities
        caps = self.extract_capabilities(
            supported_rates=supported_rates,
            ht_capabilities=ht_capabilities,
            vht_capabilities=vht_capabilities,
            vendor_ies=vendor_ies,
        )
        profile.capabilities = caps
        
        # Compute fingerprint
        fingerprint = self.compute_fingerprint(caps, list(profile.probed_ssids))
        self._fingerprint_cache[mac] = fingerprint
        
        return fingerprint
        
    def get_fingerprint(self, mac: str) -> Optional[str]:
        """Get cached fingerprint for MAC."""
        return self._fingerprint_cache.get(mac.upper())
        
    def get_probe_profile(self, mac: str) -> Optional[ProbeProfile]:
        """Get probe profile for MAC."""
        return self._probe_profiles.get(mac.upper())
        
    def identify_device_type(self, capabilities: WiFiCapabilities) -> str:
        """
        Attempt to identify device type from capabilities.
        
        Args:
            capabilities: WiFiCapabilities object
            
        Returns:
            Device type string (e.g., "smartphone", "laptop", "iot")
        """
        # Heuristics for device type identification
        
        # Modern smartphones typically have HT, VHT, and specific rate sets
        if capabilities.vht_supported and capabilities.ht_supported:
            if len(capabilities.supported_rates) >= 8:
                return "smartphone"
                
        # Laptops often have extensive capabilities
        if capabilities.vht_supported and len(capabilities.vendor_ies) > 3:
            return "laptop"
            
        # IoT devices often have limited capabilities
        if not capabilities.ht_supported and len(capabilities.supported_rates) <= 4:
            return "iot"
            
        # Legacy 802.11g device
        if not capabilities.ht_supported and 54 in capabilities.supported_rates:
            return "legacy_wifi_g"
            
        # Legacy 802.11b device
        if not capabilities.ht_supported and max(capabilities.supported_rates or [0]) <= 11:
            return "legacy_wifi_b"
            
        return "unknown"
        
    def is_likely_randomized_mac(self, mac: str) -> bool:
        """
        Check if MAC address appears to be randomized.
        
        Args:
            mac: MAC address
            
        Returns:
            True if MAC appears randomized
        """
        mac = mac.upper().replace(":", "").replace("-", "")
        
        if len(mac) != 12:
            return False
            
        # Check locally administered bit (second hex digit)
        # Randomized MACs have the local bit set (0x02)
        try:
            second_nibble = int(mac[1], 16)
            return (second_nibble & 0x02) != 0
        except ValueError:
            return False
            
    def correlate_randomized_macs(
        self,
        fingerprints: Dict[str, str],
    ) -> Dict[str, List[str]]:
        """
        Group potentially randomized MACs by fingerprint.
        
        Devices using MAC randomization may share fingerprints.
        
        Args:
            fingerprints: Dictionary of MAC -> fingerprint hash
            
        Returns:
            Dictionary of fingerprint -> [MAC list]
        """
        groups: Dict[str, List[str]] = {}
        
        for mac, fp in fingerprints.items():
            if self.is_likely_randomized_mac(mac):
                if fp not in groups:
                    groups[fp] = []
                groups[fp].append(mac)
                
        return groups
        
    def get_signature_data(
        self,
        mac: str,
        include_probes: bool = True,
    ) -> Optional[dict]:
        """
        Get complete signature data for database storage.
        
        Args:
            mac: MAC address
            include_probes: Include probed SSIDs
            
        Returns:
            Dictionary with signature data
        """
        profile = self._probe_profiles.get(mac.upper())
        if not profile:
            return None
            
        fingerprint = self._fingerprint_cache.get(mac.upper())
        if not fingerprint:
            return None
            
        data = {
            "mac": mac.upper(),
            "fingerprint_hash": fingerprint,
            "device_type": "wifi",
            "first_seen": profile.first_seen.isoformat() if profile.first_seen else None,
            "last_seen": profile.last_seen.isoformat() if profile.last_seen else None,
        }
        
        if profile.capabilities:
            caps = profile.capabilities
            data["capabilities"] = {
                "supported_rates": caps.supported_rates,
                "extended_rates": caps.extended_rates,
                "ht_supported": caps.ht_supported,
                "ht_capabilities": caps.ht_capabilities,
                "vht_supported": caps.vht_supported,
                "vht_capabilities": caps.vht_capabilities,
                "wps_enabled": caps.wps_enabled,
                "vendor_oui_count": len(caps.vendor_ies),
            }
            
            # Identify device type
            data["inferred_device_type"] = self.identify_device_type(caps)
            
        if include_probes and profile.probed_ssids:
            data["probed_ssids"] = list(profile.probed_ssids)
            
        data["is_randomized_mac"] = self.is_likely_randomized_mac(mac)
        
        return data
        
    def clear_cache(self):
        """Clear all cached fingerprints and profiles."""
        self._probe_profiles.clear()
        self._fingerprint_cache.clear()
