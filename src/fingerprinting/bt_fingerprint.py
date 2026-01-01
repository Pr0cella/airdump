"""
Project Airdump - Bluetooth Device Fingerprinting

Fingerprint Bluetooth devices based on:
- Device class
- Service UUIDs
- Manufacturer data
- Device name patterns
- BLE advertisement data
"""

import logging
import hashlib
import json
from datetime import datetime
from typing import Optional, List, Dict, Any, Set
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# Standard Bluetooth device classes
BT_DEVICE_CLASSES = {
    0x000100: "Computer - Uncategorized",
    0x000104: "Computer - Desktop",
    0x000108: "Computer - Server",
    0x00010C: "Computer - Laptop",
    0x000110: "Computer - Handheld",
    0x000114: "Computer - Palm",
    0x000118: "Computer - Wearable",
    0x000200: "Phone - Uncategorized",
    0x000204: "Phone - Cellular",
    0x000208: "Phone - Cordless",
    0x00020C: "Phone - Smartphone",
    0x000210: "Phone - Wired Modem",
    0x000300: "LAN/Network Access",
    0x000400: "Audio/Video - Uncategorized",
    0x000404: "Audio/Video - Headset",
    0x000408: "Audio/Video - Hands-free",
    0x00040C: "Audio/Video - Microphone",
    0x000414: "Audio/Video - Loudspeaker",
    0x000418: "Audio/Video - Headphones",
    0x00041C: "Audio/Video - Portable Audio",
    0x000420: "Audio/Video - Car Audio",
    0x000424: "Audio/Video - Set-top Box",
    0x000428: "Audio/Video - HiFi Audio",
    0x00042C: "Audio/Video - VCR",
    0x000430: "Audio/Video - Video Camera",
    0x000434: "Audio/Video - Camcorder",
    0x000438: "Audio/Video - Video Monitor",
    0x00043C: "Audio/Video - Video Display/Speaker",
    0x000500: "Peripheral - Uncategorized",
    0x000540: "Peripheral - Keyboard",
    0x000580: "Peripheral - Mouse",
    0x0005C0: "Peripheral - Combo Keyboard/Mouse",
    0x000600: "Imaging - Uncategorized",
    0x000604: "Imaging - Display",
    0x000608: "Imaging - Camera",
    0x000610: "Imaging - Scanner",
    0x000620: "Imaging - Printer",
    0x000700: "Wearable - Uncategorized",
    0x000704: "Wearable - Watch",
    0x000708: "Wearable - Pager",
    0x00070C: "Wearable - Jacket",
    0x000710: "Wearable - Helmet",
    0x000714: "Wearable - Glasses",
    0x000800: "Toy - Uncategorized",
    0x000804: "Toy - Robot",
    0x000808: "Toy - Vehicle",
    0x00080C: "Toy - Doll",
    0x000810: "Toy - Controller",
    0x000814: "Toy - Game",
    0x000900: "Health - Uncategorized",
    0x000904: "Health - Blood Pressure Monitor",
    0x000908: "Health - Thermometer",
    0x00090C: "Health - Weighing Scale",
    0x000910: "Health - Glucose Meter",
    0x000914: "Health - Pulse Oximeter",
    0x000918: "Health - Heart Rate Monitor",
    0x00091C: "Health - Data Display",
}

# Common BLE service UUIDs
BLE_SERVICE_UUIDS = {
    "1800": "Generic Access",
    "1801": "Generic Attribute",
    "1802": "Immediate Alert",
    "1803": "Link Loss",
    "1804": "Tx Power",
    "1805": "Current Time",
    "1806": "Reference Time Update",
    "1807": "Next DST Change",
    "1808": "Glucose",
    "1809": "Health Thermometer",
    "180A": "Device Information",
    "180D": "Heart Rate",
    "180E": "Phone Alert Status",
    "180F": "Battery",
    "1810": "Blood Pressure",
    "1811": "Alert Notification",
    "1812": "Human Interface Device",
    "1813": "Scan Parameters",
    "1814": "Running Speed and Cadence",
    "1815": "Automation IO",
    "1816": "Cycling Speed and Cadence",
    "1818": "Cycling Power",
    "1819": "Location and Navigation",
    "181A": "Environmental Sensing",
    "181B": "Body Composition",
    "181C": "User Data",
    "181D": "Weight Scale",
    "181E": "Bond Management",
    "181F": "Continuous Glucose Monitoring",
    "FE9F": "Google",
    "FD6F": "Apple Exposure Notification",
    "FEAA": "Google Eddystone",
}


@dataclass
class BluetoothCapabilities:
    """Parsed Bluetooth capabilities for fingerprinting."""
    
    # Device identification
    device_class: int = 0
    device_class_name: str = ""
    
    # Services
    service_uuids: Set[str] = field(default_factory=set)
    service_names: List[str] = field(default_factory=list)
    
    # BLE specific
    is_ble: bool = False
    is_classic: bool = False
    is_dual_mode: bool = False
    
    # Advertisement data
    adv_flags: int = 0
    tx_power: Optional[int] = None
    appearance: int = 0
    
    # Manufacturer data
    manufacturer_id: Optional[int] = None
    manufacturer_data: bytes = b""
    
    # Name info
    complete_local_name: str = ""
    shortened_local_name: str = ""


@dataclass
class BTDeviceProfile:
    """Bluetooth device profile for fingerprinting."""
    
    mac: str
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    
    # Names observed
    names_seen: Set[str] = field(default_factory=set)
    
    # Capabilities
    capabilities: Optional[BluetoothCapabilities] = None
    
    # Detection stats
    detection_count: int = 0
    rssi_samples: List[int] = field(default_factory=list)
    
    def add_detection(self, name: Optional[str], rssi: int, timestamp: datetime):
        """Record a detection."""
        if name:
            self.names_seen.add(name)
        self.detection_count += 1
        self.rssi_samples.append(rssi)
        if self.first_seen is None:
            self.first_seen = timestamp
        self.last_seen = timestamp
        
        # Keep only last 100 RSSI samples
        if len(self.rssi_samples) > 100:
            self.rssi_samples = self.rssi_samples[-100:]


class BluetoothFingerprinter:
    """
    Bluetooth device fingerprinting engine.
    
    Creates unique fingerprints for Classic BT and BLE devices.
    """
    
    def __init__(self):
        """Initialize Bluetooth fingerprinter."""
        self._profiles: Dict[str, BTDeviceProfile] = {}
        self._fingerprint_cache: Dict[str, str] = {}
        
    def parse_device_class(self, device_class: int) -> str:
        """
        Parse Bluetooth device class to human-readable name.
        
        Args:
            device_class: 24-bit device class value
            
        Returns:
            Device class description
        """
        # Mask to major service and device classes
        major_device = device_class & 0x001F00
        minor_device = device_class & 0x0000FC
        
        # Look up in table
        full_class = major_device | minor_device
        if full_class in BT_DEVICE_CLASSES:
            return BT_DEVICE_CLASSES[full_class]
            
        # Try just major class
        if major_device in BT_DEVICE_CLASSES:
            return BT_DEVICE_CLASSES[major_device]
            
        return "Unknown"
        
    def parse_service_uuid(self, uuid: str) -> str:
        """
        Parse BLE service UUID to name.
        
        Args:
            uuid: Service UUID (short or full)
            
        Returns:
            Service name or UUID if unknown
        """
        # Handle short UUIDs
        short_uuid = uuid.upper().replace("-", "")
        if len(short_uuid) == 4:
            return BLE_SERVICE_UUIDS.get(short_uuid, uuid)
            
        # Handle full UUIDs (extract short UUID from base)
        if len(short_uuid) == 32:
            # Standard Bluetooth Base UUID: 00000000-0000-1000-8000-00805F9B34FB
            if short_uuid.endswith("00001000800000805F9B34FB"):
                short = short_uuid[:8].lstrip("0")[-4:]
                return BLE_SERVICE_UUIDS.get(short, uuid)
                
        return uuid
        
    def extract_capabilities(
        self,
        device_class: int = 0,
        service_uuids: List[str] = None,
        is_ble: bool = False,
        is_classic: bool = False,
        manufacturer_id: Optional[int] = None,
        manufacturer_data: bytes = None,
        tx_power: Optional[int] = None,
        local_name: str = "",
    ) -> BluetoothCapabilities:
        """
        Extract capabilities from raw device data.
        
        Args:
            device_class: Bluetooth device class
            service_uuids: List of service UUIDs
            is_ble: Is BLE device
            is_classic: Is Classic Bluetooth device
            manufacturer_id: Manufacturer ID
            manufacturer_data: Raw manufacturer data
            tx_power: Transmit power level
            local_name: Device name
            
        Returns:
            BluetoothCapabilities object
        """
        caps = BluetoothCapabilities(
            device_class=device_class,
            device_class_name=self.parse_device_class(device_class),
            is_ble=is_ble,
            is_classic=is_classic,
            is_dual_mode=is_ble and is_classic,
            manufacturer_id=manufacturer_id,
            manufacturer_data=manufacturer_data or b"",
            tx_power=tx_power,
            complete_local_name=local_name,
        )
        
        # Parse service UUIDs
        if service_uuids:
            caps.service_uuids = set(service_uuids)
            caps.service_names = [
                self.parse_service_uuid(uuid) for uuid in service_uuids
            ]
            
        return caps
        
    def compute_fingerprint(
        self,
        capabilities: BluetoothCapabilities,
        include_name: bool = False,
    ) -> str:
        """
        Compute fingerprint hash from capabilities.
        
        Args:
            capabilities: BluetoothCapabilities object
            include_name: Include device name in fingerprint
            
        Returns:
            SHA256 fingerprint hash
        """
        features = {
            "device_class": capabilities.device_class,
            "service_uuids": sorted(capabilities.service_uuids),
            "is_ble": capabilities.is_ble,
            "is_classic": capabilities.is_classic,
            "manufacturer_id": capabilities.manufacturer_id,
            "tx_power": capabilities.tx_power,
        }
        
        if include_name and capabilities.complete_local_name:
            features["name"] = capabilities.complete_local_name
            
        canonical = json.dumps(features, sort_keys=True)
        return hashlib.sha256(canonical.encode()).hexdigest()
        
    def fingerprint_device(
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
        Create/update fingerprint for a Bluetooth device.
        
        Args:
            mac: Device MAC address
            name: Device name
            rssi: Signal strength
            device_class: Bluetooth device class
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
        mac = mac.upper()
        
        # Get or create profile
        if mac not in self._profiles:
            self._profiles[mac] = BTDeviceProfile(mac=mac)
            
        profile = self._profiles[mac]
        profile.add_detection(name, rssi, timestamp)
        
        # Extract capabilities
        caps = self.extract_capabilities(
            device_class=device_class,
            service_uuids=service_uuids,
            is_ble=is_ble,
            is_classic=is_classic,
            manufacturer_id=manufacturer_id,
            manufacturer_data=manufacturer_data,
            local_name=name or "",
        )
        profile.capabilities = caps
        
        # Compute fingerprint
        fingerprint = self.compute_fingerprint(caps)
        self._fingerprint_cache[mac] = fingerprint
        
        return fingerprint
        
    def get_fingerprint(self, mac: str) -> Optional[str]:
        """Get cached fingerprint for MAC."""
        return self._fingerprint_cache.get(mac.upper())
        
    def get_profile(self, mac: str) -> Optional[BTDeviceProfile]:
        """Get device profile for MAC."""
        return self._profiles.get(mac.upper())
        
    def identify_device_type(self, capabilities: BluetoothCapabilities) -> str:
        """
        Identify device type from capabilities.
        
        Args:
            capabilities: BluetoothCapabilities object
            
        Returns:
            Device type string
        """
        class_name = capabilities.device_class_name.lower()
        
        # Check device class first
        if "phone" in class_name or "smartphone" in class_name:
            return "smartphone"
        if "laptop" in class_name or "computer" in class_name:
            return "computer"
        if "headset" in class_name or "headphone" in class_name or "audio" in class_name:
            return "audio"
        if "keyboard" in class_name:
            return "keyboard"
        if "mouse" in class_name:
            return "mouse"
        if "watch" in class_name or "wearable" in class_name:
            return "wearable"
        if "health" in class_name:
            return "health_device"
        if "toy" in class_name:
            return "toy"
        if "printer" in class_name or "imaging" in class_name:
            return "imaging"
            
        # Check service UUIDs for BLE devices
        service_names = " ".join(capabilities.service_names).lower()
        
        if "heart rate" in service_names:
            return "fitness_tracker"
        if "blood pressure" in service_names or "glucose" in service_names:
            return "health_device"
        if "battery" in service_names and capabilities.is_ble:
            return "ble_accessory"
            
        # Check manufacturer
        if capabilities.manufacturer_id:
            # Apple
            if capabilities.manufacturer_id == 76:
                return "apple_device"
            # Samsung
            if capabilities.manufacturer_id == 117:
                return "samsung_device"
            # Microsoft
            if capabilities.manufacturer_id == 6:
                return "microsoft_device"
                
        if capabilities.is_ble and not capabilities.is_classic:
            return "ble_device"
        if capabilities.is_classic:
            return "classic_bt_device"
            
        return "unknown"
        
    def is_likely_trackable(self, mac: str) -> bool:
        """
        Check if device is likely trackable (non-randomized MAC).
        
        Classic Bluetooth devices typically don't randomize MACs.
        BLE devices often do.
        
        Args:
            mac: Device MAC address
            
        Returns:
            True if device appears trackable
        """
        profile = self._profiles.get(mac.upper())
        
        if not profile or not profile.capabilities:
            return True  # Assume trackable if unknown
            
        # Classic BT is usually trackable
        if profile.capabilities.is_classic and not profile.capabilities.is_ble:
            return True
            
        # Check for randomized MAC (local bit set)
        mac_clean = mac.upper().replace(":", "").replace("-", "")
        if len(mac_clean) == 12:
            try:
                second_nibble = int(mac_clean[1], 16)
                if (second_nibble & 0x02) != 0:
                    return False  # Locally administered = likely randomized
            except ValueError:
                pass
                
        return True
        
    def get_signature_data(self, mac: str) -> Optional[dict]:
        """
        Get complete signature data for database storage.
        
        Args:
            mac: Device MAC address
            
        Returns:
            Dictionary with signature data
        """
        profile = self._profiles.get(mac.upper())
        if not profile:
            return None
            
        fingerprint = self._fingerprint_cache.get(mac.upper())
        if not fingerprint:
            return None
            
        data = {
            "mac": mac.upper(),
            "fingerprint_hash": fingerprint,
            "device_type": "bluetooth",
            "first_seen": profile.first_seen.isoformat() if profile.first_seen else None,
            "last_seen": profile.last_seen.isoformat() if profile.last_seen else None,
            "names_seen": list(profile.names_seen),
            "detection_count": profile.detection_count,
        }
        
        if profile.capabilities:
            caps = profile.capabilities
            data["capabilities"] = {
                "device_class": caps.device_class,
                "device_class_name": caps.device_class_name,
                "is_ble": caps.is_ble,
                "is_classic": caps.is_classic,
                "service_uuids": list(caps.service_uuids),
                "service_names": caps.service_names,
                "manufacturer_id": caps.manufacturer_id,
                "tx_power": caps.tx_power,
            }
            
            data["inferred_device_type"] = self.identify_device_type(caps)
            
        data["is_trackable"] = self.is_likely_trackable(mac)
        
        # RSSI statistics
        if profile.rssi_samples:
            data["rssi_stats"] = {
                "min": min(profile.rssi_samples),
                "max": max(profile.rssi_samples),
                "avg": sum(profile.rssi_samples) / len(profile.rssi_samples),
                "samples": len(profile.rssi_samples),
            }
            
        return data
        
    def clear_cache(self):
        """Clear all cached fingerprints and profiles."""
        self._profiles.clear()
        self._fingerprint_cache.clear()
