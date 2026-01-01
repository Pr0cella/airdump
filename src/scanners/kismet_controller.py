"""
Project Airdump - Kismet Controller

Interface to Kismet's REST API for WiFi and Bluetooth device discovery.
"""

import logging
import time
import threading
import requests
from datetime import datetime
from typing import Optional, List, Dict, Any, Callable
from dataclasses import dataclass, field
from urllib.parse import urljoin

logger = logging.getLogger(__name__)


@dataclass
class KismetDevice:
    """Device discovered by Kismet."""
    
    mac: str
    device_type: str  # "wifi" or "bluetooth"
    first_seen: datetime
    last_seen: datetime
    channel: int = 0
    frequency: int = 0
    rssi: int = -100
    
    # WiFi specific
    ssid: Optional[str] = None
    encryption: Optional[str] = None
    manufacturer: Optional[str] = None
    probe_ssids: List[str] = field(default_factory=list)
    
    # Bluetooth specific
    bt_name: Optional[str] = None
    bt_class: Optional[int] = None
    bt_type: Optional[str] = None  # classic, ble, dual
    
    # Kismet metadata
    kismet_key: Optional[str] = None
    packets: int = 0
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "mac": self.mac,
            "device_type": self.device_type,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "channel": self.channel,
            "frequency": self.frequency,
            "rssi": self.rssi,
            "ssid": self.ssid,
            "encryption": self.encryption,
            "manufacturer": self.manufacturer,
            "probe_ssids": self.probe_ssids,
            "bt_name": self.bt_name,
            "bt_class": self.bt_class,
            "bt_type": self.bt_type,
            "kismet_key": self.kismet_key,
            "packets": self.packets,
        }


class KismetController:
    """
    Controller for Kismet wireless monitoring.
    
    Communicates with Kismet via REST API to:
    - Monitor discovered WiFi and Bluetooth devices
    - Control channel hopping
    - Manage data sources (interfaces)
    """
    
    def __init__(
        self,
        host: str = "localhost",
        port: int = 2501,
        username: str = "kismet",
        password: str = "kismet",
        poll_interval: float = 2.0,
        api_token: Optional[str] = None,
    ):
        """
        Initialize Kismet controller.
        
        Args:
            host: Kismet server host
            port: Kismet server port
            username: API username
            password: API password
            poll_interval: Seconds between device polls
            api_token: Optional API token (alternative to user/pass)
        """
        self.base_url = f"http://{host}:{port}"
        self.username = username
        self.password = password
        self.api_token = api_token
        self.poll_interval = poll_interval
        
        self._session = requests.Session()
        self._session.auth = (username, password)
        
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        
        # Device tracking
        self._devices: Dict[str, KismetDevice] = {}
        self._new_device_callbacks: List[Callable[[KismetDevice], None]] = []
        self._device_update_callbacks: List[Callable[[KismetDevice], None]] = []
        
        # Last timestamp for incremental updates
        self._last_poll_time: Optional[float] = None
        
    def _api_request(
        self,
        endpoint: str,
        method: str = "GET",
        json_data: Optional[dict] = None,
        params: Optional[dict] = None,
    ) -> Optional[Any]:
        """
        Make API request to Kismet.
        
        Args:
            endpoint: API endpoint path
            method: HTTP method
            json_data: JSON body data
            params: Query parameters
            
        Returns:
            Response JSON or None on error
        """
        url = urljoin(self.base_url, endpoint)
        
        headers = {}
        if self.api_token:
            headers["KISMET"] = self.api_token
            
        try:
            if method == "GET":
                resp = self._session.get(url, params=params, headers=headers, timeout=10)
            elif method == "POST":
                resp = self._session.post(url, json=json_data, headers=headers, timeout=10)
            else:
                logger.error(f"Unsupported HTTP method: {method}")
                return None
                
            resp.raise_for_status()
            
            # Try to parse JSON
            if resp.content:
                return resp.json()
            return {}
            
        except requests.exceptions.ConnectionError:
            logger.error(f"Cannot connect to Kismet at {self.base_url}")
        except requests.exceptions.Timeout:
            logger.error("Kismet API request timeout")
        except requests.exceptions.HTTPError as e:
            logger.error(f"Kismet API error: {e}")
        except Exception as e:
            logger.error(f"Kismet request failed: {e}")
            
        return None
        
    def check_connection(self) -> bool:
        """
        Check if Kismet is reachable.
        
        Returns:
            True if connected
        """
        result = self._api_request("/system/status.json")
        return result is not None
        
    def get_system_status(self) -> Optional[dict]:
        """
        Get Kismet system status.
        
        Returns:
            Status dictionary
        """
        return self._api_request("/system/status.json")
        
    def get_datasources(self) -> List[dict]:
        """
        Get list of configured data sources (interfaces).
        
        Returns:
            List of datasource info dictionaries
        """
        result = self._api_request("/datasource/all_sources.json")
        return result if result else []
        
    def set_channel(
        self,
        source_uuid: str,
        channel: str,
    ) -> bool:
        """
        Set specific channel on a data source.
        
        Args:
            source_uuid: Datasource UUID
            channel: Channel string (e.g., "6", "36", "6HT40+")
            
        Returns:
            True if successful
        """
        result = self._api_request(
            f"/datasource/by-uuid/{source_uuid}/set_channel.cmd",
            method="POST",
            json_data={"channel": channel},
        )
        return result is not None
        
    def set_hop_channels(
        self,
        source_uuid: str,
        channels: List[str],
        rate: float = 5.0,
    ) -> bool:
        """
        Set channel hop list on a data source.
        
        Args:
            source_uuid: Datasource UUID
            channels: List of channels to hop
            rate: Hop rate in channels per second
            
        Returns:
            True if successful
        """
        result = self._api_request(
            f"/datasource/by-uuid/{source_uuid}/set_hop.cmd",
            method="POST",
            json_data={
                "channels": channels,
                "rate": rate,
            },
        )
        return result is not None
        
    def enable_hop_mode(self, source_uuid: str) -> bool:
        """Enable channel hopping on a data source."""
        return self._api_request(
            f"/datasource/by-uuid/{source_uuid}/set_hop.cmd",
            method="POST",
            json_data={"hop": True},
        ) is not None
        
    def disable_hop_mode(self, source_uuid: str) -> bool:
        """Disable channel hopping on a data source."""
        return self._api_request(
            f"/datasource/by-uuid/{source_uuid}/set_hop.cmd",
            method="POST",
            json_data={"hop": False},
        ) is not None
        
    def get_devices(
        self,
        device_type: Optional[str] = None,
        last_time: Optional[float] = None,
    ) -> List[dict]:
        """
        Get list of discovered devices.
        
        Args:
            device_type: Filter by type ("Wi-Fi Device", "BR/EDR", "BTLE")
            last_time: Only devices active since this timestamp
            
        Returns:
            List of device dictionaries
        """
        # Build filter for device query
        fields = [
            "kismet.device.base.macaddr",
            "kismet.device.base.name",
            "kismet.device.base.type",
            "kismet.device.base.first_time",
            "kismet.device.base.last_time",
            "kismet.device.base.channel",
            "kismet.device.base.frequency",
            "kismet.device.base.signal/kismet.common.signal.last_signal",
            "kismet.device.base.manuf",
            "kismet.device.base.packets.total",
            "kismet.device.base.key",
            "dot11.device/dot11.device.last_beaconed_ssid",
            "dot11.device/dot11.device.probed_ssid_map",
            "dot11.device/dot11.device.wpa_present_handshake",
        ]
        
        json_data = {"fields": fields}
        
        if device_type:
            json_data["regex"] = [["kismet.device.base.type", device_type]]
            
        if last_time:
            json_data["last_time"] = int(last_time)
            
        result = self._api_request(
            "/devices/views/all/devices.json",
            method="POST",
            json_data=json_data,
        )
        
        return result if result else []
        
    def get_wifi_devices(self, last_time: Optional[float] = None) -> List[dict]:
        """Get WiFi devices only."""
        return self.get_devices(device_type="Wi-Fi Device", last_time=last_time)
        
    def get_bluetooth_devices(self, last_time: Optional[float] = None) -> List[dict]:
        """Get Bluetooth devices (classic and BLE)."""
        # Get both BR/EDR and BTLE devices
        bredr = self.get_devices(device_type="BR/EDR", last_time=last_time)
        btle = self.get_devices(device_type="BTLE", last_time=last_time)
        return bredr + btle
        
    def _parse_device(self, raw: dict) -> KismetDevice:
        """
        Parse raw Kismet device data into KismetDevice.
        
        Args:
            raw: Raw device dictionary from API
            
        Returns:
            KismetDevice object
        """
        mac = raw.get("kismet.device.base.macaddr", "00:00:00:00:00:00")
        dev_type = raw.get("kismet.device.base.type", "unknown")
        
        # Determine device type
        if dev_type == "Wi-Fi Device":
            device_type = "wifi"
        elif dev_type in ["BR/EDR", "BTLE"]:
            device_type = "bluetooth"
        else:
            device_type = "unknown"
            
        # Parse timestamps
        first_time = raw.get("kismet.device.base.first_time", 0)
        last_time = raw.get("kismet.device.base.last_time", 0)
        
        device = KismetDevice(
            mac=mac,
            device_type=device_type,
            first_seen=datetime.fromtimestamp(first_time) if first_time else datetime.utcnow(),
            last_seen=datetime.fromtimestamp(last_time) if last_time else datetime.utcnow(),
            channel=raw.get("kismet.device.base.channel", 0),
            frequency=raw.get("kismet.device.base.frequency", 0),
            rssi=raw.get("kismet.device.base.signal/kismet.common.signal.last_signal", -100),
            manufacturer=raw.get("kismet.device.base.manuf", ""),
            packets=raw.get("kismet.device.base.packets.total", 0),
            kismet_key=raw.get("kismet.device.base.key", ""),
        )
        
        # WiFi specific fields
        if device_type == "wifi":
            dot11 = raw.get("dot11.device", {})
            device.ssid = dot11.get("dot11.device.last_beaconed_ssid", "")
            
            # Extract probed SSIDs
            probe_map = dot11.get("dot11.device.probed_ssid_map", [])
            if isinstance(probe_map, list):
                device.probe_ssids = [
                    p.get("dot11.probedssid.ssid", "")
                    for p in probe_map
                    if p.get("dot11.probedssid.ssid")
                ]
                
        # Bluetooth specific fields
        elif device_type == "bluetooth":
            device.bt_name = raw.get("kismet.device.base.name", "")
            device.bt_type = "ble" if dev_type == "BTLE" else "classic"
            
        return device
        
    def start(self) -> bool:
        """
        Start device polling thread.
        
        Returns:
            True if started
        """
        if self._running:
            return True
            
        if not self.check_connection():
            logger.error("Cannot connect to Kismet - is it running?")
            return False
            
        self._running = True
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()
        logger.info("Kismet polling started")
        return True
        
    def stop(self):
        """Stop device polling."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5.0)
            self._thread = None
        logger.info("Kismet polling stopped")
        
    def _poll_loop(self):
        """Main polling loop."""
        while self._running:
            try:
                self._poll_devices()
            except Exception as e:
                logger.error(f"Kismet poll error: {e}")
                
            time.sleep(self.poll_interval)
            
    def _poll_devices(self):
        """Poll for new/updated devices."""
        # Get devices since last poll
        raw_devices = self.get_devices(last_time=self._last_poll_time)
        
        for raw in raw_devices:
            device = self._parse_device(raw)
            
            with self._lock:
                existing = self._devices.get(device.mac)
                
                if existing is None:
                    # New device
                    self._devices[device.mac] = device
                    for callback in self._new_device_callbacks:
                        try:
                            callback(device)
                        except Exception as e:
                            logger.error(f"Callback error: {e}")
                else:
                    # Update existing
                    self._devices[device.mac] = device
                    for callback in self._device_update_callbacks:
                        try:
                            callback(device)
                        except Exception as e:
                            logger.error(f"Callback error: {e}")
                            
        self._last_poll_time = time.time()
        
    def get_all_devices(self) -> List[KismetDevice]:
        """Get all tracked devices."""
        with self._lock:
            return list(self._devices.values())
            
    def get_device(self, mac: str) -> Optional[KismetDevice]:
        """Get specific device by MAC."""
        with self._lock:
            return self._devices.get(mac.upper())
            
    def get_device_count(self) -> dict:
        """Get device counts by type."""
        with self._lock:
            wifi = sum(1 for d in self._devices.values() if d.device_type == "wifi")
            bt = sum(1 for d in self._devices.values() if d.device_type == "bluetooth")
            return {"wifi": wifi, "bluetooth": bt, "total": len(self._devices)}
            
    def register_new_device_callback(self, callback: Callable[[KismetDevice], None]):
        """Register callback for new device discovery."""
        self._new_device_callbacks.append(callback)
        
    def register_update_callback(self, callback: Callable[[KismetDevice], None]):
        """Register callback for device updates."""
        self._device_update_callbacks.append(callback)
        
    def clear_devices(self):
        """Clear device tracking (for new session)."""
        with self._lock:
            self._devices.clear()
            self._last_poll_time = None


class ChannelHopper:
    """
    Adaptive channel hopping controller.
    
    Adjusts hop rate based on drone velocity.
    """
    
    # Channel lists
    CHANNELS_24GHZ = ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11"]
    CHANNELS_5GHZ = [
        "36", "40", "44", "48", "52", "56", "60", "64",
        "100", "104", "108", "112", "116", "120", "124", "128",
        "132", "136", "140", "144", "149", "153", "157", "161", "165"
    ]
    
    def __init__(
        self,
        kismet: KismetController,
        gps_logger=None,
        fast_rate: float = 10.0,
        slow_rate: float = 2.0,
        adaptive_rate: float = 5.0,
    ):
        """
        Initialize channel hopper.
        
        Args:
            kismet: KismetController instance
            gps_logger: GPSLogger for velocity-based adaptation
            fast_rate: Hop rate for fast mode (hops/second)
            slow_rate: Hop rate for slow mode (hops/second)
            adaptive_rate: Base rate for adaptive mode
        """
        self.kismet = kismet
        self.gps_logger = gps_logger
        self.fast_rate = fast_rate
        self.slow_rate = slow_rate
        self.adaptive_rate = adaptive_rate
        
        self._mode = "adaptive"
        self._active_source: Optional[str] = None
        
    def set_mode(self, mode: str) -> bool:
        """
        Set channel hopping mode.
        
        Args:
            mode: "fast", "slow", "adaptive", or "lock"
            
        Returns:
            True if successful
        """
        if mode not in ["fast", "slow", "adaptive", "lock"]:
            logger.error(f"Invalid hop mode: {mode}")
            return False
            
        self._mode = mode
        logger.info(f"Channel hop mode: {mode}")
        
        if not self._active_source:
            return True
            
        # Apply mode to active source
        if mode == "fast":
            return self.kismet.set_hop_channels(
                self._active_source,
                self.CHANNELS_24GHZ + self.CHANNELS_5GHZ,
                self.fast_rate,
            )
        elif mode == "slow":
            return self.kismet.set_hop_channels(
                self._active_source,
                self.CHANNELS_24GHZ + self.CHANNELS_5GHZ,
                self.slow_rate,
            )
        elif mode == "adaptive":
            return self.kismet.set_hop_channels(
                self._active_source,
                self.CHANNELS_24GHZ + self.CHANNELS_5GHZ,
                self.adaptive_rate,
            )
        elif mode == "lock":
            return self.kismet.disable_hop_mode(self._active_source)
            
        return False
        
    def set_active_source(self, source_uuid: str):
        """Set the active data source for channel control."""
        self._active_source = source_uuid
        
    def lock_channel(self, channel: str) -> bool:
        """Lock to specific channel (disable hopping)."""
        if not self._active_source:
            logger.error("No active source set")
            return False
            
        self._mode = "lock"
        return self.kismet.set_channel(self._active_source, channel)
        
    def update_adaptive_rate(self):
        """Update hop rate based on GPS velocity (for adaptive mode)."""
        if self._mode != "adaptive" or not self.gps_logger:
            return
            
        speed, _ = self.gps_logger.get_velocity()
        
        # Calculate adaptive rate based on speed
        # Fast when moving, slow when stationary
        if speed > 10.0:  # > 10 m/s = fast
            rate = self.fast_rate
        elif speed < 2.0:  # < 2 m/s = slow
            rate = self.slow_rate
        else:
            # Linear interpolation
            rate = self.slow_rate + (speed - 2.0) / 8.0 * (self.fast_rate - self.slow_rate)
            
        if self._active_source:
            self.kismet.set_hop_channels(
                self._active_source,
                self.CHANNELS_24GHZ + self.CHANNELS_5GHZ,
                rate,
            )
