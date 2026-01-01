"""
Project Airdump - GPS Logger

Real-time GPS position tracking via gpsd daemon.
Provides position data for tagging all wireless detections.
"""

import logging
import time
import threading
from datetime import datetime
from typing import Optional, Callable, List, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Try to import gpsd library
try:
    import gpsd
    GPSD_AVAILABLE = True
except ImportError:
    GPSD_AVAILABLE = False
    logger.warning("gpsd-py3 not installed - GPS features disabled")


@dataclass
class GPSPosition:
    """GPS position with quality metrics."""
    
    latitude: float
    longitude: float
    altitude: float
    timestamp: datetime
    speed: float = 0.0  # m/s
    heading: float = 0.0  # degrees
    hdop: float = 99.0  # Horizontal dilution of precision
    fix_quality: int = 0  # 0=no fix, 1=GPS, 2=DGPS, 4=RTK
    satellites: int = 0
    valid: bool = False
    
    def to_tuple(self) -> Tuple[float, float, float, datetime]:
        """Return (lat, lon, alt, timestamp) tuple."""
        return (self.latitude, self.longitude, self.altitude, self.timestamp)
        
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "latitude": self.latitude,
            "longitude": self.longitude,
            "altitude": self.altitude,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "speed": self.speed,
            "heading": self.heading,
            "hdop": self.hdop,
            "fix_quality": self.fix_quality,
            "satellites": self.satellites,
            "valid": self.valid,
        }
        
    @classmethod
    def invalid(cls) -> "GPSPosition":
        """Return an invalid position placeholder."""
        return cls(
            latitude=0.0,
            longitude=0.0,
            altitude=0.0,
            timestamp=datetime.utcnow(),
            valid=False,
        )


class GPSLogger:
    """
    GPS logger using gpsd daemon.
    
    Continuously polls gpsd and maintains current position.
    Supports position history buffering and track logging.
    """
    
    def __init__(
        self,
        host: str = "localhost",
        port: int = 2947,
        poll_interval: float = 1.0,
        history_size: int = 100,
        min_hdop: float = 10.0,
        min_satellites: int = 4,
    ):
        """
        Initialize GPS logger.
        
        Args:
            host: gpsd host
            port: gpsd port
            poll_interval: Seconds between position updates
            history_size: Number of positions to keep in buffer
            min_hdop: Maximum HDOP to consider fix valid
            min_satellites: Minimum satellites for valid fix
        """
        self.host = host
        self.port = port
        self.poll_interval = poll_interval
        self.history_size = history_size
        self.min_hdop = min_hdop
        self.min_satellites = min_satellites
        
        self._current_position: Optional[GPSPosition] = None
        self._position_history: List[GPSPosition] = []
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._connected = False
        self._callbacks: List[Callable[[GPSPosition], None]] = []
        
        # Statistics
        self._fix_count = 0
        self._no_fix_count = 0
        self._last_fix_time: Optional[datetime] = None
        
    def connect(self) -> bool:
        """
        Connect to gpsd daemon.
        
        Returns:
            True if connection successful
        """
        if not GPSD_AVAILABLE:
            logger.error("gpsd library not available")
            return False
            
        try:
            gpsd.connect(host=self.host, port=self.port)
            self._connected = True
            logger.info(f"Connected to gpsd at {self.host}:{self.port}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to gpsd: {e}")
            self._connected = False
            return False
            
    def start(self) -> bool:
        """
        Start GPS polling thread.
        
        Returns:
            True if started successfully
        """
        if self._running:
            logger.warning("GPS logger already running")
            return True
            
        if not self._connected:
            if not self.connect():
                return False
                
        self._running = True
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()
        logger.info("GPS polling started")
        return True
        
    def stop(self):
        """Stop GPS polling thread."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5.0)
            self._thread = None
        logger.info("GPS polling stopped")
        
    def _poll_loop(self):
        """Main polling loop (runs in separate thread)."""
        while self._running:
            try:
                self._update_position()
            except Exception as e:
                logger.error(f"GPS poll error: {e}")
                # Try to reconnect
                time.sleep(2.0)
                self.connect()
                
            time.sleep(self.poll_interval)
            
    def _update_position(self):
        """Fetch current position from gpsd."""
        if not GPSD_AVAILABLE:
            return
            
        try:
            packet = gpsd.get_current()
            
            # Parse position from gpsd packet
            position = self._parse_gpsd_packet(packet)
            
            with self._lock:
                self._current_position = position
                
                # Add to history if valid
                if position.valid:
                    self._position_history.append(position)
                    # Trim history to max size
                    if len(self._position_history) > self.history_size:
                        self._position_history = self._position_history[-self.history_size:]
                    
                    self._fix_count += 1
                    self._last_fix_time = position.timestamp
                else:
                    self._no_fix_count += 1
                    
            # Notify callbacks
            for callback in self._callbacks:
                try:
                    callback(position)
                except Exception as e:
                    logger.error(f"GPS callback error: {e}")
                    
        except Exception as e:
            logger.debug(f"GPS update failed: {e}")
            
    def _parse_gpsd_packet(self, packet) -> GPSPosition:
        """
        Parse gpsd packet into GPSPosition.
        
        Args:
            packet: gpsd packet object
            
        Returns:
            GPSPosition object
        """
        try:
            # Get position (may raise NoFixError)
            lat, lon = packet.position()
            alt = packet.altitude() if hasattr(packet, 'altitude') else 0.0
            
            # Get additional data
            speed = packet.speed() if hasattr(packet, 'speed') else 0.0
            heading = packet.movement().get('track', 0.0) if hasattr(packet, 'movement') else 0.0
            
            # Get precision info
            try:
                precision = packet.position_precision()
                hdop = precision[0] if precision else 99.0
            except:
                hdop = 99.0
                
            # Get satellite count
            try:
                sats = packet.sats
                satellites = len([s for s in sats if s.used]) if sats else 0
            except:
                satellites = 0
                
            # Determine fix quality
            mode = packet.mode if hasattr(packet, 'mode') else 0
            fix_quality = 1 if mode >= 2 else 0  # 2D or 3D fix
            
            # Validate fix
            valid = (
                hdop <= self.min_hdop and
                satellites >= self.min_satellites and
                mode >= 2
            )
            
            return GPSPosition(
                latitude=lat,
                longitude=lon,
                altitude=alt,
                timestamp=datetime.utcnow(),
                speed=speed,
                heading=heading,
                hdop=hdop,
                fix_quality=fix_quality,
                satellites=satellites,
                valid=valid,
            )
            
        except gpsd.NoFixError:
            return GPSPosition.invalid()
        except Exception as e:
            logger.debug(f"Parse error: {e}")
            return GPSPosition.invalid()
            
    def get_current_position(self) -> Tuple[float, float, float, datetime]:
        """
        Get current GPS position.
        
        Returns:
            Tuple of (latitude, longitude, altitude, timestamp)
            Returns (0, 0, 0, now) if no valid fix
        """
        with self._lock:
            if self._current_position and self._current_position.valid:
                return self._current_position.to_tuple()
            return (0.0, 0.0, 0.0, datetime.utcnow())
            
    def get_position(self) -> Optional[GPSPosition]:
        """
        Get current GPS position object.
        
        Returns:
            GPSPosition or None if no data
        """
        with self._lock:
            return self._current_position
            
    def get_history(self, count: Optional[int] = None) -> List[GPSPosition]:
        """
        Get position history.
        
        Args:
            count: Number of recent positions (None for all)
            
        Returns:
            List of GPSPosition objects
        """
        with self._lock:
            if count:
                return self._position_history[-count:]
            return self._position_history.copy()
            
    def has_fix(self) -> bool:
        """Check if we currently have a valid GPS fix."""
        with self._lock:
            return self._current_position is not None and self._current_position.valid
            
    def get_stats(self) -> dict:
        """
        Get GPS statistics.
        
        Returns:
            Dictionary with fix stats
        """
        with self._lock:
            total = self._fix_count + self._no_fix_count
            has_fix = self._current_position is not None and self._current_position.valid
            return {
                "connected": self._connected,
                "running": self._running,
                "has_fix": has_fix,
                "fix_count": self._fix_count,
                "no_fix_count": self._no_fix_count,
                "fix_rate": self._fix_count / total if total > 0 else 0.0,
                "last_fix": self._last_fix_time.isoformat() if self._last_fix_time else None,
                "history_size": len(self._position_history),
            }
            
    def register_callback(self, callback: Callable[[GPSPosition], None]):
        """
        Register callback for position updates.
        
        Args:
            callback: Function to call with each GPSPosition
        """
        self._callbacks.append(callback)
        
    def unregister_callback(self, callback: Callable[[GPSPosition], None]):
        """Remove a callback."""
        if callback in self._callbacks:
            self._callbacks.remove(callback)
            
    def wait_for_fix(self, timeout: float = 60.0) -> bool:
        """
        Wait for valid GPS fix.
        
        Args:
            timeout: Maximum seconds to wait
            
        Returns:
            True if fix acquired
        """
        start = time.time()
        while time.time() - start < timeout:
            if self.has_fix():
                return True
            time.sleep(0.5)
        return False
        
    def get_velocity(self) -> Tuple[float, float]:
        """
        Get current velocity.
        
        Returns:
            Tuple of (speed in m/s, heading in degrees)
        """
        with self._lock:
            if self._current_position and self._current_position.valid:
                return (self._current_position.speed, self._current_position.heading)
            return (0.0, 0.0)
            
    def estimate_channel_hop_mode(
        self,
        fast_threshold: float = 5.0,
        slow_threshold: float = 2.0,
    ) -> str:
        """
        Estimate appropriate channel hopping mode based on velocity.
        
        Args:
            fast_threshold: Speed above which to use fast mode (m/s)
            slow_threshold: Speed below which to use slow mode (m/s)
            
        Returns:
            "fast", "slow", or "adaptive"
        """
        speed, _ = self.get_velocity()
        
        if speed >= fast_threshold:
            return "fast"
        elif speed <= slow_threshold:
            return "slow"
        else:
            return "adaptive"


class MockGPSLogger(GPSLogger):
    """Mock GPS logger for testing without gpsd."""
    
    def __init__(
        self,
        base_lat: float = 51.5074,
        base_lon: float = -0.1278,
        base_alt: float = 50.0,
        **kwargs
    ):
        """
        Initialize mock GPS with static position.
        
        Args:
            base_lat: Base latitude
            base_lon: Base longitude
            base_alt: Base altitude
        """
        super().__init__(**kwargs)
        self.base_lat = base_lat
        self.base_lon = base_lon
        self.base_alt = base_alt
        self._mock_position = GPSPosition(
            latitude=base_lat,
            longitude=base_lon,
            altitude=base_alt,
            timestamp=datetime.utcnow(),
            hdop=1.0,
            fix_quality=1,
            satellites=10,
            valid=True,
        )
        
    def connect(self) -> bool:
        """Mock connect always succeeds."""
        self._connected = True
        logger.info("Mock GPS connected")
        return True
        
    def _update_position(self):
        """Update mock position with slight variation."""
        import random
        
        # Add small random variation
        lat_offset = random.uniform(-0.0001, 0.0001)
        lon_offset = random.uniform(-0.0001, 0.0001)
        
        self._mock_position = GPSPosition(
            latitude=self.base_lat + lat_offset,
            longitude=self.base_lon + lon_offset,
            altitude=self.base_alt + random.uniform(-1, 1),
            timestamp=datetime.utcnow(),
            speed=random.uniform(0, 15),
            heading=random.uniform(0, 360),
            hdop=random.uniform(0.8, 2.0),
            fix_quality=1,
            satellites=random.randint(6, 12),
            valid=True,
        )
        
        with self._lock:
            self._current_position = self._mock_position
            self._position_history.append(self._mock_position)
            if len(self._position_history) > self.history_size:
                self._position_history = self._position_history[-self.history_size:]
            self._fix_count += 1
            self._last_fix_time = self._mock_position.timestamp
