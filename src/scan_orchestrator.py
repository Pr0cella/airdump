"""
Project Airdump - Scan Orchestrator

Main coordinator for all scanning operations.
Manages lifecycle of GPS, Kismet, tshark, and fingerprinting modules.
"""

import atexit
import logging
import signal
import sys
import time
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any, List

from core.database import Database
from core.models import ScanSession, ScanStatus
from core.utils import setup_logging, load_config, generate_session_id, restore_managed_mode
from core.encryption import KeyManager

from scanners.gps_logger import GPSLogger, MockGPSLogger
from scanners.kismet_controller import KismetController, ChannelHopper
from scanners.tshark_capture import TsharkCapture

from fingerprinting.engine import FingerprintEngine

from drone.power_monitor import PowerMonitor

logger = logging.getLogger(__name__)

# Global reference to active orchestrator for atexit cleanup
_active_orchestrator: Optional['ScanOrchestrator'] = None


def _atexit_cleanup():
    """Cleanup handler called on program exit."""
    global _active_orchestrator
    if _active_orchestrator:
        logger.info("Running atexit cleanup...")
        _active_orchestrator.stop()
    else:
        # Even without orchestrator, try to restore interface
        restore_managed_mode()


# Register atexit handler
atexit.register(_atexit_cleanup)


class ScanOrchestrator:
    """
    Main scan orchestrator.
    
    Coordinates all scanning modules and handles:
    - Session management
    - Module lifecycle
    - Graceful shutdown
    - Error recovery
    - Data persistence
    """
    
    def __init__(
        self,
        config_file: str = "config/config.yaml",
        data_dir: str = "data",
        mock_gps: bool = False,
    ):
        """
        Initialize scan orchestrator.
        
        Args:
            config_file: Path to configuration file
            data_dir: Base data directory
            mock_gps: Use mock GPS for testing
        """
        self.config_file = config_file
        self.data_dir = Path(data_dir)
        self.mock_gps = mock_gps
        
        # Load configuration
        self.config = load_config(config_file)
        
        # Setup logging
        log_dir = self.data_dir / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        setup_logging(
            log_dir=str(log_dir),
            log_level=self.config.get("general", {}).get("log_level", "INFO"),
        )
        
        # State
        self._running = False
        self._session: Optional[ScanSession] = None
        self._shutdown_event = threading.Event()
        
        # Modules (initialized on start)
        self.database: Optional[Database] = None
        self.gps: Optional[GPSLogger] = None
        self.kismet: Optional[KismetController] = None
        self.channel_hopper: Optional[ChannelHopper] = None
        self.tshark: Optional[TsharkCapture] = None
        self.fingerprint_engine: Optional[FingerprintEngine] = None
        self.power_monitor: Optional[PowerMonitor] = None
        
        # Statistics
        self._stats = {
            "wifi_devices": 0,
            "bt_devices": 0,
            "packets_captured": 0,
            "gps_fixes": 0,
        }
        
        # Register signal handlers
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
        
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        logger.info(f"Received signal {signum}, initiating graceful shutdown")
        self.stop()
        
    def start(
        self,
        session_name: Optional[str] = None,
        property_id: Optional[str] = None,
        duration: Optional[int] = None,
    ) -> bool:
        """
        Start scanning session.
        
        Args:
            session_name: Optional session name
            property_id: Optional property identifier
            duration: Max duration in seconds (None for unlimited)
            
        Returns:
            True if started successfully
        """
        global _active_orchestrator
        
        if self._running:
            logger.warning("Scan already running")
            return False
            
        logger.info("Starting scan orchestrator...")
        
        # Register for atexit cleanup
        _active_orchestrator = self
        
        try:
            # Initialize database
            if not self._init_database():
                return False
                
            # Create session
            session_id = generate_session_id()
            self._session = ScanSession(
                session_id=session_id,
                start_time=datetime.now().astimezone(),
                status=ScanStatus.RUNNING,
                property_id=property_id,
                notes=session_name,
                node_id=self.config.get("general", {}).get("node_id", "primary"),
            )
            self.database.create_session(self._session)
            logger.info(f"Created session: {session_id}")
            
            # Initialize GPS
            if not self._init_gps():
                logger.warning("GPS initialization failed - continuing without GPS")
                
            # Initialize Kismet
            if not self._init_kismet():
                logger.warning("Kismet initialization failed - continuing without Kismet")
                
            # Initialize tshark
            if not self._init_tshark():
                logger.warning("tshark initialization failed - continuing without tshark")
                
            # Initialize fingerprinting engine
            self._init_fingerprinting()
            
            # Initialize power monitor
            if not self._init_power_monitor():
                logger.warning("Power monitor initialization failed")
                
            self._running = True
            
            # Start main loop in thread
            self._main_thread = threading.Thread(target=self._main_loop, daemon=True)
            self._main_thread.start()
            
            logger.info("Scan orchestrator started successfully")
            
            # Wait for duration if specified
            if duration:
                logger.info(f"Scanning for {duration} seconds...")
                self._shutdown_event.wait(timeout=duration)
                if self._running:
                    self.stop()
                    
            return True
            
        except Exception as e:
            logger.error(f"Failed to start scan: {e}")
            self.stop()
            return False
            
    def _init_database(self) -> bool:
        """Initialize database connection."""
        try:
            db_config = self.config.get("database", {})
            db_path_str = db_config.get("path", "database/airdump.db")
            
            # Path may already be expanded by load_config, or contain ${data_dir}
            # Expand any remaining ${data_dir} variables
            if "${data_dir}" in db_path_str:
                db_path_str = db_path_str.replace("${data_dir}", str(self.data_dir))
            
            # If path is already absolute or relative from cwd, use as-is
            # Otherwise join with data_dir
            db_path = Path(db_path_str)
            if not db_path.is_absolute() and not db_path_str.startswith(("./", "../")):
                # Check if it's not already prefixed with data_dir
                data_dir_str = str(self.data_dir)
                if not db_path_str.startswith(data_dir_str + "/") and not db_path_str.startswith(data_dir_str + "\\"):
                    db_path = self.data_dir / db_path_str
            
            db_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Get encryption key if enabled
            encryption_key = None
            if db_config.get("encryption_enabled", False):
                key_manager = KeyManager()
                encryption_key = key_manager.get_db_key()
                if not encryption_key:
                    logger.warning("Database encryption enabled but no key found")
                    
            self.database = Database(
                db_path=str(db_path),
                encryption_key=encryption_key,
            )
            
            # Initialize schema (creates tables if not exist)
            self.database.initialize_schema()
            
            logger.info(f"Database initialized: {db_path}")
            return True
            
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
            return False
            
    def _init_gps(self) -> bool:
        """Initialize GPS module."""
        try:
            gps_config = self.config.get("gps", {})
            
            # Check if GPS is enabled in config
            if not gps_config.get("enabled", False) and not self.mock_gps:
                logger.info("GPS disabled in config (use --gps to enable)")
                return False
            
            if self.mock_gps:
                self.gps = MockGPSLogger(
                    poll_interval=gps_config.get("poll_interval", 1.0),
                )
            else:
                self.gps = GPSLogger(
                    host=gps_config.get("host", "localhost"),
                    port=gps_config.get("port", 2947),
                    poll_interval=gps_config.get("poll_interval", 1.0),
                    min_hdop=gps_config.get("min_hdop", 10.0),
                    min_satellites=gps_config.get("min_satellites", 4),
                )
                
            if not self.gps.start():
                return False
                
            # Wait for initial fix only if configured
            if gps_config.get("wait_for_fix", False):
                timeout = gps_config.get("fix_timeout", 60)
                logger.info(f"Waiting for GPS fix (timeout: {timeout}s)...")
                if self.gps.wait_for_fix(timeout):
                    logger.info("GPS fix acquired")
                else:
                    logger.warning("GPS fix timeout - continuing without fix")
                    
            # Register GPS track callback
            self.gps.register_callback(self._on_gps_update)
            
            return True
            
        except Exception as e:
            logger.error(f"GPS initialization failed: {e}")
            return False
            
    def _init_kismet(self) -> bool:
        """Initialize Kismet controller."""
        try:
            kismet_config = self.config.get("kismet", {})
            
            if not kismet_config.get("enabled", True):
                logger.info("Kismet disabled in config")
                return False
                
            self.kismet = KismetController(
                host=kismet_config.get("host", "localhost"),
                port=kismet_config.get("port", 2501),
                username=kismet_config.get("username", "kismet"),
                password=kismet_config.get("password", "kismet"),
                poll_interval=kismet_config.get("poll_interval", 2.0),
            )
            
            if not self.kismet.check_connection():
                logger.error("Cannot connect to Kismet")
                return False
                
            # Register callbacks
            self.kismet.register_new_device_callback(self._on_new_device)
            self.kismet.register_update_callback(self._on_device_update)
            
            if not self.kismet.start():
                return False
                
            # Initialize channel hopper
            hop_config = self.config.get("channel_hopping", {})
            self.channel_hopper = ChannelHopper(
                kismet=self.kismet,
                gps_logger=self.gps,
                fast_rate=hop_config.get("fast_rate", 10.0),
                slow_rate=hop_config.get("slow_rate", 2.0),
            )
            
            # Set initial hop mode
            self.channel_hopper.set_mode(hop_config.get("default_mode", "adaptive"))
            
            logger.info("Kismet initialized")
            return True
            
        except Exception as e:
            logger.error(f"Kismet initialization failed: {e}")
            return False
            
    def _init_tshark(self) -> bool:
        """Initialize tshark capture."""
        try:
            capture_config = self.config.get("capture", {})
            
            if not capture_config.get("enabled", True):
                logger.info("Packet capture disabled in config")
                return False
                
            pcap_dir = self.data_dir / "pcap"
            pcap_dir.mkdir(parents=True, exist_ok=True)
            
            self.tshark = TsharkCapture(
                interface=capture_config.get("interface", "wlan0mon"),
                output_dir=str(pcap_dir),
                max_file_size_mb=capture_config.get("max_file_size_mb", 100),
            )
            
            # Start capture for current session
            if self._session:
                self.tshark.start_capture(
                    session_id=self._session.session_id,
                    filter_expr=capture_config.get("filter", None),
                )
                
            logger.info("tshark capture initialized")
            return True
            
        except Exception as e:
            logger.error(f"tshark initialization failed: {e}")
            return False
            
    def _init_fingerprinting(self):
        """Initialize fingerprinting engine."""
        self.fingerprint_engine = FingerprintEngine(
            database=self.database,
            gps_logger=self.gps,
            auto_store=True,
        )
        
        # Register callback for new fingerprints
        self.fingerprint_engine.register_callback(self._on_fingerprint)
        
        logger.info("Fingerprinting engine initialized")
        
    def _init_power_monitor(self) -> bool:
        """Initialize power monitor."""
        try:
            power_config = self.config.get("power", {})
            
            if not power_config.get("monitor_enabled", False):
                logger.info("Power monitoring disabled in config")
                return False
                
            self.power_monitor = PowerMonitor(
                voltage_source=power_config.get("voltage_source", "sysfs"),
                poll_interval=power_config.get("poll_interval", 5.0),
                warning_threshold=power_config.get("warning_voltage", 3.5),
                critical_threshold=power_config.get("critical_voltage", 3.3),
                shutdown_threshold=power_config.get("shutdown_voltage", 3.1),
            )
            
            # Register callbacks
            self.power_monitor.register_warning_callback(self._on_power_warning)
            self.power_monitor.register_critical_callback(self._on_power_critical)
            self.power_monitor.register_shutdown_callback(self._on_power_shutdown)
            
            self.power_monitor.start()
            logger.info("Power monitoring initialized")
            return True
            
        except Exception as e:
            logger.error(f"Power monitor initialization failed: {e}")
            return False
            
    def _main_loop(self):
        """Main orchestration loop."""
        while self._running:
            try:
                # Update adaptive channel hopping
                if self.channel_hopper:
                    self.channel_hopper.update_adaptive_rate()
                    
                # Log periodic stats
                self._log_stats()
                
                # Check for shutdown conditions
                if self.power_monitor and self.power_monitor.should_shutdown():
                    logger.warning("Power critical - initiating shutdown")
                    self.stop()
                    break
                    
            except Exception as e:
                logger.error(f"Main loop error: {e}")
                
            time.sleep(10)  # Main loop interval
            
    def _on_gps_update(self, position):
        """Handle GPS position update."""
        if position.valid:
            self._stats["gps_fixes"] += 1
            
            # Log to database
            if self.database and self._session:
                self.database.insert_gps_point(
                    self._session.session_id,
                    position.latitude,
                    position.longitude,
                    position.altitude,
                    position.timestamp,
                    position.hdop,
                    position.satellites,
                )
                
    def _on_new_device(self, device):
        """Handle new device discovery from Kismet."""
        if device.device_type == "wifi":
            self._stats["wifi_devices"] += 1
        elif device.device_type == "bluetooth":
            self._stats["bt_devices"] += 1
            
        # Process through fingerprinting engine
        if self.fingerprint_engine:
            self.fingerprint_engine.process_kismet_device(device)
            
        logger.info(f"New device: {device.device_type} {device.mac} (RSSI: {device.rssi})")
        
    def _on_device_update(self, device):
        """Handle device update from Kismet."""
        # Could update fingerprint or track movement
        pass
        
    def _on_fingerprint(self, device_type: str, fingerprint: str, data: dict):
        """Handle new fingerprint."""
        logger.debug(f"Fingerprint: {device_type} {fingerprint[:16]}...")
        
    def _on_power_warning(self, voltage: float):
        """Handle power warning."""
        logger.warning(f"Power warning: {voltage:.2f}V")
        
    def _on_power_critical(self, voltage: float):
        """Handle power critical."""
        logger.warning(f"Power critical: {voltage:.2f}V - saving state")
        self._save_state()
        
    def _on_power_shutdown(self, voltage: float):
        """Handle power shutdown."""
        logger.error(f"Power shutdown: {voltage:.2f}V")
        self.stop()
        
    def _save_state(self):
        """Save current state for recovery."""
        if self.database:
            self.database.flush_buffer()
            
    def _log_stats(self):
        """Log current statistics."""
        logger.info(
            f"Stats: WiFi={self._stats['wifi_devices']}, "
            f"BT={self._stats['bt_devices']}, "
            f"GPS={self._stats['gps_fixes']}"
        )
        
    def stop(self):
        """Stop scanning and cleanup."""
        if not self._running:
            return
        
        global _active_orchestrator
            
        logger.info("Stopping scan orchestrator...")
        self._running = False
        self._shutdown_event.set()
        
        # Stop modules in reverse order
        if self.power_monitor:
            self.power_monitor.stop()
            
        if self.tshark:
            pcap_file = self.tshark.stop_capture()
            if pcap_file:
                logger.info(f"Capture saved: {pcap_file}")
                
        if self.kismet:
            self.kismet.stop()
            
        if self.gps:
            self.gps.stop()
            
        # Update session
        if self._session and self.database:
            self._session.end_time = datetime.now().astimezone()
            self._session.status = ScanStatus.STOPPED
            self._session.wifi_device_count = self._stats["wifi_devices"]
            self._session.bt_device_count = self._stats["bt_devices"]
            self.database.update_session(self._session)
            
        # Flush database
        if self.database:
            self.database.flush_buffer()
            self.database.close()
        
        # Restore WiFi interface to managed mode
        interface = None
        if self.tshark and self.tshark.interface:
            interface = self.tshark.interface
        restore_managed_mode(interface)
        
        # Clear global reference
        _active_orchestrator = None
            
        logger.info("Scan orchestrator stopped")
        
    def get_session_id(self) -> Optional[str]:
        """Get current session ID."""
        return self._session.session_id if self._session else None
        
    def get_stats(self) -> dict:
        """Get current statistics."""
        stats = {**self._stats}
        
        if self.gps:
            stats["gps"] = self.gps.get_stats()
            
        if self.kismet:
            stats["kismet"] = self.kismet.get_device_count()
            
        if self.power_monitor:
            stats["power"] = self.power_monitor.get_stats()
            
        if self.tshark:
            stats["capture"] = self.tshark.get_capture_stats()
            
        return stats
        
    def set_channel_mode(self, mode: str):
        """Change channel hopping mode."""
        if self.channel_hopper:
            self.channel_hopper.set_mode(mode)


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Airdump Scan Orchestrator")
    parser.add_argument("--config", default="config/config.yaml", help="Config file path")
    parser.add_argument("--data-dir", default="data", help="Data directory")
    parser.add_argument("--duration", type=int, help="Scan duration in seconds")
    parser.add_argument("--session-name", help="Session name")
    parser.add_argument("--property-id", help="Property identifier")
    parser.add_argument("--mock-gps", action="store_true", help="Use mock GPS")
    
    args = parser.parse_args()
    
    orchestrator = ScanOrchestrator(
        config_file=args.config,
        data_dir=args.data_dir,
        mock_gps=args.mock_gps,
    )
    
    try:
        orchestrator.start(
            session_name=args.session_name,
            property_id=args.property_id,
            duration=args.duration,
        )
        
        # If no duration, wait for signal
        if not args.duration:
            while orchestrator._running:
                time.sleep(1)
                
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received")
    finally:
        orchestrator.stop()


if __name__ == "__main__":
    main()
