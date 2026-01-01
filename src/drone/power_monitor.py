"""
Project Airdump - Power Monitor

Monitor ZeroPi power status for graceful shutdown before power loss.
Uses voltage monitoring or I2C UPS status.
"""

import logging
import threading
import time
from datetime import datetime
from typing import Optional, Callable, List
from pathlib import Path

logger = logging.getLogger(__name__)


class PowerMonitor:
    """
    Monitor power status for safe shutdown.
    
    Supports:
    - Voltage monitoring via ADC
    - UPS HAT status via I2C
    - GPIO shutdown signal
    - USB power detection
    """
    
    # Default thresholds (volts)
    VOLTAGE_WARNING = 3.5  # Warning level
    VOLTAGE_CRITICAL = 3.3  # Initiate shutdown
    VOLTAGE_SHUTDOWN = 3.1  # Immediate shutdown
    
    def __init__(
        self,
        voltage_source: str = "adc",  # "adc", "i2c", "sysfs"
        adc_channel: int = 0,
        voltage_divider: float = 2.0,  # Resistor divider ratio
        poll_interval: float = 5.0,
        warning_threshold: float = VOLTAGE_WARNING,
        critical_threshold: float = VOLTAGE_CRITICAL,
        shutdown_threshold: float = VOLTAGE_SHUTDOWN,
    ):
        """
        Initialize power monitor.
        
        Args:
            voltage_source: Method to read voltage
            adc_channel: ADC channel number
            voltage_divider: Voltage divider ratio for ADC
            poll_interval: Seconds between polls
            warning_threshold: Warning voltage level
            critical_threshold: Critical voltage level
            shutdown_threshold: Immediate shutdown level
        """
        self.voltage_source = voltage_source
        self.adc_channel = adc_channel
        self.voltage_divider = voltage_divider
        self.poll_interval = poll_interval
        self.warning_threshold = warning_threshold
        self.critical_threshold = critical_threshold
        self.shutdown_threshold = shutdown_threshold
        
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        
        self._current_voltage: float = 0.0
        self._power_state: str = "unknown"
        self._on_battery: bool = False
        
        # Callbacks
        self._warning_callbacks: List[Callable[[float], None]] = []
        self._critical_callbacks: List[Callable[[float], None]] = []
        self._shutdown_callbacks: List[Callable[[float], None]] = []
        
        # History for trend analysis
        self._voltage_history: List[tuple] = []  # (timestamp, voltage)
        self._history_max_size = 100
        
    def start(self) -> bool:
        """Start power monitoring."""
        if self._running:
            return True
            
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        logger.info("Power monitoring started")
        return True
        
    def stop(self):
        """Stop power monitoring."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5.0)
            self._thread = None
        logger.info("Power monitoring stopped")
        
    def _monitor_loop(self):
        """Main monitoring loop."""
        while self._running:
            try:
                voltage = self._read_voltage()
                
                with self._lock:
                    self._current_voltage = voltage
                    self._voltage_history.append((datetime.utcnow(), voltage))
                    
                    # Trim history
                    if len(self._voltage_history) > self._history_max_size:
                        self._voltage_history = self._voltage_history[-self._history_max_size:]
                        
                    # Update state
                    old_state = self._power_state
                    self._power_state = self._determine_state(voltage)
                    
                # Trigger callbacks if state changed or critical
                if self._power_state == "shutdown":
                    for callback in self._shutdown_callbacks:
                        try:
                            callback(voltage)
                        except Exception as e:
                            logger.error(f"Shutdown callback error: {e}")
                            
                elif self._power_state == "critical":
                    if old_state != "critical":
                        for callback in self._critical_callbacks:
                            try:
                                callback(voltage)
                            except Exception as e:
                                logger.error(f"Critical callback error: {e}")
                                
                elif self._power_state == "warning":
                    if old_state not in ["warning", "critical", "shutdown"]:
                        for callback in self._warning_callbacks:
                            try:
                                callback(voltage)
                            except Exception as e:
                                logger.error(f"Warning callback error: {e}")
                                
            except Exception as e:
                logger.error(f"Power monitoring error: {e}")
                
            time.sleep(self.poll_interval)
            
    def _read_voltage(self) -> float:
        """Read voltage from configured source."""
        if self.voltage_source == "adc":
            return self._read_adc_voltage()
        elif self.voltage_source == "i2c":
            return self._read_i2c_voltage()
        elif self.voltage_source == "sysfs":
            return self._read_sysfs_voltage()
        else:
            return 5.0  # Assume OK if no monitoring
            
    def _read_adc_voltage(self) -> float:
        """Read voltage from ADC (MCP3008 or similar)."""
        try:
            # Try to use spidev for MCP3008
            import spidev
            
            spi = spidev.SpiDev()
            spi.open(0, 0)
            spi.max_speed_hz = 1350000
            
            # Read from channel
            channel = self.adc_channel
            adc = spi.xfer2([1, (8 + channel) << 4, 0])
            data = ((adc[1] & 3) << 8) + adc[2]
            
            spi.close()
            
            # Convert to voltage (3.3V reference, 10-bit ADC)
            voltage = (data * 3.3) / 1024.0
            
            # Account for voltage divider
            voltage *= self.voltage_divider
            
            return voltage
            
        except ImportError:
            logger.debug("spidev not available")
            return 5.0
        except Exception as e:
            logger.debug(f"ADC read error: {e}")
            return 5.0
            
    def _read_i2c_voltage(self) -> float:
        """Read voltage from I2C UPS HAT."""
        try:
            import smbus
            
            bus = smbus.SMBus(1)
            
            # Example: Read from INA219 power monitor
            # Address and register would depend on specific HAT
            address = 0x40
            
            # Read voltage register
            raw = bus.read_word_data(address, 0x02)
            
            # Convert (depends on specific chip)
            voltage = (raw >> 3) * 0.004
            
            return voltage
            
        except ImportError:
            logger.debug("smbus not available")
            return 5.0
        except Exception as e:
            logger.debug(f"I2C read error: {e}")
            return 5.0
            
    def _read_sysfs_voltage(self) -> float:
        """Read voltage from sysfs (Linux power supply class)."""
        try:
            # Look for battery/power supply info
            power_supply_path = Path("/sys/class/power_supply")
            
            if not power_supply_path.exists():
                return 5.0
                
            # Find battery device
            for device in power_supply_path.iterdir():
                voltage_file = device / "voltage_now"
                if voltage_file.exists():
                    voltage_uv = int(voltage_file.read_text().strip())
                    return voltage_uv / 1_000_000.0  # Convert µV to V
                    
            return 5.0
            
        except Exception as e:
            logger.debug(f"sysfs read error: {e}")
            return 5.0
            
    def _determine_state(self, voltage: float) -> str:
        """Determine power state from voltage."""
        if voltage <= self.shutdown_threshold:
            return "shutdown"
        elif voltage <= self.critical_threshold:
            return "critical"
        elif voltage <= self.warning_threshold:
            return "warning"
        else:
            return "ok"
            
    def get_voltage(self) -> float:
        """Get current voltage reading."""
        with self._lock:
            return self._current_voltage
            
    def get_state(self) -> str:
        """Get current power state."""
        with self._lock:
            return self._power_state
            
    def get_stats(self) -> dict:
        """Get power statistics."""
        with self._lock:
            # Calculate trend
            trend = 0.0
            if len(self._voltage_history) >= 2:
                recent = self._voltage_history[-10:]
                if len(recent) >= 2:
                    first_v = recent[0][1]
                    last_v = recent[-1][1]
                    first_t = recent[0][0]
                    last_t = recent[-1][0]
                    time_diff = (last_t - first_t).total_seconds()
                    if time_diff > 0:
                        trend = (last_v - first_v) / time_diff * 60  # V/minute
                        
            # Estimate remaining time
            remaining_minutes = None
            if trend < 0 and self._current_voltage > self.shutdown_threshold:
                voltage_remaining = self._current_voltage - self.shutdown_threshold
                remaining_minutes = abs(voltage_remaining / trend) if trend != 0 else None
                
            return {
                "voltage": self._current_voltage,
                "state": self._power_state,
                "trend_v_per_min": trend,
                "remaining_minutes": remaining_minutes,
                "on_battery": self._on_battery,
                "history_points": len(self._voltage_history),
            }
            
    def register_warning_callback(self, callback: Callable[[float], None]):
        """Register callback for warning level."""
        self._warning_callbacks.append(callback)
        
    def register_critical_callback(self, callback: Callable[[float], None]):
        """Register callback for critical level."""
        self._critical_callbacks.append(callback)
        
    def register_shutdown_callback(self, callback: Callable[[float], None]):
        """Register callback for shutdown level."""
        self._shutdown_callbacks.append(callback)
        
    def should_shutdown(self) -> bool:
        """Check if immediate shutdown is needed."""
        with self._lock:
            return self._power_state == "shutdown"
            
    def should_save_state(self) -> bool:
        """Check if state should be saved (critical or worse)."""
        with self._lock:
            return self._power_state in ["critical", "shutdown"]


class MockPowerMonitor(PowerMonitor):
    """Mock power monitor for testing."""
    
    def __init__(self, initial_voltage: float = 4.2, **kwargs):
        """Initialize with controllable voltage."""
        super().__init__(**kwargs)
        self._mock_voltage = initial_voltage
        
    def _read_voltage(self) -> float:
        """Return mock voltage."""
        return self._mock_voltage
        
    def set_voltage(self, voltage: float):
        """Set mock voltage for testing."""
        self._mock_voltage = voltage
        
    def simulate_discharge(self, rate: float = 0.01):
        """Simulate battery discharge."""
        self._mock_voltage = max(3.0, self._mock_voltage - rate)
