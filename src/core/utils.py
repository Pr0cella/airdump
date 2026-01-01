"""
Project Airdump - Core Utilities

Shared utility functions for the project.
"""

import os
import re
import yaml
import logging
import hashlib
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, List
from logging.handlers import RotatingFileHandler


# Module logger
logger = logging.getLogger(__name__)


def setup_logging(
    log_dir: str = "/data/logs",
    log_level: str = "INFO",
    app_name: str = "airdump",
) -> logging.Logger:
    """
    Configure application logging.
    
    Args:
        log_dir: Directory for log files
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR)
        app_name: Application name for logger
        
    Returns:
        Configured logger instance
    """
    # Ensure log directory exists
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    
    # Get logger
    logger = logging.getLogger(app_name)
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # File handler with rotation (10MB, keep 5 backups)
    file_handler = RotatingFileHandler(
        Path(log_dir) / f"{app_name}.log",
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    ))
    logger.addHandler(file_handler)
    
    # Console handler for systemd journal
    console_handler = logging.StreamHandler()
    console_handler.setLevel(getattr(logging, log_level.upper()))
    console_handler.setFormatter(logging.Formatter(
        "%(levelname)s - %(message)s"
    ))
    logger.addHandler(console_handler)
    
    return logger


def load_config(config_path: str = "config/config.yaml") -> Dict[str, Any]:
    """
    Load YAML configuration file.
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        Configuration dictionary
    """
    config_file = Path(config_path)
    
    if not config_file.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
        
    with open(config_file, "r") as f:
        config = yaml.safe_load(f)
        
    # Expand ${data_dir} variables
    data_dir = config.get("general", {}).get("data_dir", "/opt/airdump/data")
    config = _expand_variables(config, {"data_dir": data_dir})
    
    return config


def _expand_variables(obj: Any, variables: Dict[str, str]) -> Any:
    """Recursively expand ${var} in config values."""
    if isinstance(obj, dict):
        return {k: _expand_variables(v, variables) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_expand_variables(item, variables) for item in obj]
    elif isinstance(obj, str):
        for var, value in variables.items():
            obj = obj.replace(f"${{{var}}}", value)
        return obj
    return obj


def generate_session_id(prefix: str = "") -> str:
    """
    Generate unique session ID.
    
    Format: PREFIX_YYYYMMDD_XXX where XXX is sequential
    Example: airdump_scan_20251225_143022, SWARM_20251225_143022
    
    Args:
        prefix: Optional prefix (e.g., "SWARM"). If None, uses "airdump_scan"
        
    Returns:
        Session ID string
    """
    date_str = datetime.utcnow().strftime("%Y%m%d")
    timestamp = datetime.utcnow().strftime("%H%M%S")
    
    if prefix:
        return f"{prefix}_{date_str}_{timestamp}"
    return f"airdump_scan_{date_str}_{timestamp}"


def normalize_mac(mac: str) -> str:
    """
    Normalize MAC address to uppercase with colons.
    
    Args:
        mac: MAC address in any format
        
    Returns:
        Normalized MAC (AA:BB:CC:DD:EE:FF)
    """
    # Remove all separators and convert to uppercase
    clean = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
    
    if len(clean) != 12:
        return mac  # Return original if invalid
        
    # Insert colons
    return ":".join(clean[i:i+2] for i in range(0, 12, 2))


def mac_matches_pattern(mac: str, pattern: str) -> bool:
    """
    Check if MAC address matches a pattern.
    
    Patterns can include:
    - Exact match: AA:BB:CC:DD:EE:FF
    - OUI prefix: AA:BB:CC:*
    - Wildcard: AA:BB:*
    
    Args:
        mac: MAC address to check
        pattern: Pattern to match against
        
    Returns:
        True if MAC matches pattern
    """
    mac = normalize_mac(mac)
    pattern = pattern.upper().replace("-", ":")
    
    # Exact match
    if "*" not in pattern:
        return mac == pattern
        
    # Prefix match
    prefix = pattern.rstrip("*").rstrip(":")
    return mac.startswith(prefix)


def get_oui_manufacturer(mac: str, oui_file: str = "oui/oui.txt") -> Optional[str]:
    """
    Look up manufacturer from OUI database.
    
    Args:
        mac: MAC address
        oui_file: Path to OUI database file
        
    Returns:
        Manufacturer name or None
    """
    mac = normalize_mac(mac)
    oui = mac[:8].replace(":", "-")
    
    oui_path = Path(oui_file)
    if not oui_path.exists():
        return None
        
    try:
        with open(oui_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if line.startswith(oui):
                    # Format: AA-BB-CC   (hex)		Manufacturer Name
                    parts = line.split("\t")
                    if len(parts) >= 3:
                        return parts[2].strip()
    except Exception:
        pass
        
    return None


def haversine_distance(
    lat1: float,
    lon1: float,
    lat2: float,
    lon2: float,
) -> float:
    """
    Calculate distance between two GPS coordinates in meters.
    
    Args:
        lat1, lon1: First point
        lat2, lon2: Second point
        
    Returns:
        Distance in meters
    """
    from math import radians, sin, cos, sqrt, atan2
    
    R = 6371000  # Earth radius in meters
    
    lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
    
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    
    a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
    c = 2 * atan2(sqrt(a), sqrt(1-a))
    
    return R * c


def get_disk_usage(path: str) -> Dict[str, float]:
    """
    Get disk usage statistics.
    
    Args:
        path: Path to check
        
    Returns:
        Dictionary with total, used, free in MB
    """
    stat = os.statvfs(path)
    
    total = (stat.f_blocks * stat.f_frsize) / (1024 * 1024)
    free = (stat.f_bavail * stat.f_frsize) / (1024 * 1024)
    used = total - free
    
    return {
        "total_mb": round(total, 2),
        "used_mb": round(used, 2),
        "free_mb": round(free, 2),
        "percent_used": round((used / total) * 100, 1) if total > 0 else 0,
    }


def get_file_size_mb(path: str) -> float:
    """Get file size in MB."""
    try:
        return os.path.getsize(path) / (1024 * 1024)
    except OSError:
        return 0.0


def get_directory_size_mb(path: str) -> float:
    """Get total size of directory in MB."""
    total = 0
    for dirpath, dirnames, filenames in os.walk(path):
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            try:
                total += os.path.getsize(filepath)
            except OSError:
                pass
    return total / (1024 * 1024)


def run_command(
    cmd: List[str],
    timeout: int = 30,
    capture_output: bool = True,
) -> subprocess.CompletedProcess:
    """
    Run shell command with timeout.
    
    Args:
        cmd: Command and arguments as list
        timeout: Timeout in seconds
        capture_output: Whether to capture stdout/stderr
        
    Returns:
        CompletedProcess instance
    """
    return subprocess.run(
        cmd,
        timeout=timeout,
        capture_output=capture_output,
        text=True,
    )


def is_interface_up(interface: str) -> bool:
    """Check if network interface is up."""
    try:
        result = run_command(["ip", "link", "show", interface])
        return "state UP" in result.stdout
    except Exception:
        return False


def is_monitor_mode(interface: str) -> bool:
    """Check if WiFi interface is in monitor mode."""
    try:
        result = run_command(["iwconfig", interface])
        return "Mode:Monitor" in result.stdout
    except Exception:
        return False


def set_interface_mode(interface: str, mode: str) -> bool:
    """
    Set WiFi interface to specified mode.
    
    Args:
        interface: WiFi interface name (e.g., wlan0, wlan0mon)
        mode: Mode to set ('managed' or 'monitor')
        
    Returns:
        True if mode was set successfully
    """
    if mode not in ("managed", "monitor"):
        raise ValueError(f"Invalid mode: {mode}. Must be 'managed' or 'monitor'")
    
    # Check if interface exists first
    try:
        result = subprocess.run(
            ["ip", "link", "show", interface],
            capture_output=True,
            timeout=5,
        )
        if result.returncode != 0:
            logger.debug(f"Interface {interface} does not exist, skipping mode change")
            return False
    except Exception:
        return False
    
    try:
        # Bring interface down
        subprocess.run(
            ["ip", "link", "set", interface, "down"],
            check=True,
            capture_output=True,
            timeout=10,
        )
        
        # Set mode using iw
        subprocess.run(
            ["iw", "dev", interface, "set", "type", mode],
            check=True,
            capture_output=True,
            timeout=10,
        )
        
        # Bring interface back up
        subprocess.run(
            ["ip", "link", "set", interface, "up"],
            check=True,
            capture_output=True,
            timeout=10,
        )
        
        return True
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to set interface {interface} to {mode} mode: {e}")
        return False
    except subprocess.TimeoutExpired:
        logger.error(f"Timeout setting interface {interface} to {mode} mode")
        return False
    except Exception as e:
        logger.error(f"Error setting interface mode: {e}")
        return False


def restore_managed_mode(interface: str = None) -> bool:
    """
    Restore WiFi interface to managed mode.
    
    Args:
        interface: Interface to restore. If None, auto-detects from saved state
                  or finds first monitor mode interface.
                  
    Returns:
        True if interface was restored (or no restore needed)
    """
    original_iface = None
    monitor_iface = interface
    
    # Try to get saved interface names from start_scan.sh
    if not monitor_iface:
        try:
            if os.path.exists("/tmp/airdump_monitor_iface"):
                with open("/tmp/airdump_monitor_iface") as f:
                    monitor_iface = f.read().strip()
            if os.path.exists("/tmp/airdump_original_iface"):
                with open("/tmp/airdump_original_iface") as f:
                    original_iface = f.read().strip()
        except Exception:
            pass
    
    # If still no interface, try to find one in monitor mode
    if not monitor_iface:
        try:
            result = subprocess.run(
                ["iw", "dev"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                current_iface = None
                for line in lines:
                    if "Interface" in line:
                        current_iface = line.split()[-1]
                    elif "type monitor" in line and current_iface:
                        monitor_iface = current_iface
                        break
        except Exception:
            pass
    
    if not monitor_iface:
        logger.debug("No monitor interface found to restore")
        return True  # Nothing to restore
    
    # Check if airmon-ng created a *mon interface
    if monitor_iface.endswith("mon"):
        # Try airmon-ng first
        try:
            result = subprocess.run(
                ["airmon-ng", "stop", monitor_iface],
                capture_output=True,
                timeout=30,
            )
            if result.returncode == 0:
                logger.info(f"Restored {monitor_iface} using airmon-ng")
                _cleanup_temp_files()
                _restart_network_manager()
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
    
    # Manual restoration using iw
    success = set_interface_mode(monitor_iface, "managed")
    
    if success:
        logger.info(f"Restored {monitor_iface} to managed mode")
        _cleanup_temp_files()
        _restart_network_manager()
        
    return success


def _cleanup_temp_files():
    """Remove temporary interface state files."""
    for path in ["/tmp/airdump_original_iface", "/tmp/airdump_monitor_iface"]:
        try:
            if os.path.exists(path):
                os.remove(path)
        except Exception:
            pass


def _restart_network_manager():
    """Restart NetworkManager if available to restore normal WiFi."""
    try:
        # Check if NetworkManager is active
        result = subprocess.run(
            ["systemctl", "is-active", "NetworkManager"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0 and "active" in result.stdout:
            subprocess.run(
                ["systemctl", "restart", "NetworkManager"],
                capture_output=True,
                timeout=30,
            )
            logger.info("Restarted NetworkManager")
    except Exception:
        pass  # NetworkManager not available or not running


def get_system_uptime() -> int:
    """Get system uptime in seconds."""
    try:
        with open("/proc/uptime", "r") as f:
            uptime = float(f.read().split()[0])
            return int(uptime)
    except Exception:
        return 0


def sync_filesystem():
    """Sync all filesystems."""
    try:
        subprocess.run(["sync"], timeout=30)
    except Exception:
        pass


class RateLimiter:
    """Simple rate limiter for API calls."""
    
    def __init__(self, calls_per_second: float = 10.0):
        self.min_interval = 1.0 / calls_per_second
        self.last_call = 0.0
        
    def wait(self):
        """Wait if necessary to respect rate limit."""
        import time
        elapsed = time.time() - self.last_call
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self.last_call = time.time()


def compute_hash(data: str, algorithm: str = "sha256") -> str:
    """
    Compute hash of string data.
    
    Args:
        data: String to hash
        algorithm: Hash algorithm (sha256, md5, etc.)
        
    Returns:
        Hex digest string
    """
    h = hashlib.new(algorithm)
    h.update(data.encode())
    return h.hexdigest()
