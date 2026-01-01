"""
Project Airdump - tshark Packet Capture

Deep packet analysis using tshark for device fingerprinting.
Extracts Information Elements (IEs), vendor-specific data, and
protocol fingerprints from captured traffic.
"""

import logging
import subprocess
import threading
import json
import time
import os
import signal
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any, Callable
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class CaptureSession:
    """Active capture session metadata."""
    
    session_id: str
    interface: str
    output_file: str
    start_time: datetime
    filter_expr: Optional[str] = None
    channel: Optional[int] = None
    process: Optional[subprocess.Popen] = None
    packet_count: int = 0
    bytes_captured: int = 0
    
    
@dataclass
class ProbeRequest:
    """Parsed probe request data for fingerprinting."""
    
    source_mac: str
    timestamp: datetime
    ssid: str
    channel: int
    rssi: int
    
    # Information Elements
    supported_rates: List[int] = field(default_factory=list)
    extended_rates: List[int] = field(default_factory=list)
    ht_capabilities: Optional[str] = None
    vht_capabilities: Optional[str] = None
    vendor_ies: List[Dict[str, Any]] = field(default_factory=list)
    
    # Raw frame data
    sequence_number: int = 0
    frame_length: int = 0


@dataclass
class BeaconFrame:
    """Parsed beacon frame data."""
    
    bssid: str
    timestamp: datetime
    ssid: str
    channel: int
    rssi: int
    
    # Security info
    encryption: str = "Open"
    cipher: Optional[str] = None
    auth: Optional[str] = None
    
    # Capabilities
    supported_rates: List[int] = field(default_factory=list)
    ht_capabilities: Optional[str] = None
    vht_capabilities: Optional[str] = None
    vendor_ies: List[Dict[str, Any]] = field(default_factory=list)
    
    beacon_interval: int = 100


class TsharkCapture:
    """
    tshark-based packet capture for WiFi fingerprinting.
    
    Captures and parses:
    - Probe requests (client fingerprinting)
    - Beacon frames (AP fingerprinting)
    - Management frames for IE extraction
    """
    
    def __init__(
        self,
        interface: str = "",
        output_dir: str = "data/pcap",
        max_file_size_mb: int = 100,
        rotate_files: bool = True,
    ):
        """
        Initialize tshark capture.
        
        Args:
            interface: Monitor mode interface (auto-detect if empty)
            output_dir: Directory for pcap files
            max_file_size_mb: Max pcap file size before rotation
            rotate_files: Enable file rotation
        """
        self.interface = interface or self._detect_monitor_interface()
        self.output_dir = Path(output_dir)
        self.max_file_size_mb = max_file_size_mb
        self.rotate_files = rotate_files
        
        # Ensure output directory exists
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self._active_session: Optional[CaptureSession] = None
        self._lock = threading.Lock()
        
        # Callbacks for real-time processing
        self._probe_callbacks: List[Callable[[ProbeRequest], None]] = []
        self._beacon_callbacks: List[Callable[[BeaconFrame], None]] = []
    
    def _detect_monitor_interface(self) -> str:
        """Auto-detect a monitor mode interface."""
        # Check saved interface from start_scan.sh
        if os.path.exists("/tmp/airdump_monitor_iface"):
            try:
                with open("/tmp/airdump_monitor_iface") as f:
                    iface = f.read().strip()
                    if iface and self._is_monitor_mode(iface):
                        logger.info(f"Using saved monitor interface: {iface}")
                        return iface
            except Exception:
                pass
        
        # Try common monitor interface names
        for iface in ["wlan0mon", "wlan1mon", "wlp3s0mon"]:
            if self._is_monitor_mode(iface):
                logger.info(f"Found monitor interface: {iface}")
                return iface
        
        # Check all interfaces for monitor mode
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
                        logger.info(f"Found monitor interface: {current_iface}")
                        return current_iface
        except Exception as e:
            logger.debug(f"Error detecting interfaces: {e}")
        
        logger.warning("No monitor interface found")
        return "wlan0mon"  # Default fallback
    
    def _is_monitor_mode(self, interface: str) -> bool:
        """Check if interface exists and is in monitor mode."""
        try:
            result = subprocess.run(
                ["iw", "dev", interface, "info"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0 and "type monitor" in result.stdout
        except Exception:
            return False
        
    def _check_tshark(self) -> bool:
        """Check if tshark is available."""
        try:
            result = subprocess.run(
                ["tshark", "--version"],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
            
    def _check_interface(self) -> bool:
        """Check if interface exists and is in monitor mode."""
        return self._is_monitor_mode(self.interface)
            
    def start_capture(
        self,
        session_id: str,
        filter_expr: Optional[str] = None,
        channel: Optional[int] = None,
    ) -> bool:
        """
        Start packet capture.
        
        Args:
            session_id: Scan session ID
            filter_expr: BPF filter expression
            channel: Optional channel to lock to
            
        Returns:
            True if capture started
        """
        if self._active_session:
            logger.warning("Capture already active")
            return False
            
        if not self._check_tshark():
            logger.error("tshark not found")
            return False
            
        if not self._check_interface():
            logger.error(f"Interface {self.interface} not available or not in monitor mode")
            return False
            
        # Generate output filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"airdump_capture_{session_id}_{timestamp}.pcapng"
        
        # Build tshark command
        cmd = [
            "tshark",
            "-i", self.interface,
            "-w", str(output_file),
            "-F", "pcapng",  # Output format
        ]
        
        if filter_expr:
            cmd.extend(["-f", filter_expr])
            
        if self.rotate_files:
            # File rotation settings
            cmd.extend([
                "-b", f"filesize:{self.max_file_size_mb * 1024}",  # KB
                "-b", "files:10",  # Keep last 10 files
            ])
            
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            
            with self._lock:
                self._active_session = CaptureSession(
                    session_id=session_id,
                    interface=self.interface,
                    output_file=str(output_file),
                    start_time=datetime.now(),
                    filter_expr=filter_expr,
                    channel=channel,
                    process=process,
                )
                
            logger.info(f"Started capture: {output_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start capture: {e}")
            return False
            
    def stop_capture(self) -> Optional[str]:
        """
        Stop active capture.
        
        Returns:
            Path to captured pcap file
        """
        with self._lock:
            if not self._active_session:
                return None
                
            session = self._active_session
            
            if session.process:
                # Send SIGTERM for graceful shutdown
                session.process.send_signal(signal.SIGTERM)
                try:
                    session.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    session.process.kill()
                    
            output_file = session.output_file
            self._active_session = None
            
        logger.info(f"Stopped capture: {output_file}")
        return output_file
        
    def is_capturing(self) -> bool:
        """Check if capture is active."""
        with self._lock:
            return self._active_session is not None
            
    def get_capture_stats(self) -> Optional[dict]:
        """Get statistics for active capture."""
        with self._lock:
            if not self._active_session:
                return None
                
            session = self._active_session
            
            # Get file size
            try:
                file_size = Path(session.output_file).stat().st_size
            except:
                file_size = 0
                
            return {
                "session_id": session.session_id,
                "interface": session.interface,
                "output_file": session.output_file,
                "start_time": session.start_time.isoformat(),
                "duration_seconds": (datetime.now() - session.start_time).total_seconds(),
                "file_size_bytes": file_size,
            }
            
    def parse_pcap(
        self,
        pcap_file: str,
        extract_probes: bool = True,
        extract_beacons: bool = True,
    ) -> Dict[str, List]:
        """
        Parse pcap file and extract fingerprint data.
        
        Args:
            pcap_file: Path to pcap file
            extract_probes: Extract probe requests
            extract_beacons: Extract beacon frames
            
        Returns:
            Dictionary with 'probes' and 'beacons' lists
        """
        result = {"probes": [], "beacons": []}
        
        if not Path(pcap_file).exists():
            logger.error(f"Pcap file not found: {pcap_file}")
            return result
            
        if extract_probes:
            result["probes"] = self._extract_probe_requests(pcap_file)
            
        if extract_beacons:
            result["beacons"] = self._extract_beacons(pcap_file)
            
        return result
        
    def _extract_probe_requests(self, pcap_file: str) -> List[ProbeRequest]:
        """Extract probe requests from pcap file."""
        probes = []
        
        # tshark fields for probe request analysis
        fields = [
            "frame.time_epoch",
            "wlan.sa",
            "wlan.ssid",
            "wlan.channel",
            "wlan_radio.signal_dbm",
            "wlan.seq",
            "frame.len",
            "wlan.supported_rates",
            "wlan.extended_supported_rates",
            "wlan.ht.capabilities",
            "wlan.vht.capabilities",
            "wlan.tag.vendor.oui.type",
            "wlan.tag.vendor.data",
        ]
        
        field_args = []
        for f in fields:
            field_args.extend(["-e", f])
            
        cmd = [
            "tshark",
            "-r", pcap_file,
            "-Y", "wlan.fc.type_subtype == 0x04",  # Probe Request
            "-T", "json",
        ] + field_args
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )
            
            if result.returncode != 0:
                logger.error(f"tshark error: {result.stderr}")
                return probes
                
            data = json.loads(result.stdout) if result.stdout else []
            
            for packet in data:
                layers = packet.get("_source", {}).get("layers", {})
                
                probe = ProbeRequest(
                    source_mac=self._get_field(layers, "wlan.sa", "00:00:00:00:00:00"),
                    timestamp=datetime.fromtimestamp(
                        float(self._get_field(layers, "frame.time_epoch", "0"))
                    ),
                    ssid=self._get_field(layers, "wlan.ssid", ""),
                    channel=int(self._get_field(layers, "wlan.channel", "0")),
                    rssi=int(self._get_field(layers, "wlan_radio.signal_dbm", "-100")),
                    sequence_number=int(self._get_field(layers, "wlan.seq", "0")),
                    frame_length=int(self._get_field(layers, "frame.len", "0")),
                )
                
                # Parse supported rates
                rates_str = self._get_field(layers, "wlan.supported_rates", "")
                if rates_str:
                    probe.supported_rates = self._parse_rates(rates_str)
                    
                ext_rates_str = self._get_field(layers, "wlan.extended_supported_rates", "")
                if ext_rates_str:
                    probe.extended_rates = self._parse_rates(ext_rates_str)
                    
                # HT/VHT capabilities
                probe.ht_capabilities = self._get_field(layers, "wlan.ht.capabilities", None)
                probe.vht_capabilities = self._get_field(layers, "wlan.vht.capabilities", None)
                
                probes.append(probe)
                
        except subprocess.TimeoutExpired:
            logger.error(f"tshark timeout parsing {pcap_file}")
        except json.JSONDecodeError as e:
            logger.error(f"JSON parse error: {e}")
        except Exception as e:
            logger.error(f"Probe extraction error: {e}")
            
        return probes
        
    def _extract_beacons(self, pcap_file: str) -> List[BeaconFrame]:
        """Extract beacon frames from pcap file."""
        beacons = []
        
        fields = [
            "frame.time_epoch",
            "wlan.bssid",
            "wlan.ssid",
            "wlan.channel",
            "wlan_radio.signal_dbm",
            "wlan.fixed.beacon",
            "wlan.supported_rates",
            "wlan.ht.capabilities",
            "wlan.vht.capabilities",
            "wlan.rsn.pcs.type",
            "wlan.rsn.akms.type",
        ]
        
        field_args = []
        for f in fields:
            field_args.extend(["-e", f])
            
        cmd = [
            "tshark",
            "-r", pcap_file,
            "-Y", "wlan.fc.type_subtype == 0x08",  # Beacon
            "-T", "json",
        ] + field_args
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )
            
            if result.returncode != 0:
                logger.error(f"tshark error: {result.stderr}")
                return beacons
                
            data = json.loads(result.stdout) if result.stdout else []
            
            # Track unique BSSIDs (only keep latest beacon per AP)
            seen_bssids: Dict[str, BeaconFrame] = {}
            
            for packet in data:
                layers = packet.get("_source", {}).get("layers", {})
                
                bssid = self._get_field(layers, "wlan.bssid", "00:00:00:00:00:00")
                
                beacon = BeaconFrame(
                    bssid=bssid,
                    timestamp=datetime.fromtimestamp(
                        float(self._get_field(layers, "frame.time_epoch", "0"))
                    ),
                    ssid=self._get_field(layers, "wlan.ssid", ""),
                    channel=int(self._get_field(layers, "wlan.channel", "0")),
                    rssi=int(self._get_field(layers, "wlan_radio.signal_dbm", "-100")),
                    beacon_interval=int(self._get_field(layers, "wlan.fixed.beacon", "100")),
                )
                
                # Parse rates
                rates_str = self._get_field(layers, "wlan.supported_rates", "")
                if rates_str:
                    beacon.supported_rates = self._parse_rates(rates_str)
                    
                # Capabilities
                beacon.ht_capabilities = self._get_field(layers, "wlan.ht.capabilities", None)
                beacon.vht_capabilities = self._get_field(layers, "wlan.vht.capabilities", None)
                
                # Security
                cipher = self._get_field(layers, "wlan.rsn.pcs.type", None)
                auth = self._get_field(layers, "wlan.rsn.akms.type", None)
                
                if cipher or auth:
                    beacon.encryption = "WPA2/WPA3"
                    beacon.cipher = cipher
                    beacon.auth = auth
                    
                seen_bssids[bssid] = beacon
                
            beacons = list(seen_bssids.values())
            
        except subprocess.TimeoutExpired:
            logger.error(f"tshark timeout parsing {pcap_file}")
        except json.JSONDecodeError as e:
            logger.error(f"JSON parse error: {e}")
        except Exception as e:
            logger.error(f"Beacon extraction error: {e}")
            
        return beacons
        
    def _get_field(self, layers: dict, field: str, default: Any) -> Any:
        """Extract field from tshark JSON layers."""
        # Fields may be nested or direct
        for key, value in layers.items():
            if field in key:
                if isinstance(value, list):
                    return value[0] if value else default
                return value
            if isinstance(value, dict):
                result = self._get_field(value, field, None)
                if result is not None:
                    return result
        return default
        
    def _parse_rates(self, rates_str: str) -> List[int]:
        """Parse rates string into list of integers."""
        rates = []
        try:
            # Rates may be comma-separated or in various formats
            for part in str(rates_str).replace(",", " ").split():
                # Remove units like "Mb/s"
                num = ''.join(c for c in part if c.isdigit() or c == '.')
                if num:
                    rates.append(int(float(num)))
        except:
            pass
        return rates
        
    def extract_vendor_ies(self, pcap_file: str) -> Dict[str, List[dict]]:
        """
        Extract vendor-specific Information Elements by MAC.
        
        Args:
            pcap_file: Path to pcap file
            
        Returns:
            Dictionary mapping MAC addresses to vendor IE lists
        """
        vendor_ies: Dict[str, List[dict]] = {}
        
        cmd = [
            "tshark",
            "-r", pcap_file,
            "-Y", "wlan.tag.number == 221",  # Vendor Specific IE
            "-T", "json",
            "-e", "wlan.sa",
            "-e", "wlan.tag.vendor.oui.type",
            "-e", "wlan.tag.vendor.data",
            "-e", "wlan.tag.oui",
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )
            
            if result.returncode != 0:
                return vendor_ies
                
            data = json.loads(result.stdout) if result.stdout else []
            
            for packet in data:
                layers = packet.get("_source", {}).get("layers", {})
                mac = self._get_field(layers, "wlan.sa", None)
                
                if not mac:
                    continue
                    
                if mac not in vendor_ies:
                    vendor_ies[mac] = []
                    
                ie = {
                    "oui": self._get_field(layers, "wlan.tag.oui", ""),
                    "type": self._get_field(layers, "wlan.tag.vendor.oui.type", ""),
                    "data": self._get_field(layers, "wlan.tag.vendor.data", ""),
                }
                
                vendor_ies[mac].append(ie)
                
        except Exception as e:
            logger.error(f"Vendor IE extraction error: {e}")
            
        return vendor_ies
        
    def get_unique_macs(self, pcap_file: str) -> List[str]:
        """
        Get list of unique source MACs from pcap.
        
        Args:
            pcap_file: Path to pcap file
            
        Returns:
            List of unique MAC addresses
        """
        macs = set()
        
        cmd = [
            "tshark",
            "-r", pcap_file,
            "-T", "fields",
            "-e", "wlan.sa",
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    mac = line.strip()
                    if mac and mac != "":
                        macs.add(mac.upper())
                        
        except Exception as e:
            logger.error(f"MAC extraction error: {e}")
            
        return list(macs)
        
    def register_probe_callback(self, callback: Callable[[ProbeRequest], None]):
        """Register callback for real-time probe request processing."""
        self._probe_callbacks.append(callback)
        
    def register_beacon_callback(self, callback: Callable[[BeaconFrame], None]):
        """Register callback for real-time beacon processing."""
        self._beacon_callbacks.append(callback)


class LivePacketParser:
    """
    Real-time packet parsing using tshark live capture.
    
    Parses packets on-the-fly for immediate fingerprinting.
    """
    
    def __init__(
        self,
        interface: str = "wlan0mon",
        callback: Optional[Callable[[dict], None]] = None,
    ):
        """
        Initialize live parser.
        
        Args:
            interface: Monitor mode interface
            callback: Function to call for each parsed packet
        """
        self.interface = interface
        self.callback = callback
        
        self._process: Optional[subprocess.Popen] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None
        
    def start(self) -> bool:
        """Start live packet parsing."""
        if self._running:
            return True
            
        # Fields to extract
        fields = [
            "frame.time_epoch",
            "wlan.fc.type_subtype",
            "wlan.sa",
            "wlan.da",
            "wlan.bssid",
            "wlan.ssid",
            "wlan.channel",
            "wlan_radio.signal_dbm",
            "wlan.supported_rates",
            "wlan.ht.capabilities",
        ]
        
        field_args = []
        for f in fields:
            field_args.extend(["-e", f])
            
        cmd = [
            "tshark",
            "-i", self.interface,
            "-T", "ek",  # Elasticsearch JSON format (one JSON per line)
            "-l",  # Line buffered
        ] + field_args
        
        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,  # Line buffered
            )
            
            self._running = True
            self._thread = threading.Thread(target=self._read_loop, daemon=True)
            self._thread.start()
            
            logger.info("Live packet parser started")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start live parser: {e}")
            return False
            
    def stop(self):
        """Stop live packet parsing."""
        self._running = False
        
        if self._process:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
            self._process = None
            
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
            
        logger.info("Live packet parser stopped")
        
    def _read_loop(self):
        """Read and parse packets from tshark output."""
        while self._running and self._process:
            try:
                line = self._process.stdout.readline()
                if not line:
                    break
                    
                # Parse JSON line
                try:
                    data = json.loads(line)
                    if self.callback:
                        self.callback(data)
                except json.JSONDecodeError:
                    continue
                    
            except Exception as e:
                logger.debug(f"Read error: {e}")
                break
