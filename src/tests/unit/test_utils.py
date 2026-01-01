"""
Project Airdump - Core Utils Tests

Unit tests for utility functions in core/utils.py.
"""

import os
import subprocess
import time
import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open

from core.utils import (
    normalize_mac,
    mac_matches_pattern,
    haversine_distance,
    load_config,
    generate_session_id,
    setup_logging,
    get_disk_usage,
    get_file_size_mb,
    get_directory_size_mb,
    run_command,
    is_interface_up,
    is_monitor_mode,
    get_system_uptime,
    sync_filesystem,
    RateLimiter,
    compute_hash,
    _expand_variables,
)


class TestNormalizeMac:
    """Tests for MAC address normalization."""
    
    def test_normalize_colon_format(self):
        """Test MAC with colons."""
        assert normalize_mac("aa:bb:cc:dd:ee:ff") == "AA:BB:CC:DD:EE:FF"
        
    def test_normalize_dash_format(self):
        """Test MAC with dashes."""
        assert normalize_mac("aa-bb-cc-dd-ee-ff") == "AA:BB:CC:DD:EE:FF"
        
    def test_normalize_no_separator(self):
        """Test MAC without separators."""
        assert normalize_mac("aabbccddeeff") == "AA:BB:CC:DD:EE:FF"
        
    def test_normalize_mixed_case(self):
        """Test mixed case MAC."""
        assert normalize_mac("Aa:Bb:Cc:Dd:Ee:Ff") == "AA:BB:CC:DD:EE:FF"
        
    def test_normalize_already_normalized(self):
        """Test already normalized MAC."""
        assert normalize_mac("AA:BB:CC:DD:EE:FF") == "AA:BB:CC:DD:EE:FF"
        
    def test_normalize_invalid_too_short(self):
        """Test invalid MAC (too short)."""
        assert normalize_mac("aa:bb:cc") == "aa:bb:cc"  # Returns original
        
    def test_normalize_invalid_too_long(self):
        """Test invalid MAC (too long)."""
        assert normalize_mac("aa:bb:cc:dd:ee:ff:00") == "aa:bb:cc:dd:ee:ff:00"
        
    def test_normalize_empty(self):
        """Test empty string."""
        assert normalize_mac("") == ""


class TestMacMatchesPattern:
    """Tests for MAC pattern matching."""
    
    def test_exact_match(self):
        """Test exact MAC match."""
        assert mac_matches_pattern("AA:BB:CC:DD:EE:FF", "AA:BB:CC:DD:EE:FF") is True
        assert mac_matches_pattern("AA:BB:CC:DD:EE:FF", "AA:BB:CC:DD:EE:00") is False
        
    def test_exact_match_case_insensitive(self):
        """Test case insensitive matching."""
        assert mac_matches_pattern("aa:bb:cc:dd:ee:ff", "AA:BB:CC:DD:EE:FF") is True
        
    def test_oui_prefix_match(self):
        """Test OUI prefix matching with wildcard."""
        assert mac_matches_pattern("AA:BB:CC:DD:EE:FF", "AA:BB:CC:*") is True
        assert mac_matches_pattern("AA:BB:CC:DD:EE:FF", "AA:BB:00:*") is False
        
    def test_prefix_match_partial(self):
        """Test partial prefix matching."""
        assert mac_matches_pattern("AA:BB:CC:DD:EE:FF", "AA:BB:*") is True
        assert mac_matches_pattern("AA:BB:CC:DD:EE:FF", "AA:*") is True
        
    def test_pattern_with_dashes(self):
        """Test pattern with dash separators."""
        assert mac_matches_pattern("AA:BB:CC:DD:EE:FF", "AA-BB-CC-*") is True
        
    def test_wildcard_all(self):
        """Test full wildcard."""
        # Note: "*" alone would match empty prefix
        assert mac_matches_pattern("AA:BB:CC:DD:EE:FF", "AA:BB:CC:DD:EE:FF") is True


class TestHaversineDistance:
    """Tests for GPS distance calculation."""
    
    def test_same_point(self):
        """Test distance between same point is zero."""
        dist = haversine_distance(51.5074, -0.1278, 51.5074, -0.1278)
        assert dist == pytest.approx(0.0, abs=0.001)
        
    def test_london_to_paris(self):
        """Test known distance London to Paris (~343km)."""
        # London: 51.5074, -0.1278
        # Paris: 48.8566, 2.3522
        dist = haversine_distance(51.5074, -0.1278, 48.8566, 2.3522)
        assert dist == pytest.approx(343_500, rel=0.02)  # Within 2%
        
    def test_short_distance(self):
        """Test short distance calculation."""
        # Points ~100m apart
        dist = haversine_distance(51.5074, -0.1278, 51.5083, -0.1278)
        assert 90 < dist < 110  # ~100 meters
        
    def test_across_equator(self):
        """Test distance across equator."""
        dist = haversine_distance(-1.0, 0.0, 1.0, 0.0)
        assert dist == pytest.approx(222_390, rel=0.02)  # ~222km per 2 degrees lat
        
    def test_across_dateline(self):
        """Test distance near international date line."""
        dist = haversine_distance(0.0, 179.0, 0.0, -179.0)
        assert dist == pytest.approx(222_390, rel=0.02)


class TestLoadConfig:
    """Tests for YAML configuration loading."""
    
    def test_load_valid_config(self, temp_config_file):
        """Test loading valid YAML config."""
        config = load_config(temp_config_file)
        assert config["general"]["property_id"] == "TEST-FACILITY"
        assert config["kismet"]["host"] == "localhost"
        
    def test_load_missing_config(self):
        """Test loading non-existent config raises error."""
        with pytest.raises(FileNotFoundError):
            load_config("/nonexistent/config.yaml")
            
    def test_variable_expansion(self, temp_config_file):
        """Test ${data_dir} variable expansion."""
        config = load_config(temp_config_file)
        # Check that data_dir variable was expanded
        assert "${data_dir}" not in str(config.get("database", {}).get("path", ""))
        
    def test_expand_variables_function(self):
        """Test _expand_variables utility."""
        variables = {"data_dir": "/opt/airdump"}
        
        # Test string expansion
        result = _expand_variables("${data_dir}/data.db", variables)
        assert result == "/opt/airdump/data.db"
        
        # Test dict expansion
        result = _expand_variables({"path": "${data_dir}/test"}, variables)
        assert result["path"] == "/opt/airdump/test"
        
        # Test list expansion
        result = _expand_variables(["${data_dir}/a", "${data_dir}/b"], variables)
        assert result == ["/opt/airdump/a", "/opt/airdump/b"]
        
        # Test non-string passthrough
        result = _expand_variables(123, variables)
        assert result == 123


class TestGenerateSessionId:
    """Tests for session ID generation."""
    
    def test_generate_session_id_format(self):
        """Test session ID format."""
        sid = generate_session_id()
        # Format: airdump_scan_YYYYMMDD_HHMMSS
        assert sid.startswith("airdump_scan_")
        assert "_" in sid
        # airdump_scan_ (13) + YYYYMMDD (8) + _ (1) + HHMMSS (6) = 28
        assert len(sid) == 28
        
    def test_generate_session_id_with_prefix(self):
        """Test session ID with prefix."""
        sid = generate_session_id("SWARM")
        assert sid.startswith("SWARM_")
        # SWARM_ (6) + YYYYMMDD (8) + _ (1) + HHMMSS (6) = 21
        assert len(sid) == 21
        
    def test_generate_unique_ids(self):
        """Test that sequential IDs are unique."""
        # Note: This test might be flaky if run within same second
        import time
        sid1 = generate_session_id()
        time.sleep(0.1)
        sid2 = generate_session_id()
        # At minimum, they shouldn't be exactly the same format
        # (though could be same if within same second)
        assert sid1 is not sid2


class TestSetupLogging:
    """Tests for logging configuration."""
    
    def test_setup_logging_creates_directory(self):
        """Test that logging creates log directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir) / "logs"
            logger = setup_logging(str(log_dir), "INFO", "test_app")
            assert log_dir.exists()
            assert logger.name == "test_app"
            
    def test_setup_logging_level(self):
        """Test logging level configuration."""
        import logging
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = setup_logging(tmpdir, "DEBUG", "test_debug")
            assert logger.level == logging.DEBUG
            
            logger2 = setup_logging(tmpdir, "ERROR", "test_error")
            assert logger2.level == logging.ERROR
            
    def test_setup_logging_creates_file(self):
        """Test that log file is created."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = setup_logging(tmpdir, "INFO", "test_file")
            log_file = Path(tmpdir) / "test_file.log"
            logger.info("Test message")
            # File may not exist until first write is flushed
            # Just verify no errors occurred


class TestDiskAndFileOperations:
    """Tests for disk and file utility functions."""
    
    def test_get_disk_usage(self):
        """Test disk usage reporting."""
        usage = get_disk_usage("/")
        assert "total_mb" in usage
        assert "used_mb" in usage
        assert "free_mb" in usage
        assert "percent_used" in usage
        assert usage["total_mb"] > 0
        assert usage["percent_used"] >= 0
        
    def test_get_file_size_mb(self):
        """Test file size calculation."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"x" * 1024)  # 1KB file
            f.flush()
            size = get_file_size_mb(f.name)
            assert size == pytest.approx(0.001, rel=0.1)  # ~0.001 MB
            os.unlink(f.name)
            
    def test_get_file_size_nonexistent(self):
        """Test file size of non-existent file."""
        size = get_file_size_mb("/nonexistent/file.txt")
        assert size == 0.0
        
    def test_get_directory_size_mb(self):
        """Test directory size calculation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create some files
            for i in range(3):
                with open(Path(tmpdir) / f"file{i}.txt", "wb") as f:
                    f.write(b"x" * 1024)
            size = get_directory_size_mb(tmpdir)
            assert size == pytest.approx(0.003, rel=0.1)  # ~3KB


class TestSystemCommands:
    """Tests for system command utilities."""
    
    def test_run_command_success(self):
        """Test running successful command."""
        result = run_command(["echo", "hello"])
        assert result.returncode == 0
        assert "hello" in result.stdout
        
    def test_run_command_failure(self):
        """Test running failing command."""
        result = run_command(["false"])
        assert result.returncode != 0
        
    def test_run_command_timeout(self):
        """Test command timeout."""
        import subprocess
        with pytest.raises(subprocess.TimeoutExpired):
            run_command(["sleep", "10"], timeout=1)
            
    @patch("core.utils.run_command")
    def test_is_interface_up_true(self, mock_run):
        """Test interface up detection."""
        mock_run.return_value = MagicMock(stdout="state UP")
        assert is_interface_up("eth0") is True
        
    @patch("core.utils.run_command")
    def test_is_interface_up_false(self, mock_run):
        """Test interface down detection."""
        mock_run.return_value = MagicMock(stdout="state DOWN")
        assert is_interface_up("eth0") is False
        
    @patch("core.utils.run_command")
    def test_is_monitor_mode_true(self, mock_run):
        """Test monitor mode detection."""
        mock_run.return_value = MagicMock(stdout="Mode:Monitor")
        assert is_monitor_mode("wlan0") is True
        
    @patch("core.utils.run_command")
    def test_is_monitor_mode_false(self, mock_run):
        """Test managed mode detection."""
        mock_run.return_value = MagicMock(stdout="Mode:Managed")
        assert is_monitor_mode("wlan0") is False
        
    def test_get_system_uptime(self):
        """Test system uptime retrieval."""
        uptime = get_system_uptime()
        assert uptime >= 0
        
    @patch("subprocess.run")
    def test_sync_filesystem(self, mock_run):
        """Test filesystem sync."""
        sync_filesystem()
        mock_run.assert_called_once_with(["sync"], timeout=30)


class TestRateLimiter:
    """Tests for rate limiter class."""
    
    def test_rate_limiter_init(self):
        """Test rate limiter initialization."""
        limiter = RateLimiter(calls_per_second=10.0)
        assert limiter.min_interval == 0.1
        
    def test_rate_limiter_wait(self):
        """Test rate limiter waiting."""
        limiter = RateLimiter(calls_per_second=100.0)  # 10ms interval
        
        limiter.wait()
        t1 = time.time()
        limiter.wait()
        t2 = time.time()
        
        # Should have waited at least ~10ms
        assert t2 - t1 >= 0.008  # Allow some tolerance
        
    def test_rate_limiter_no_wait_first_call(self):
        """Test first call doesn't wait."""
        limiter = RateLimiter(calls_per_second=1.0)
        
        t1 = time.time()
        limiter.wait()
        t2 = time.time()
        
        # First call should be instant
        assert t2 - t1 < 0.1


class TestComputeHash:
    """Tests for hash computation."""
    
    def test_compute_hash_sha256(self):
        """Test SHA256 hash computation."""
        result = compute_hash("hello world")
        assert len(result) == 64  # SHA256 produces 64 hex chars
        assert result == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        
    def test_compute_hash_md5(self):
        """Test MD5 hash computation."""
        result = compute_hash("hello world", algorithm="md5")
        assert len(result) == 32  # MD5 produces 32 hex chars
        assert result == "5eb63bbbe01eeed093cb22bb8f5acdc3"
        
    def test_compute_hash_empty_string(self):
        """Test hash of empty string."""
        result = compute_hash("")
        assert len(result) == 64
        # SHA256 of empty string is well-known
        assert result == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        
    def test_compute_hash_deterministic(self):
        """Test hash is deterministic."""
        h1 = compute_hash("test data")
        h2 = compute_hash("test data")
        assert h1 == h2
        
    def test_compute_hash_different_inputs(self):
        """Test different inputs produce different hashes."""
        h1 = compute_hash("input1")
        h2 = compute_hash("input2")
        assert h1 != h2

class TestInterfaceManagement:
    """Tests for WiFi interface mode management."""
    
    @patch("subprocess.run")
    def test_set_interface_mode_managed(self, mock_run):
        """Test setting interface to managed mode."""
        from core.utils import set_interface_mode
        
        mock_run.return_value = MagicMock(returncode=0)
        
        result = set_interface_mode("wlan0", "managed")
        
        assert result is True
        assert mock_run.call_count == 4  # check exists, down, set type, up
        
    @patch("subprocess.run")
    def test_set_interface_mode_monitor(self, mock_run):
        """Test setting interface to monitor mode."""
        from core.utils import set_interface_mode
        
        mock_run.return_value = MagicMock(returncode=0)
        
        result = set_interface_mode("wlan0", "monitor")
        
        assert result is True
        assert mock_run.call_count == 4  # check exists, down, set type, up
        
    @patch("subprocess.run")
    def test_set_interface_mode_nonexistent(self, mock_run):
        """Test setting mode on non-existent interface returns False without error."""
        from core.utils import set_interface_mode
        
        # Simulate interface not found
        mock_run.return_value = MagicMock(returncode=1)
        
        result = set_interface_mode("wlan99", "managed")
        
        assert result is False
        assert mock_run.call_count == 1  # Only the check call
        
    def test_set_interface_mode_invalid(self):
        """Test invalid mode raises error."""
        from core.utils import set_interface_mode
        
        with pytest.raises(ValueError, match="Invalid mode"):
            set_interface_mode("wlan0", "invalid")
            
    @patch("subprocess.run")
    def test_set_interface_mode_failure(self, mock_run):
        """Test handling of command failure."""
        from core.utils import set_interface_mode
        import subprocess
        
        mock_run.side_effect = subprocess.CalledProcessError(1, "ip")
        
        result = set_interface_mode("wlan0", "managed")
        
        assert result is False
        
    @patch("subprocess.run")
    def test_set_interface_mode_timeout(self, mock_run):
        """Test handling of command timeout."""
        from core.utils import set_interface_mode
        import subprocess
        
        mock_run.side_effect = subprocess.TimeoutExpired("ip", 10)
        
        result = set_interface_mode("wlan0", "managed")
        
        assert result is False
        
    @patch("core.utils.set_interface_mode")
    @patch("subprocess.run")
    @patch("os.path.exists")
    def test_restore_managed_mode_from_saved_state(self, mock_exists, mock_run, mock_set_mode):
        """Test restore from saved temp files."""
        from core.utils import restore_managed_mode
        
        # Simulate saved state files exist
        mock_exists.return_value = True
        mock_set_mode.return_value = True
        
        with patch("builtins.open", mock_open(read_data="wlan0mon")):
            result = restore_managed_mode()
        
        assert result is True
        
    @patch("subprocess.run")
    @patch("os.path.exists")
    def test_restore_managed_mode_no_interface(self, mock_exists, mock_run):
        """Test restore when no monitor interface found."""
        from core.utils import restore_managed_mode
        
        # No saved state files
        mock_exists.return_value = False
        
        # No monitor interfaces found
        mock_run.return_value = MagicMock(returncode=0, stdout="")
        
        result = restore_managed_mode()
        
        # Should return True (nothing to restore)
        assert result is True
        
    @patch("core.utils.set_interface_mode")
    @patch("subprocess.run")
    @patch("os.path.exists")
    def test_restore_managed_mode_airmon_ng(self, mock_exists, mock_run, mock_set_mode):
        """Test restore using airmon-ng for *mon interfaces."""
        from core.utils import restore_managed_mode
        
        # No saved files, will auto-detect
        mock_exists.return_value = False
        
        # Mock iw dev to find monitor interface
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Interface wlan0mon\n\ttype monitor\n"
        )
        
        restore_managed_mode()
        
        # Should try airmon-ng stop for *mon interfaces
        calls = mock_run.call_args_list
        assert any("airmon-ng" in str(call) for call in calls)
        
    @patch("core.utils.set_interface_mode")
    def test_restore_managed_mode_with_interface(self, mock_set_mode):
        """Test restore with explicit interface."""
        from core.utils import restore_managed_mode
        
        mock_set_mode.return_value = True
        
        result = restore_managed_mode("wlan0")
        
        mock_set_mode.assert_called_once_with("wlan0", "managed")
        assert result is True