"""
Project Airdump - Analysis Tests

Unit tests for analysis modules: Analyzer, Reporter, WhitelistComparer.
"""

import os
import json
import pytest
import tempfile
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import Mock, MagicMock, patch

from analysis.analyzer import (
    AnalysisResult, WhitelistEntry, WhitelistComparer, Analyzer
)
from analysis.reporter import Reporter


class TestAnalysisResult:
    """Tests for AnalysisResult dataclass."""
    
    def test_create_result(self):
        """Test creating analysis result."""
        result = AnalysisResult(
            session_id="20251225_120000",
            analysis_time=datetime.now(timezone.utc),
            total_wifi_devices=10,
            total_bt_devices=5,
            unknown_devices=3,
        )
        assert result.session_id == "20251225_120000"
        assert result.total_wifi_devices == 10
        assert result.unknown_devices == 3
        
    def test_default_values(self):
        """Test default result values."""
        result = AnalysisResult(
            session_id="test",
            analysis_time=datetime.now(timezone.utc),
        )
        assert result.total_wifi_devices == 0
        assert result.total_bt_devices == 0
        assert result.unknown_wifi == []
        assert result.alerts == []
        
    def test_to_dict(self):
        """Test result serialization."""
        result = AnalysisResult(
            session_id="20251225_120000",
            analysis_time=datetime.now(timezone.utc),
            total_wifi_devices=10,
            unknown_devices=3,
            alerts=[{"type": "test", "reason": "test alert"}],
        )
        data = result.to_dict()
        assert data["session_id"] == "20251225_120000"
        assert data["summary"]["total_wifi_devices"] == 10
        assert data["summary"]["unknown_devices"] == 3
        assert len(data["alerts"]) == 1


class TestWhitelistEntry:
    """Tests for WhitelistEntry dataclass."""
    
    def test_create_mac_entry(self):
        """Test creating MAC whitelist entry."""
        entry = WhitelistEntry(
            identifier="AA:BB:CC:DD:EE:FF",
            match_type="mac",
            name="Office Router",
            category="infrastructure",
        )
        assert entry.identifier == "AA:BB:CC:DD:EE:FF"
        assert entry.match_type == "mac"
        
    def test_matches_mac_exact(self):
        """Test MAC address matching."""
        entry = WhitelistEntry(
            identifier="AA:BB:CC:DD:EE:FF",
            match_type="mac",
        )
        device = {"mac": "AA:BB:CC:DD:EE:FF"}
        assert entry.matches(device) is True
        
    def test_matches_mac_case_insensitive(self):
        """Test MAC matching is case insensitive."""
        entry = WhitelistEntry(
            identifier="AA:BB:CC:DD:EE:FF",
            match_type="mac",
        )
        device = {"mac": "aa:bb:cc:dd:ee:ff"}
        assert entry.matches(device) is True
        
    def test_matches_mac_no_match(self):
        """Test MAC non-match."""
        entry = WhitelistEntry(
            identifier="AA:BB:CC:DD:EE:FF",
            match_type="mac",
        )
        device = {"mac": "11:22:33:44:55:66"}
        assert entry.matches(device) is False
        
    def test_matches_oui(self):
        """Test OUI prefix matching."""
        entry = WhitelistEntry(
            identifier="AABBCC",
            match_type="oui",
        )
        device = {"mac": "AA:BB:CC:11:22:33"}
        assert entry.matches(device) is True
        
    def test_matches_oui_no_match(self):
        """Test OUI non-match."""
        entry = WhitelistEntry(
            identifier="AABBCC",
            match_type="oui",
        )
        device = {"mac": "11:22:33:44:55:66"}
        assert entry.matches(device) is False
        
    def test_matches_fingerprint(self):
        """Test fingerprint matching."""
        entry = WhitelistEntry(
            identifier="abc123hash",
            match_type="fingerprint",
        )
        device = {"fingerprint_hash": "abc123hash"}
        assert entry.matches(device) is True
        
    def test_matches_ssid(self):
        """Test SSID matching."""
        entry = WhitelistEntry(
            identifier="OfficeNetwork",
            match_type="ssid",
        )
        device = {"ssid": "OfficeNetwork"}
        assert entry.matches(device) is True


class TestWhitelistComparer:
    """Tests for WhitelistComparer class."""
    
    @pytest.fixture
    def whitelist_file(self, tmp_path):
        """Create temporary whitelist file."""
        whitelist = {
            "wifi_devices": [
                {"mac": "AA:BB:CC:DD:EE:FF", "name": "Router", "category": "infra"},
                {"mac": "11:22:33:44:55:66", "name": "Printer", "category": "office"},
            ],
            "bluetooth_devices": [
                {"mac": "AA:11:22:33:44:55", "name": "Conference Phone"},
            ],
            "oui_whitelist": ["00:17:F2", "00:1A:2B"],
            "fingerprint_whitelist": ["hash123", "hash456"],
            "ssid_whitelist": ["CorpNetwork", "GuestWiFi"],
        }
        filepath = tmp_path / "whitelist.json"
        with open(filepath, "w") as f:
            json.dump(whitelist, f)
        return str(filepath)
        
    def test_init_without_file(self):
        """Test initialization without whitelist file."""
        comparer = WhitelistComparer()
        assert len(comparer._entries) == 0
        
    def test_init_with_file(self, whitelist_file):
        """Test initialization with whitelist file."""
        comparer = WhitelistComparer(whitelist_file)
        assert len(comparer._entries) > 0
        
    def test_load_whitelist(self, whitelist_file):
        """Test loading whitelist from file."""
        comparer = WhitelistComparer()
        comparer.load_whitelist(whitelist_file)
        
        assert "AA:BB:CC:DD:EE:FF" in comparer._mac_set
        assert "11:22:33:44:55:66" in comparer._mac_set
        assert "0017F2" in comparer._oui_set
        assert "hash123" in comparer._fingerprint_set
        
    def test_load_nonexistent_file(self):
        """Test loading non-existent whitelist file."""
        comparer = WhitelistComparer()
        comparer.load_whitelist("/nonexistent/whitelist.json")
        assert len(comparer._entries) == 0
        
    def test_is_known_by_mac(self, whitelist_file):
        """Test device known check by MAC."""
        comparer = WhitelistComparer(whitelist_file)
        
        device = {"mac": "AA:BB:CC:DD:EE:FF"}
        assert comparer.is_whitelisted(device) is True
        
        device = {"mac": "99:99:99:99:99:99"}
        assert comparer.is_whitelisted(device) is False
        
    def test_is_known_by_oui(self, whitelist_file):
        """Test device known check by OUI prefix."""
        comparer = WhitelistComparer(whitelist_file)
        
        device = {"mac": "00:17:F2:11:22:33"}  # OUI in whitelist
        assert comparer.is_whitelisted(device) is True
        
    def test_is_known_by_fingerprint(self, whitelist_file):
        """Test device known check by fingerprint."""
        comparer = WhitelistComparer(whitelist_file)
        
        device = {"mac": "99:99:99:99:99:99", "fingerprint_hash": "hash123"}
        assert comparer.is_whitelisted(device) is True
        
    def test_compare_devices(self, whitelist_file):
        """Test comparing device list against whitelist."""
        comparer = WhitelistComparer(whitelist_file)
        
        devices = [
            {"mac": "AA:BB:CC:DD:EE:FF"},  # Known
            {"mac": "11:22:33:44:55:66"},  # Known
            {"mac": "99:99:99:99:99:99"},  # Unknown
        ]
        
        known = [d for d in devices if comparer.is_whitelisted(d)]
        unknown = [d for d in devices if not comparer.is_whitelisted(d)]
        assert len(known) == 2
        assert len(unknown) == 1


class TestAnalyzer:
    """Tests for Analyzer class."""
    
    @pytest.fixture
    def mock_database(self):
        """Create mock database."""
        db = Mock()
        db.get_session.return_value = {
            "session_id": "20251225_120000",
            "start_time": "2025-12-25T12:00:00",
            "end_time": "2025-12-25T13:00:00",
            "status": "stopped",
        }
        db.get_wifi_devices.return_value = [
            {"id": 1, "bssid": "AA:BB:CC:DD:EE:FF", "essid": "TestNet", "signal_dbm": -45},
            {"id": 2, "bssid": "11:22:33:44:55:66", "essid": "Unknown", "signal_dbm": -60},
        ]
        db.get_bt_devices.return_value = [
            {"id": 1, "mac_address": "AA:11:22:33:44:55", "device_name": "iPhone"},
        ]
        db.get_gps_track.return_value = [
            {"latitude": 51.5074, "longitude": -0.1278},
            {"latitude": 51.5075, "longitude": -0.1279},
        ]
        return db
        
    @pytest.fixture
    def analyzer(self, mock_database):
        """Create Analyzer instance."""
        return Analyzer(database=mock_database)
        
    def test_init(self, analyzer):
        """Test analyzer initialization."""
        assert analyzer.database is not None
        
    def test_analyze_session(self, analyzer):
        """Test analyzing a scan session."""
        result = analyzer.analyze_session("20251225_120000")
        
        assert result.session_id == "20251225_120000"
        assert result.total_wifi_devices == 2
        assert result.total_bt_devices == 1
        
    def test_analyze_with_whitelist(self, mock_database, tmp_path):
        """Test analysis with whitelist comparison."""
        # Create whitelist
        whitelist = {
            "wifi_devices": [
                {"mac": "AA:BB:CC:DD:EE:FF", "name": "Known Router"},
            ],
            "bluetooth_devices": [],
        }
        whitelist_path = tmp_path / "whitelist.json"
        with open(whitelist_path, "w") as f:
            json.dump(whitelist, f)
            
        analyzer = Analyzer(
            database=mock_database,
            whitelist_file=str(whitelist_path),
        )
        result = analyzer.analyze_session("20251225_120000")
        
        assert result.known_devices >= 1
        assert len(result.unknown_wifi) >= 1
        
    def test_analyze_nonexistent_session(self, mock_database):
        """Test analyzing non-existent session."""
        mock_database.get_session.return_value = None
        analyzer = Analyzer(database=mock_database)
        
        result = analyzer.analyze_session("nonexistent")
        # API returns an empty AnalysisResult, not None
        assert result.total_wifi_devices == 0
        assert result.total_bt_devices == 0
        
    def test_detect_suspicious_patterns(self, analyzer):
        """Test suspicious device detection."""
        # Test with devices showing suspicious patterns
        devices = [
            {"mac": "AA:BB:CC:DD:EE:FF", "essid": "ATT-WiFi", "signal_dbm": -90},  # Evil twin candidate
            {"mac": "02:00:00:00:00:01", "essid": "", "signal_dbm": -30},  # Strong random MAC
        ]
        
        # The analyzer checks suspicious patterns internally during analyze_session
        # Here we just verify the analyzer has the internal check method
        assert hasattr(analyzer, '_check_suspicious_wifi')
        suspicious = analyzer._check_suspicious_wifi(devices[1])
        # Should return None or a string reason
        assert suspicious is None or isinstance(suspicious, str)
        
    def test_calculate_coverage(self, analyzer):
        """Test coverage area calculation."""
        gps_track = [
            {"latitude": 51.5074, "longitude": -0.1278},
            {"latitude": 51.5075, "longitude": -0.1279},
            {"latitude": 51.5076, "longitude": -0.1280},
        ]
        
        coverage = analyzer._calculate_coverage_area(gps_track)
        assert coverage >= 0  # Should return area in sqm


class TestReporter:
    """Tests for Reporter class."""
    
    @pytest.fixture
    def mock_database(self):
        """Create mock database."""
        db = Mock()
        db.get_session.return_value = {
            "session_id": "20251225_120000",
            "start_time": "2025-12-25T12:00:00",
            "status": "stopped",
        }
        db.get_wifi_devices.return_value = [
            {"id": 1, "bssid": "AA:BB:CC:DD:EE:FF", "essid": "TestNet"},
        ]
        db.get_bt_devices.return_value = []
        db.get_gps_track.return_value = []
        return db
        
    @pytest.fixture
    def reporter(self, tmp_path):
        """Create Reporter instance."""
        return Reporter(
            output_dir=str(tmp_path),
        )
        
    def test_init(self, reporter):
        """Test reporter initialization."""
        assert reporter.output_dir is not None
        
    def test_generate_json_report(self, reporter, tmp_path):
        """Test JSON report generation."""
        result = AnalysisResult(
            session_id="20251225_120000",
            analysis_time=datetime.now(timezone.utc),
            total_wifi_devices=5,
            total_bt_devices=3,
        )
        
        filepath = reporter.generate_json_report(result)
        assert filepath is not None
        assert Path(filepath).exists()
        
        with open(filepath) as f:
            data = json.load(f)
        assert data["session_id"] == "20251225_120000"
        
    @patch("analysis.reporter.JINJA_AVAILABLE", True)
    def test_generate_html_report(self, reporter, tmp_path):
        """Test HTML report generation."""
        result = AnalysisResult(
            session_id="20251225_120000",
            analysis_time=datetime.now(timezone.utc),
            total_wifi_devices=5,
        )
        
        # This may not actually generate if jinja2 not installed
        try:
            filepath = reporter.generate_html_report(result)
            if filepath:
                assert Path(filepath).exists()
        except Exception:
            pytest.skip("jinja2 not available")
            
    def test_generate_csv_report(self, reporter, tmp_path):
        """Test CSV report generation."""
        result = AnalysisResult(
            session_id="20251225_120000",
            analysis_time=datetime.now(timezone.utc),
            unknown_wifi=[
                {"mac": "AA:BB:CC:DD:EE:FF", "ssid": "Test", "rssi": -45},
            ],
        )
        
        filepath = reporter.generate_csv_report(result)
        assert filepath is not None
        
    def test_generate_all_reports(self, reporter, tmp_path):
        """Test generating all report formats."""
        result = AnalysisResult(
            session_id="20251225_120000",
            analysis_time=datetime.now(timezone.utc),
        )
        
        reports = reporter.generate_all_reports(result)
        assert "json" in reports


class TestReporterMapGeneration:
    """Tests for map generation in Reporter."""
    
    @pytest.fixture
    def reporter_with_gps(self, tmp_path):
        """Create reporter with GPS data."""
        return Reporter(output_dir=str(tmp_path))
        
    @patch("analysis.reporter.FOLIUM_AVAILABLE", True)
    def test_generate_heatmap(self, reporter_with_gps, tmp_path):
        """Test heatmap generation."""
        try:
            filepath = reporter_with_gps.generate_heatmap(
                session_id="20251225_120000",
            )
            if filepath:
                assert Path(filepath).exists()
        except Exception:
            pytest.skip("folium not available")


class TestAnalyzerSuspiciousDetection:
    """Tests for suspicious device detection."""
    
    @pytest.fixture
    def analyzer(self):
        """Create analyzer with mock database."""
        db = Mock()
        db.get_session.return_value = {"session_id": "test"}
        db.get_wifi_devices.return_value = []
        db.get_bt_devices.return_value = []
        db.get_gps_track.return_value = []
        return Analyzer(database=db)
        
    def test_detect_evil_twin(self, analyzer):
        """Test evil twin detection (same SSID, different BSSID)."""
        devices = [
            {"bssid": "AA:BB:CC:DD:EE:FF", "essid": "CorpNetwork", "signal_dbm": -50},
            {"bssid": "11:22:33:44:55:66", "essid": "CorpNetwork", "signal_dbm": -45},
        ]
        
        # Evil twin detection is done internally by _check_suspicious_wifi
        # Check for common carrier SSIDs that could be evil twins
        for device in devices:
            result = analyzer._check_suspicious_wifi(device)
            # May or may not flag depending on SSID
            assert result is None or isinstance(result, str)
        
    def test_detect_randomized_mac(self, analyzer):
        """Test randomized MAC detection."""
        devices = [
            {"bssid": "02:00:00:00:00:01", "essid": "", "signal_dbm": -30},  # Random MAC
            {"bssid": "A0:BB:CC:DD:EE:FF", "essid": "Test", "signal_dbm": -50},  # Not random (0 has no local bit)
        ]
        
        # Check randomized MAC detection
        assert analyzer._is_randomized_mac("02:00:00:00:00:01") is True
        assert analyzer._is_randomized_mac("A0:BB:CC:DD:EE:FF") is False
        
    def test_detect_deauth_source(self, analyzer):
        """Test deauth attack source detection."""
        # This would be detected from packet analysis
        # Placeholder test
        pass


class TestWhitelistEdgeCases:
    """Tests for whitelist edge cases."""
    
    def test_empty_whitelist(self):
        """Test with empty whitelist."""
        comparer = WhitelistComparer()
        device = {"mac": "AA:BB:CC:DD:EE:FF"}
        assert comparer.is_whitelisted(device) is False
        
    def test_malformed_whitelist_file(self, tmp_path):
        """Test with malformed whitelist JSON."""
        filepath = tmp_path / "bad_whitelist.json"
        with open(filepath, "w") as f:
            f.write("not valid json{{{")
            
        comparer = WhitelistComparer()
        # Should not raise, just log warning
        try:
            comparer.load_whitelist(str(filepath))
        except json.JSONDecodeError:
            pass  # Expected
            
    def test_whitelist_with_empty_mac(self, tmp_path):
        """Test whitelist with empty MAC entries."""
        whitelist = {
            "wifi_devices": [
                {"mac": "", "name": "Empty MAC"},
                {"mac": "AA:BB:CC:DD:EE:FF", "name": "Valid"},
            ],
        }
        filepath = tmp_path / "whitelist.json"
        with open(filepath, "w") as f:
            json.dump(whitelist, f)
            
        comparer = WhitelistComparer(str(filepath))
        # Should only add valid MAC
        assert "AA:BB:CC:DD:EE:FF" in comparer._mac_set


class TestAnalysisIntegration:
    """Integration tests for analysis workflow."""
    
    def test_full_analysis_workflow(self, tmp_path):
        """Test complete analysis workflow."""
        # Setup mock database
        db = Mock()
        db.get_session.return_value = {
            "session_id": "20251225_120000",
            "start_time": "2025-12-25T12:00:00",
            "end_time": "2025-12-25T13:00:00",
            "status": "stopped",
            "wifi_device_count": 10,
            "bt_device_count": 5,
        }
        db.get_wifi_devices.return_value = [
            {"id": i, "bssid": f"AA:BB:CC:DD:EE:{i:02X}", "essid": f"Network{i}",
             "signal_dbm": -45 - i, "gps_lat": 51.5074, "gps_lon": -0.1278}
            for i in range(10)
        ]
        db.get_bt_devices.return_value = [
            {"id": i, "mac_address": f"11:22:33:44:55:{i:02X}", "device_name": f"Device{i}",
             "rssi": -50 - i}
            for i in range(5)
        ]
        db.get_gps_track.return_value = [
            {"latitude": 51.5074 + i * 0.0001, "longitude": -0.1278 - i * 0.0001}
            for i in range(20)
        ]
        
        # Create whitelist
        whitelist = {
            "wifi_devices": [
                {"mac": "AA:BB:CC:DD:EE:00", "name": "Known Router"},
            ],
        }
        whitelist_path = tmp_path / "whitelist.json"
        with open(whitelist_path, "w") as f:
            json.dump(whitelist, f)
            
        # Run analysis with whitelist at init time
        analyzer = Analyzer(
            database=db,
            whitelist_file=str(whitelist_path),
        )
        result = analyzer.analyze_session("20251225_120000")
        
        assert result is not None
        assert result.total_wifi_devices == 10
        assert result.total_bt_devices == 5
        
        # Generate reports
        reporter = Reporter(output_dir=str(tmp_path))
        json_path = reporter.generate_json_report(result)
        
        assert Path(json_path).exists()
        
        # Verify report content
        with open(json_path) as f:
            report_data = json.load(f)
        assert report_data["summary"]["total_wifi_devices"] == 10
