# Project Airdump - Test Documentation

Comprehensive test suite for the Airdump drone-mounted wireless reconnaissance system.

## Table of Contents

- [Overview](#overview)
- [Test Structure](#test-structure)
- [Running Tests](#running-tests)
- [Test Categories](#test-categories)
- [Coverage Targets](#coverage-targets)
- [Writing New Tests](#writing-new-tests)
- [CI/CD Integration](#cicd-integration)

## Overview

The test suite covers all major components of Project Airdump:

| Component | Test File | Coverage |
|-----------|-----------|----------|
| Core Models | `tests/unit/test_models.py` | Data classes, enums, serialization |
| Core Utils | `tests/unit/test_utils.py` | MAC normalization, GPS distance, config loading |
| Database | `tests/unit/test_database.py` | CRUD operations, transactions, queries |
| Scanners | `tests/unit/test_scanners.py` | Kismet, GPS logger, tshark capture |
| Fingerprinting | `tests/unit/test_fingerprinting.py` | WiFi/BT fingerprinting, device identification |
| Analysis | `tests/unit/test_analysis.py` | Whitelist comparison, reporting |
| Integration | `tests/integration/test_workflow.py` | End-to-end workflows |

## Test Structure

```
tests/
├── conftest.py              # Shared pytest fixtures
├── mocks/
│   ├── __init__.py          # Mock module exports
│   └── mock_data.py         # Mock Kismet, GPS, pcap data
├── unit/
│   ├── test_models.py       # Core data model tests
│   ├── test_utils.py        # Utility function tests
│   ├── test_database.py     # Database operation tests
│   ├── test_scanners.py     # Scanner module tests
│   ├── test_fingerprinting.py  # Fingerprinting engine tests
│   └── test_analysis.py     # Analysis/reporting tests
└── integration/
    └── test_workflow.py     # End-to-end workflow tests
```

## Running Tests

### Prerequisites

```bash
# Install test dependencies
pip install pytest pytest-cov pytest-mock

# Optional: Install all project dependencies
pip install -r requirements.txt
```

### Basic Test Execution

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/unit/test_models.py

# Run specific test class
pytest tests/unit/test_models.py::TestWiFiDevice

# Run specific test function
pytest tests/unit/test_models.py::TestWiFiDevice::test_create_wifi_ap
```

### Coverage Reports

```bash
# Run with coverage report
pytest --cov=. --cov-report=html

# Generate terminal coverage report
pytest --cov=. --cov-report=term-missing

# Coverage for specific modules
pytest --cov=core --cov=scanners --cov=fingerprinting --cov=analysis
```

### Test Filtering

```bash
# Run only unit tests
pytest tests/unit/

# Run only integration tests
pytest tests/integration/

# Run tests matching a pattern
pytest -k "wifi"
pytest -k "database"
pytest -k "fingerprint"

# Skip slow tests
pytest -m "not slow"

# Run only tests that failed last time
pytest --lf
```

## Test Categories

### Unit Tests

Unit tests focus on individual functions and classes in isolation.

#### Core Models (`test_models.py`)

Tests for data models defined in `core/models.py`:

- **GPSPosition**: Position creation, serialization, invalid positions
- **ScanSession**: Session lifecycle, status transitions
- **WiFiDevice**: AP/client creation, GPS fields, JSON-lines format
- **BTDevice**: Classic/BLE devices, service UUIDs
- **Enums**: DeviceType, BTDeviceType, ScanStatus, GPSFixQuality

```bash
pytest tests/unit/test_models.py -v
```

#### Core Utils (`test_utils.py`)

Tests for utility functions in `core/utils.py`:

- **MAC Functions**: `normalize_mac()`, `mac_matches_pattern()`
- **GPS Functions**: `haversine_distance()`
- **Config Functions**: `load_config()`, variable expansion
- **System Functions**: `run_command()`, `is_monitor_mode()`
- **Interface Management**: `set_interface_mode()`, `restore_managed_mode()`
- **Rate Limiter**: API rate limiting
- **Hashing**: `compute_hash()` SHA256/MD5

```bash
pytest tests/unit/test_utils.py -v
```

#### Database (`test_database.py`)

Tests for database operations in `core/database.py`:

- **Connection**: Connect, close, reconnect, row factory
- **Transactions**: Commit, rollback on error
- **Sessions**: Create, get, update, end sessions
- **WiFi Devices**: Insert, update, query, unknown filtering
- **BT Devices**: Insert, update, query
- **GPS Track**: Insert, ordered retrieval
- **Fingerprints**: Insert, increment times_seen
- **Statistics**: Session stats, device counts
- **Buffer Recovery**: File-based buffering for failed writes

```bash
pytest tests/unit/test_database.py -v
```

#### Scanners (`test_scanners.py`)

Tests for scanner modules:

- **KismetController**: Connection, API requests, device parsing
- **KismetDevice**: WiFi/BT device dataclass
- **ChannelHopper**: Hop modes, adaptive rate
- **GPSLogger**: Position tracking, history, velocity
- **GPSPosition**: Position dataclass, validation
- **TsharkCapture**: Probe/beacon dataclasses

```bash
pytest tests/unit/test_scanners.py -v
```

#### Fingerprinting (`test_fingerprinting.py`)

Tests for device fingerprinting:

- **WiFiCapabilities**: Capability extraction, WPS detection
- **WiFiFingerprinter**: Probe processing, fingerprint computation
- **BluetoothCapabilities**: Device class, service UUIDs
- **BluetoothFingerprinter**: BT/BLE fingerprinting
- **FingerprintEngine**: Coordinated fingerprinting
- **MAC Randomization**: Detection of randomized MACs

```bash
pytest tests/unit/test_fingerprinting.py -v
```

#### Analysis (`test_analysis.py`)

Tests for analysis and reporting:

- **AnalysisResult**: Result dataclass, serialization
- **WhitelistEntry**: MAC/OUI/fingerprint/SSID matching
- **WhitelistComparer**: Whitelist loading, device comparison
- **Analyzer**: Session analysis, suspicious detection
- **Reporter**: JSON/HTML/CSV report generation

```bash
pytest tests/unit/test_analysis.py -v
```

### Integration Tests

Integration tests verify complete workflows across multiple components.

#### Workflow Tests (`test_workflow.py`)

- **Database Workflow**: Complete scan session lifecycle
- **Fingerprinting Workflow**: WiFi/BT fingerprinting pipeline
- **Analysis Workflow**: Scan to report generation
- **Scanner Integration**: Kismet + GPS coordination
- **End-to-End Scenarios**: Property audit, swarm consolidation
- **Error Handling**: Graceful degradation
- **Performance**: Large device counts

```bash
pytest tests/integration/test_workflow.py -v
```

## Coverage Targets

| Module | Target | Current |
|--------|--------|---------|
| core/models.py | 90% | - |
| core/utils.py | 85% | - |
| core/database.py | 80% | - |
| scanners/ | 75% | - |
| fingerprinting/ | 80% | - |
| analysis/ | 85% | - |
| **Overall** | **80%** | - |

## Writing New Tests

### Test File Template

```python
"""
Project Airdump - [Module] Tests

Unit tests for [module description].
"""

import pytest
from datetime import datetime, timezone
from unittest.mock import Mock, patch

from module.to.test import ClassToTest


class TestClassToTest:
    """Tests for ClassToTest class."""
    
    @pytest.fixture
    def instance(self):
        """Create test instance."""
        return ClassToTest()
        
    def test_method_basic(self, instance):
        """Test basic method functionality."""
        result = instance.method()
        assert result is not None
        
    def test_method_edge_case(self, instance):
        """Test edge case handling."""
        with pytest.raises(ValueError):
            instance.method(invalid_input)
```

### Using Fixtures

Common fixtures are defined in `tests/conftest.py`:

```python
def test_with_fixtures(
    self,
    temp_db,           # Temporary database
    sample_session,    # ScanSession instance
    sample_wifi_ap,    # WiFi AP device
    sample_bt_classic, # BT Classic device
    sample_config_file,  # Config YAML file path
    mock_kismet_status,  # Mock Kismet API response
):
    # Test implementation
    pass
```

### Using Mock Data

Mock data is available in `tests/mocks/mock_data.py`:

```python
from tests.mocks import (
    MOCK_KISMET_STATUS,
    MOCK_KISMET_WIFI_DEVICES,
    MOCK_KISMET_BT_DEVICES,
    MOCK_GPSD_TPV,
    MOCK_PROBE_REQUEST,
    create_mock_wifi_device,
    create_mock_bt_device,
)
```

### Mocking External Dependencies

```python
@patch("requests.Session.get")
def test_with_mocked_requests(self, mock_get):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"status": "ok"}
    mock_get.return_value = mock_response
    
    # Test code that uses requests
    
@patch("scanners.gps_logger.GPSD_AVAILABLE", False)
def test_without_gpsd(self):
    # Test code when gpsd is not available
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
          
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install pytest pytest-cov
          
      - name: Run tests
        run: |
          pytest --cov=. --cov-report=xml
          
      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          file: ./coverage.xml
```

### Pre-commit Hook

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: pytest
        name: pytest
        entry: pytest tests/unit/ -v --tb=short
        language: system
        pass_filenames: false
        always_run: true
```

## Test Data Files

### Sample Whitelist (`tests/fixtures/whitelist.json`)

```json
{
  "wifi_devices": [
    {"mac": "AA:BB:CC:DD:EE:FF", "name": "Test Router", "category": "infrastructure"}
  ],
  "bluetooth_devices": [
    {"mac": "11:22:33:44:55:66", "name": "Test Phone"}
  ],
  "oui_whitelist": ["00:17:F2"],
  "ssid_whitelist": ["TestNetwork"]
}
```

### Sample Config (`tests/fixtures/config.yaml`)

```yaml
general:
  property_id: TEST-FACILITY
  data_dir: /tmp/airdump_test

kismet:
  host: localhost
  port: 2501
  username: kismet
  password: kismet

gps:
  host: localhost
  port: 2947
```

## Troubleshooting

### Common Issues

**Import Errors**
```bash
# Ensure project root is in PYTHONPATH
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
pytest
```

**Database Permission Errors**
```bash
# Tests use temporary databases, but check permissions
pytest tests/unit/test_database.py -v
```

**Missing Dependencies**
```bash
# Install optional test dependencies
pip install pytest-mock responses
```

### Debug Mode

```bash
# Run with debug output
pytest -v -s --tb=long

# Drop into debugger on failure
pytest --pdb

# Show local variables in tracebacks
pytest -l
```

## Contributing Tests

1. Create tests for any new functionality
2. Ensure tests are isolated and don't depend on external state
3. Use descriptive test names explaining what is tested
4. Include both positive and negative test cases
5. Mock external dependencies (Kismet, gpsd, etc.)
6. Run full test suite before submitting PR

```bash
# Full test validation
pytest --cov=. --cov-report=term-missing -v
```
