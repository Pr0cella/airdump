#!/bin/bash
#
# Project Airdump - Pre-flight Check Script
# Verifies system is ready for scanning
#

# Don't use set -e as we want to continue checking even if individual checks fail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CONFIG_FILE="${PROJECT_DIR}/config/config.yaml"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS="${GREEN}[PASS]${NC}"
FAIL="${RED}[FAIL]${NC}"
WARN="${YELLOW}[WARN]${NC}"

check_count=0
pass_count=0
warn_count=0
fail_count=0

check() {
    local name="$1"
    local result="$2"
    local message="$3"
    
    ((check_count++))
    
    if [[ "$result" == "pass" ]]; then
        echo -e "$PASS $name: $message"
        ((pass_count++))
    elif [[ "$result" == "warn" ]]; then
        echo -e "$WARN $name: $message"
        ((warn_count++))
    else
        echo -e "$FAIL $name: $message"
        ((fail_count++))
    fi
}

echo "========================================="
echo "  Airdump Pre-flight Check"
echo "========================================="
echo ""

# System checks
echo "## System Checks ##"

# Root check
if [[ $EUID -eq 0 ]]; then
    check "Root Access" "pass" "Running as root"
else
    check "Root Access" "fail" "Not running as root"
fi

# Python
if command -v python3 &> /dev/null; then
    py_version=$(python3 --version 2>&1)
    check "Python" "pass" "$py_version"
else
    check "Python" "fail" "Python 3 not found"
fi

# Free disk space
free_space=$(df -h "${PROJECT_DIR}" | awk 'NR==2 {print $4}')
free_bytes=$(df "${PROJECT_DIR}" | awk 'NR==2 {print $4}')
if [[ $free_bytes -gt 1048576 ]]; then  # > 1GB
    check "Disk Space" "pass" "$free_space free"
elif [[ $free_bytes -gt 524288 ]]; then  # > 500MB
    check "Disk Space" "warn" "$free_space free (low)"
else
    check "Disk Space" "fail" "$free_space free (insufficient)"
fi

# RAM
free_ram=$(free -h | awk '/^Mem:/ {print $4}')
check "Free RAM" "pass" "$free_ram available"

echo ""
echo "## Service Checks ##"

# gpsd
if systemctl is-active --quiet gpsd 2>/dev/null || pgrep -x gpsd > /dev/null; then
    check "gpsd" "pass" "Running"
else
    check "gpsd" "warn" "Not running"
fi

# Kismet
if pgrep -x kismet > /dev/null; then
    check "Kismet" "pass" "Running"
else
    check "Kismet" "warn" "Not running (will be started)"
fi

echo ""
echo "## Network Checks ##"

# WiFi interface
wifi_iface=""
for iface in wlan0 wlan1 wlp2s0; do
    if ip link show "$iface" &> /dev/null; then
        wifi_iface="$iface"
        break
    fi
done

if [[ -n "$wifi_iface" ]]; then
    check "WiFi Interface" "pass" "$wifi_iface found"
else
    check "WiFi Interface" "fail" "No WiFi interface found"
fi

# Monitor mode interface
mon_iface=""
for iface in wlan0mon wlan1mon mon0; do
    if ip link show "$iface" &> /dev/null; then
        mon_iface="$iface"
        break
    fi
done

if [[ -n "$mon_iface" ]]; then
    check "Monitor Mode" "pass" "$mon_iface available"
else
    check "Monitor Mode" "warn" "No monitor interface (run: airmon-ng start $wifi_iface)"
fi

echo ""
echo "## GPS Checks ##"

# GPS device
if [[ -e /dev/ttyUSB0 ]] || [[ -e /dev/ttyACM0 ]] || [[ -e /dev/serial0 ]]; then
    gps_dev=$(ls /dev/ttyUSB0 /dev/ttyACM0 /dev/serial0 2>/dev/null | head -1)
    check "GPS Device" "pass" "$gps_dev found"
else
    check "GPS Device" "warn" "No GPS device found"
fi

# GPS fix (check via gpsd)
if command -v gpspipe &> /dev/null && pgrep gpsd > /dev/null; then
    gps_data=$(timeout 5 gpspipe -w -n 5 2>/dev/null | grep -o '"mode":[0-9]' | head -1 || echo "")
    if [[ "$gps_data" == *"mode\":3"* ]] || [[ "$gps_data" == *"mode\":2"* ]]; then
        check "GPS Fix" "pass" "Fix acquired"
    else
        check "GPS Fix" "warn" "No GPS fix yet"
    fi
else
    check "GPS Fix" "warn" "Cannot check (gpspipe not available)"
fi

echo ""
echo "## Configuration Checks ##"

# Config file
if [[ -f "$CONFIG_FILE" ]]; then
    check "Config File" "pass" "$CONFIG_FILE exists"
else
    if [[ -f "${CONFIG_FILE}.example" ]]; then
        check "Config File" "warn" "Using example config (copy to config.yaml)"
    else
        check "Config File" "fail" "No config file found"
    fi
fi

# Data directory
data_dir="${PROJECT_DIR}/data"
if [[ -d "$data_dir" ]]; then
    check "Data Directory" "pass" "$data_dir exists"
else
    mkdir -p "$data_dir" 2>/dev/null && check "Data Directory" "pass" "Created $data_dir" || check "Data Directory" "fail" "Cannot create $data_dir"
fi

echo ""
echo "========================================="
echo "  Results: $pass_count passed, $warn_count warnings, $fail_count failed"
echo "========================================="

if [[ $fail_count -gt 0 ]]; then
    echo -e "${RED}Pre-flight check FAILED${NC}"
    exit 1
elif [[ $warn_count -gt 0 ]]; then
    echo -e "${YELLOW}Pre-flight check passed with warnings${NC}"
    exit 0
else
    echo -e "${GREEN}Pre-flight check PASSED${NC}"
    exit 0
fi
