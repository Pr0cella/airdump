#!/bin/bash
#
# Project Airdump - Start Scan Script
# Usage: sudo ./start_scan.sh [mode] [options]
#
# Modes:
#   all      - Start all scanners (default)
#   wifi     - WiFi only
#   bt       - Bluetooth only
#
# Options:
#   --duration SECONDS    - Scan duration
#   --session-name NAME   - Session name
#   --property-id ID      - Property identifier
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CONFIG_FILE="${PROJECT_DIR}/config/config.yaml"
DATA_DIR="${PROJECT_DIR}/data"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

check_dependencies() {
    log_info "Checking dependencies..."
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 not found"
        exit 1
    fi
    
    # Check required commands
    local deps=("kismet" "tshark" "gpsd")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            log_warn "$dep not found"
        fi
    done
}

check_interfaces() {
    log_info "Checking wireless interfaces..."
    
    # Look for monitor mode interface
    if ip link show wlan0mon &> /dev/null; then
        log_info "Monitor interface wlan0mon found"
        MONITOR_IFACE="wlan0mon"
    elif ip link show wlan1mon &> /dev/null; then
        log_info "Monitor interface wlan1mon found"
        MONITOR_IFACE="wlan1mon"
    else
        log_warn "No monitor mode interface found"
        MONITOR_IFACE=""
    fi
}

# Auto-detect WiFi interface
detect_wifi_interface() {
    # Find first wireless interface (prefer wlan*, then wlp*)
    local iface
    iface=$(iw dev 2>/dev/null | awk '$1=="Interface"{print $2}' | grep -E "^wlan|^wlp" | head -1)
    
    if [[ -z "$iface" ]]; then
        log_warn "No WiFi interface detected"
        return 1
    fi
    
    echo "$iface"
}

# Start monitor mode on interface
start_monitor_mode() {
    local iface="${1:-}"
    
    # Auto-detect if not provided
    if [[ -z "$iface" ]]; then
        iface=$(detect_wifi_interface) || return 1
    fi
    
    log_info "Setting up monitor mode on $iface..."
    
    # Check if already in monitor mode
    local mode
    mode=$(iw dev "$iface" info 2>/dev/null | awk '/type/{print $2}')
    if [[ "$mode" == "monitor" ]]; then
        log_info "$iface is already in monitor mode"
        MONITOR_IFACE="$iface"
        return 0
    fi
    
    # Check if airmon-ng is available
    if command -v airmon-ng &> /dev/null; then
        # Kill interfering processes
        log_info "Killing interfering processes..."
        airmon-ng check kill &> /dev/null || true
        
        # Start monitor mode with airmon-ng
        log_info "Starting monitor mode with airmon-ng..."
        airmon-ng start "$iface" &> /dev/null
        
        # airmon-ng usually creates wlan0mon or similar
        sleep 1
        if ip link show "${iface}mon" &> /dev/null; then
            MONITOR_IFACE="${iface}mon"
        elif ip link show "wlan0mon" &> /dev/null; then
            MONITOR_IFACE="wlan0mon"
        else
            # Interface might stay same name
            MONITOR_IFACE="$iface"
        fi
    else
        # Manual method using iw
        log_info "Using iw to set monitor mode..."
        
        # Bring interface down
        ip link set "$iface" down
        
        # Set monitor mode
        iw dev "$iface" set type monitor
        
        # Bring interface up
        ip link set "$iface" up
        
        MONITOR_IFACE="$iface"
    fi
    
    # Verify monitor mode
    mode=$(iw dev "$MONITOR_IFACE" info 2>/dev/null | awk '/type/{print $2}')
    if [[ "$mode" == "monitor" ]]; then
        log_info "Monitor mode enabled on $MONITOR_IFACE"
        
        # Save original interface name for restore
        echo "$iface" > /tmp/airdump_original_iface
        echo "$MONITOR_IFACE" > /tmp/airdump_monitor_iface
        return 0
    else
        log_error "Failed to enable monitor mode on $iface"
        return 1
    fi
}

start_services() {
    log_info "Starting required services..."
    
    # Start gpsd if not running
    if ! pgrep -x "gpsd" > /dev/null; then
        log_info "Starting gpsd..."
        systemctl start gpsd || true
    fi
    
    # Start Kismet if not running
    if ! pgrep -x "kismet" > /dev/null; then
        log_info "Starting Kismet..."
        kismet --daemonize || log_warn "Failed to start Kismet"
        sleep 2
    fi
}

start_scan() {
    local mode="${1:-all}"
    shift || true
    
    log_info "Starting scan in mode: $mode"
    
    cd "$PROJECT_DIR"
    
    # Build arguments
    local args=("--config" "$CONFIG_FILE" "--data-dir" "$DATA_DIR")
    
    # Parse remaining arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --duration)
                args+=("--duration" "$2")
                shift 2
                ;;
            --session-name)
                args+=("--session-name" "$2")
                shift 2
                ;;
            --property-id)
                args+=("--property-id" "$2")
                shift 2
                ;;
            *)
                shift
                ;;
        esac
    done
    
    log_info "Starting scan orchestrator..."
    python3 -m scan_orchestrator "${args[@]}"
}

show_help() {
    echo "Airdump Scan Control"
    echo ""
    echo "Usage: $0 [mode] [options]"
    echo ""
    echo "Modes:"
    echo "  all      - Start all scanners (default)"
    echo "  wifi     - WiFi only"
    echo "  bt       - Bluetooth only"
    echo ""
    echo "Options:"
    echo "  --duration SECONDS    - Scan duration"
    echo "  --session-name NAME   - Session name"
    echo "  --property-id ID      - Property identifier"
    echo "  --help                - Show this help"
}

# Main
main() {
    if [[ "$1" == "--help" || "$1" == "-h" ]]; then
        show_help
        exit 0
    fi
    
    check_root
    check_dependencies
    check_interfaces
    
    # Start monitor mode if not already available
    if [[ -z "$MONITOR_IFACE" ]]; then
        start_monitor_mode || log_warn "Could not enable monitor mode - continuing anyway"
    fi
    
    start_services
    start_scan "$@"
}

main "$@"
