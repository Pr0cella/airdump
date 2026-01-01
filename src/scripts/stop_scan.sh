#!/bin/bash
#
# Project Airdump - Stop Scan Script
# Gracefully stops all scanning processes and restores WiFi interface
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

stop_scan() {
    log_info "Stopping Airdump scan..."
    
    # Send SIGTERM to scan orchestrator
    if pgrep -f "scan_orchestrator" > /dev/null; then
        log_info "Sending SIGTERM to scan orchestrator..."
        pkill -TERM -f "scan_orchestrator" || true
        
        # Wait for graceful shutdown
        for i in {1..10}; do
            if ! pgrep -f "scan_orchestrator" > /dev/null; then
                break
            fi
            sleep 1
        done
        
        # Force kill if still running
        if pgrep -f "scan_orchestrator" > /dev/null; then
            log_info "Force killing scan orchestrator..."
            pkill -9 -f "scan_orchestrator" || true
        fi
    fi
    
    log_info "Scan stopped"
}

stop_monitor_mode() {
    log_info "Restoring WiFi interface..."
    
    local original_iface=""
    local monitor_iface=""
    
    # Read saved interface names
    if [[ -f /tmp/airdump_original_iface ]]; then
        original_iface=$(cat /tmp/airdump_original_iface)
    fi
    if [[ -f /tmp/airdump_monitor_iface ]]; then
        monitor_iface=$(cat /tmp/airdump_monitor_iface)
    fi
    
    # If no saved state, try to detect monitor interface
    if [[ -z "$monitor_iface" ]]; then
        if ip link show wlan0mon &> /dev/null; then
            monitor_iface="wlan0mon"
            original_iface="wlan0"
        elif ip link show wlan1mon &> /dev/null; then
            monitor_iface="wlan1mon"
            original_iface="wlan1"
        else
            # Check if any interface is in monitor mode
            monitor_iface=$(iw dev 2>/dev/null | awk '$1=="Interface"{iface=$2} /type monitor/{print iface}' | head -1)
            original_iface="$monitor_iface"
        fi
    fi
    
    if [[ -z "$monitor_iface" ]]; then
        log_info "No monitor interface to restore"
        return 0
    fi
    
    # Check if airmon-ng is available
    if command -v airmon-ng &> /dev/null; then
        log_info "Stopping monitor mode with airmon-ng..."
        airmon-ng stop "$monitor_iface" &> /dev/null || true
    else
        # Manual method using iw
        log_info "Using iw to restore managed mode..."
        
        ip link set "$monitor_iface" down 2>/dev/null || true
        iw dev "$monitor_iface" set type managed 2>/dev/null || true
        ip link set "$monitor_iface" up 2>/dev/null || true
    fi
    
    # Restart NetworkManager if available (to restore normal WiFi)
    if command -v systemctl &> /dev/null; then
        if systemctl is-active --quiet NetworkManager 2>/dev/null; then
            log_info "Restarting NetworkManager..."
            systemctl restart NetworkManager || true
        fi
    fi
    
    # Clean up temp files
    rm -f /tmp/airdump_original_iface /tmp/airdump_monitor_iface
    
    log_info "WiFi interface restored"
}

# Main
main() {
    stop_scan
    stop_monitor_mode
    log_info "Airdump shutdown complete"
}

main
