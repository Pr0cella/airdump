#!/usr/bin/env python3
"""
Project Airdump - Restore WiFi Interface

Restores WiFi interface from monitor mode to managed mode.
Can be run after scans complete, after interrupts, or as cleanup.

Usage:
    python3 scripts/restore_interface.py [interface]
    
Examples:
    python3 scripts/restore_interface.py           # Auto-detect
    python3 scripts/restore_interface.py wlan0     # Specific interface
    python3 scripts/restore_interface.py wlan0mon  # Monitor interface
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.utils import restore_managed_mode, is_monitor_mode


def main():
    """Main entry point."""
    interface = sys.argv[1] if len(sys.argv) > 1 else None
    
    # Check if there's actually a monitor interface
    if interface and not is_monitor_mode(interface):
        print(f"Interface {interface} is not in monitor mode")
        return 0
    
    print("Restoring WiFi interface to managed mode...")
    
    success = restore_managed_mode(interface)
    
    if success:
        print("✅ Interface restored to managed mode")
        return 0
    else:
        print("❌ Failed to restore interface")
        return 1


if __name__ == "__main__":
    sys.exit(main())
