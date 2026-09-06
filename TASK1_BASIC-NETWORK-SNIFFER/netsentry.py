#!/usr/bin/env python3
"""
NetSentry - Professional Network Packet Sniffer
================================================

Entry point for the NetSentry application.

Author: Muhammad Ahsan
Version: 1.0.0
License: MIT
"""

import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from netsentry.main import main

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        try:
            from colorama import Fore, Style
            print(f"\n{Fore.YELLOW}[INTERRUPTED]{Style.RESET_ALL} Capture stopped by user")
        except:
            print("\n[INTERRUPTED] Capture stopped by user")
        sys.exit(0)
    except Exception as e:
        import logging
        logger = logging.getLogger("NetSentry")
        logger.error(f"Fatal error: {e}")
        try:
            from colorama import Fore, Style
            print(f"{Fore.RED}[FATAL ERROR]{Style.RESET_ALL} {e}")
        except:
            print(f"[FATAL ERROR] {e}")
        sys.exit(1)
