#!/usr/bin/env python3
"""Universal cross-platform launcher for Crowd VPN."""

import sys
import os
from pathlib import Path

def main():
    try:
        # Set working directory to script location
        script_dir = Path(__file__).parent
        os.chdir(script_dir)
        
        # Add to Python path
        sys.path.insert(0, str(script_dir))
        
        print("Starting Crowd VPN GUI...")
        
        # Import and run GUI
        from crowd_vpn_gui import CrowdVPNGUI
        app = CrowdVPNGUI()
        app.run()
        
    except ImportError as e:
        print(f"[ERROR] Import error: {e}")
        print("Please ensure all dependencies are installed:")
        print("  pip install -r requirements.txt")
        input("Press Enter to exit...")
    except Exception as e:
        print(f"[ERROR] Error: {e}")
        import traceback
        traceback.print_exc()
        input("Press Enter to exit...")

if __name__ == "__main__":
    main()
