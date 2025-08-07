#!/usr/bin/env python3
"""Simple launcher for Crowd VPN GUI application."""

import sys
import os
from pathlib import Path

def main():
    """Launch the GUI application."""
    try:
        # Add the current directory to Python path if needed
        current_dir = Path(__file__).parent
        if str(current_dir) not in sys.path:
            sys.path.insert(0, str(current_dir))
        
        # Import and run the GUI
        from crowd_vpn_gui import CrowdVPNGUI
        
        print("🚀 Starting Crowd VPN GUI...")
        app = CrowdVPNGUI()
        app.run()
        
    except ImportError as e:
        print(f"❌ Error importing required modules: {e}")
        print("")
        print("Please ensure all dependencies are installed:")
        print("  pip install -r requirements.txt")
        input("Press Enter to exit...")
        
    except Exception as e:
        print(f"❌ Error starting application: {e}")
        input("Press Enter to exit...")

if __name__ == "__main__":
    main()

