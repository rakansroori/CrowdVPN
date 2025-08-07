#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Simple test script to verify GUI functionality."""

import sys
import os
from pathlib import Path

# Fix encoding on Windows console
if sys.platform == 'win32':
    os.environ['PYTHONIOENCODING'] = 'utf-8'

def test_imports():
    """Test if all required modules can be imported."""
    print("Testing imports...")
    
    try:
        import tkinter as tk
        print("[OK] tkinter")
    except ImportError as e:
        print(f"[FAIL] tkinter - FAILED: {e}")
        return False
        
    try:
        from tkinter import ttk, messagebox, scrolledtext
        print("[OK] tkinter components")
    except ImportError as e:
        print(f"[FAIL] tkinter components - FAILED: {e}")
        return False
    
    try:
        import threading, asyncio, json, time
        from datetime import datetime
        print("[OK] Standard library modules")
    except ImportError as e:
        print(f"[FAIL] Standard library modules - FAILED: {e}")
        return False
    
    return True

def test_gui():
    """Test basic GUI functionality."""
    print("Testing GUI creation...")
    
    try:
        # Add current directory to path
        current_dir = Path(__file__).parent
        if str(current_dir) not in sys.path:
            sys.path.insert(0, str(current_dir))
        
        from crowd_vpn_gui import CrowdVPNGUI
        
        print("[OK] GUI module import")
        print("Creating GUI instance...")
        
        app = CrowdVPNGUI()
        print("[OK] GUI instance created")
        
        print("")
        print("GUI test successful! You can now run:")
        print("  python crowd_vpn_gui.py")
        print("  or")
        print("  python launch_gui.py")
        
        return True
        
    except Exception as e:
        print(f"[FAIL] GUI test FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    print("Crowd VPN GUI Test")
    print("=" * 30)
    
    if not test_imports():
        print("\n[FAIL] Import tests failed")
        return False
        
    if not test_gui():
        print("\n[FAIL] GUI tests failed")
        return False
    
    print("\n[OK] All tests passed!")
    return True

if __name__ == "__main__":
    success = main()
    if not success:
        sys.exit(1)

