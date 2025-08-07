#!/usr/bin/env python3
"""Setup script for the modern Crowd VPN frontend."""

import os
import sys
import subprocess
import json
from pathlib import Path

def run_command(cmd, cwd=None):
    """Run a command and return success status."""
    try:
        result = subprocess.run(cmd, shell=True, cwd=cwd, check=True, 
                              capture_output=True, text=True)
        print(f"✅ {cmd}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {cmd}")
        print(f"   Error: {e.stderr}")
        return False

def check_node_installed():
    """Check if Node.js is installed."""
    try:
        result = subprocess.run(['node', '--version'], capture_output=True, text=True)
        if result.returncode == 0:
            version = result.stdout.strip()
            print(f"✅ Node.js found: {version}")
            return True
    except FileNotFoundError:
        pass
    
    print("❌ Node.js not found. Please install Node.js from https://nodejs.org/")
    return False

def setup_frontend():
    """Setup the React frontend."""
    print("🚀 Setting up Crowd VPN Modern Frontend...")
    print("="*50)
    
    # Check prerequisites
    if not check_node_installed():
        return False
    
    frontend_dir = Path(__file__).parent / "frontend"
    
    # Create frontend directory if it doesn't exist
    frontend_dir.mkdir(exist_ok=True)
    
    print("\n📦 Installing React dependencies...")
    if not run_command("npm install", cwd=frontend_dir):
        return False
    
    print("\n🐍 Installing Python backend dependencies...")
    if not run_command("pip install -r requirements-frontend.txt"):
        print("⚠️  Python backend dependencies failed, but frontend should still work")
    
    print("\n✨ Setup completed successfully!")
    print("\n🚀 To start the application:")
    print("\n1. Start the Python backend:")
    print("   python backend_api.py")
    print("\n2. In another terminal, start the React frontend:")
    print(f"   cd {frontend_dir}")
    print("   npm start")
    print("\n3. Or build the Electron app:")
    print(f"   cd {frontend_dir}")
    print("   npm run electron-dev")
    
    print("\n🌐 The app will be available at http://localhost:3000")
    return True

if __name__ == "__main__":
    success = setup_frontend()
    if not success:
        sys.exit(1)
    
    # Ask if user wants to start the development servers
    start_now = input("\n❓ Would you like to start the development servers now? (y/N): ").lower().strip()
    if start_now in ['y', 'yes']:
        print("\n🚀 Starting development servers...")
        
        # Start backend in background
        backend_process = subprocess.Popen([sys.executable, "backend_api.py"])
        print("✅ Backend server starting on http://localhost:8000")
        
        # Give backend time to start
        import time
        time.sleep(2)
        
        # Start frontend
        frontend_dir = Path(__file__).parent / "frontend"
        print("✅ Frontend server starting on http://localhost:3000")
        subprocess.run(["npm", "start"], cwd=frontend_dir)

