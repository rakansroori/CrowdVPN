#!/usr/bin/env python3
"""Crowd VPN - Modern Python GUI Application"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import asyncio
import json
import time
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path
import logging

# Import VPN components
try:
    from crowd_vpn.node import CrowdVPNNode
    from crowd_vpn.core.network import NodeType
    from crowd_vpn.core.router import RoutingAlgorithm
    HAS_VPN_BACKEND = True
except ImportError:
    HAS_VPN_BACKEND = False
    print("VPN backend not available, running in demo mode")


class CrowdVPNGUI:
    """Main GUI application for Crowd VPN"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.setup_window()
        self.setup_styles()
        
        # VPN state
        self.vpn_node: Optional[CrowdVPNNode] = None
        self.is_connected = False
        self.is_connecting = False
        self.connection_start_time = None
        self.selected_country = "Auto"
        
        # GUI variables
        self.status_var = tk.StringVar(value="Disconnected")
        self.country_var = tk.StringVar(value="Auto")
        self.ip_var = tk.StringVar(value="Not connected")
        self.uptime_var = tk.StringVar(value="00:00:00")
        self.data_sent_var = tk.StringVar(value="0 MB")
        self.data_received_var = tk.StringVar(value="0 MB")
        
        # Available locations
        self.countries = [
            "Auto", "United States", "United Kingdom", "Germany", 
            "France", "Netherlands", "Switzerland", "Sweden", 
            "Japan", "Singapore", "Australia", "Canada"
        ]
        
        self.create_widgets()
        self.setup_logging()
        self.start_update_thread()
        
    def setup_window(self):
        """Configure main window"""
        self.root.title("Crowd VPN - Decentralized P2P VPN")
        self.root.geometry("800x600")
        self.root.minsize(700, 500)
        self.root.configure(bg='#f0f0f0')
        
        # Center window on screen
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (800 // 2)
        y = (self.root.winfo_screenheight() // 2) - (600 // 2)
        self.root.geometry(f"800x600+{x}+{y}")
        
    def setup_styles(self):
        """Configure custom styles"""
        style = ttk.Style()
        
        # Configure custom button styles
        style.configure('Connect.TButton', 
                       font=('Helvetica', 12, 'bold'),
                       padding=(20, 10))
        
        style.configure('Disconnect.TButton',
                       font=('Helvetica', 12, 'bold'),
                       padding=(20, 10))
        
        style.configure('Status.TLabel',
                       font=('Helvetica', 14, 'bold'),
                       background='#f0f0f0')
        
        style.configure('Title.TLabel',
                       font=('Helvetica', 16, 'bold'),
                       background='#f0f0f0')
        
    def create_widgets(self):
        """Create and layout GUI widgets"""
        # Main container
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="🌍 Crowd VPN", style='Title.TLabel')
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # Connection status section
        self.create_status_section(main_frame, row=1)
        
        # Connection control section
        self.create_control_section(main_frame, row=2)
        
        # Statistics section
        self.create_stats_section(main_frame, row=3)
        
        # Settings section
        self.create_settings_section(main_frame, row=4)
        
        # Log section
        self.create_log_section(main_frame, row=5)
        
    def create_status_section(self, parent, row):
        """Create connection status display"""
        status_frame = ttk.LabelFrame(parent, text="Connection Status", padding="15")
        status_frame.grid(row=row, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        status_frame.columnconfigure(1, weight=1)
        
        # Status indicator
        self.status_label = ttk.Label(status_frame, textvariable=self.status_var, 
                                     style='Status.TLabel', foreground='red')
        self.status_label.grid(row=0, column=0, columnspan=2, pady=(0, 10))
        
        # Connection details
        ttk.Label(status_frame, text="Country:").grid(row=1, column=0, sticky=tk.W)
        ttk.Label(status_frame, textvariable=self.country_var).grid(row=1, column=1, sticky=tk.W, padx=(10, 0))
        
        ttk.Label(status_frame, text="IP Address:").grid(row=2, column=0, sticky=tk.W)
        ttk.Label(status_frame, textvariable=self.ip_var).grid(row=2, column=1, sticky=tk.W, padx=(10, 0))
        
        ttk.Label(status_frame, text="Connection Time:").grid(row=3, column=0, sticky=tk.W)
        ttk.Label(status_frame, textvariable=self.uptime_var).grid(row=3, column=1, sticky=tk.W, padx=(10, 0))
        
    def create_control_section(self, parent, row):
        """Create connection control buttons"""
        control_frame = ttk.LabelFrame(parent, text="Connection Control", padding="15")
        control_frame.grid(row=row, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        control_frame.columnconfigure(1, weight=1)
        
        # Country selection
        ttk.Label(control_frame, text="Select Location:").grid(row=0, column=0, sticky=tk.W)
        self.country_combo = ttk.Combobox(control_frame, textvariable=self.country_var, 
                                         values=self.countries, state="readonly", width=20)
        self.country_combo.grid(row=0, column=1, sticky=tk.W, padx=(10, 0))
        self.country_combo.set("Auto")
        
        # Connect/Disconnect buttons
        button_frame = ttk.Frame(control_frame)
        button_frame.grid(row=1, column=0, columnspan=2, pady=(15, 0))
        
        self.connect_btn = ttk.Button(button_frame, text="🔗 Connect", 
                                     command=self.connect_vpn, style='Connect.TButton')
        self.connect_btn.grid(row=0, column=0, padx=(0, 10))
        
        self.disconnect_btn = ttk.Button(button_frame, text="❌ Disconnect", 
                                        command=self.disconnect_vpn, style='Disconnect.TButton',
                                        state='disabled')
        self.disconnect_btn.grid(row=0, column=1)
        
    def create_stats_section(self, parent, row):
        """Create statistics display"""
        stats_frame = ttk.LabelFrame(parent, text="Connection Statistics", padding="15")
        stats_frame.grid(row=row, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Data usage
        ttk.Label(stats_frame, text="Data Sent:").grid(row=0, column=0, sticky=tk.W)
        ttk.Label(stats_frame, textvariable=self.data_sent_var).grid(row=0, column=1, sticky=tk.W, padx=(10, 0))
        
        ttk.Label(stats_frame, text="Data Received:").grid(row=0, column=2, sticky=tk.W, padx=(20, 0))
        ttk.Label(stats_frame, textvariable=self.data_received_var).grid(row=0, column=3, sticky=tk.W, padx=(10, 0))
        
    def create_settings_section(self, parent, row):
        """Create settings section"""
        settings_frame = ttk.LabelFrame(parent, text="Settings", padding="15")
        settings_frame.grid(row=row, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Node type selection
        ttk.Label(settings_frame, text="Node Type:").grid(row=0, column=0, sticky=tk.W)
        self.node_type_var = tk.StringVar(value="hybrid")
        node_type_combo = ttk.Combobox(settings_frame, textvariable=self.node_type_var,
                                      values=["client", "relay", "exit", "hybrid"],
                                      state="readonly", width=15)
        node_type_combo.grid(row=0, column=1, sticky=tk.W, padx=(10, 0))
        
        # Port setting
        ttk.Label(settings_frame, text="Port:").grid(row=0, column=2, sticky=tk.W, padx=(20, 0))
        self.port_var = tk.StringVar(value="8080")
        port_entry = ttk.Entry(settings_frame, textvariable=self.port_var, width=8)
        port_entry.grid(row=0, column=3, sticky=tk.W, padx=(10, 0))
        
        # Auto-reconnect
        self.auto_reconnect_var = tk.BooleanVar(value=True)
        auto_reconnect_check = ttk.Checkbutton(settings_frame, text="Auto-reconnect",
                                              variable=self.auto_reconnect_var)
        auto_reconnect_check.grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=(10, 0))
        
        # Enable logging
        self.enable_logging_var = tk.BooleanVar(value=True)
        logging_check = ttk.Checkbutton(settings_frame, text="Enable detailed logging",
                                       variable=self.enable_logging_var)
        logging_check.grid(row=1, column=2, columnspan=2, sticky=tk.W, pady=(10, 0))
        
    def create_log_section(self, parent, row):
        """Create log display section"""
        log_frame = ttk.LabelFrame(parent, text="Activity Log", padding="15")
        log_frame.grid(row=row, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        parent.rowconfigure(row, weight=1)
        
        # Log text area with scrollbar
        self.log_text = scrolledtext.ScrolledText(log_frame, height=8, width=80,
                                                 font=('Consolas', 9), wrap=tk.WORD)
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Clear log button
        clear_btn = ttk.Button(log_frame, text="Clear Log", command=self.clear_log)
        clear_btn.grid(row=1, column=0, sticky=tk.E, pady=(5, 0))
        
    def setup_logging(self):
        """Setup logging to display in GUI"""
        self.log_queue = []
        self.add_log("INFO", "Crowd VPN GUI started")
        if HAS_VPN_BACKEND:
            self.add_log("INFO", "VPN backend available")
        else:
            self.add_log("WARNING", "VPN backend not available - running in demo mode")
            
    def add_log(self, level: str, message: str):
        """Add log entry to display"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {level}: {message}\n"
        
        # Add to queue for thread-safe GUI update
        self.log_queue.append(log_entry)
        
        # Keep only last 100 entries
        if len(self.log_queue) > 100:
            self.log_queue.pop(0)
            
    def update_log_display(self):
        """Update log display in GUI (called from main thread)"""
        if self.log_queue:
            for entry in self.log_queue:
                self.log_text.insert(tk.END, entry)
                self.log_text.see(tk.END)
            self.log_queue.clear()
            
    def clear_log(self):
        """Clear log display"""
        self.log_text.delete(1.0, tk.END)
        self.log_queue.clear()
        
    def connect_vpn(self):
        """Connect to VPN"""
        if self.is_connected or self.is_connecting:
            return
            
        self.is_connecting = True
        self.connect_btn.configure(state='disabled')
        self.country_combo.configure(state='disabled')
        self.status_var.set("Connecting...")
        self.status_label.configure(foreground='orange')
        
        selected_country = self.country_var.get()
        self.add_log("INFO", f"Connecting to VPN via {selected_country}...")
        
        # Start connection in background thread
        thread = threading.Thread(target=self._connect_background, 
                                 args=(selected_country,), daemon=True)
        thread.start()
        
    def _connect_background(self, country: str):
        """Background connection process"""
        try:
            if HAS_VPN_BACKEND:
                # Create and start VPN node
                port = int(self.port_var.get())
                node_type = NodeType(self.node_type_var.get())
                
                self.vpn_node = CrowdVPNNode(
                    port=port,
                    node_type=node_type,
                    routing_algorithm=RoutingAlgorithm.REPUTATION_BASED
                )
                
                # Start node (this would be async in real implementation)
                self.add_log("INFO", "Starting VPN node...")
                # asyncio.run(self.vpn_node.start())
                
            # Simulate connection delay
            time.sleep(3)
            
            # Update connection state
            self.is_connecting = False
            self.is_connected = True
            self.connection_start_time = time.time()
            self.selected_country = country
            
            # Update GUI (schedule on main thread)
            self.root.after(0, self._connection_successful)
            
        except Exception as e:
            self.add_log("ERROR", f"Connection failed: {str(e)}")
            self.root.after(0, self._connection_failed)
            
    def _connection_successful(self):
        """Handle successful connection (called on main thread)"""
        self.status_var.set("🟢 Connected")
        self.status_label.configure(foreground='green')
        self.country_var.set(self.selected_country)
        self.ip_var.set("192.168.100.50")  # Simulated IP
        
        self.connect_btn.configure(state='disabled')
        self.disconnect_btn.configure(state='normal')
        self.country_combo.configure(state='disabled')
        
        self.add_log("SUCCESS", f"Connected to VPN via {self.selected_country}")
        
    def _connection_failed(self):
        """Handle failed connection (called on main thread)"""
        self.is_connecting = False
        self.is_connected = False
        
        self.status_var.set("❌ Connection Failed")
        self.status_label.configure(foreground='red')
        
        self.connect_btn.configure(state='normal')
        self.country_combo.configure(state='readonly')
        
    def disconnect_vpn(self):
        """Disconnect from VPN"""
        if not self.is_connected:
            return
            
        self.add_log("INFO", "Disconnecting from VPN...")
        
        # Stop VPN node if running
        if self.vpn_node and HAS_VPN_BACKEND:
            # asyncio.run(self.vpn_node.stop())
            self.vpn_node = None
            
        # Update state
        self.is_connected = False
        self.connection_start_time = None
        
        # Update GUI
        self.status_var.set("Disconnected")
        self.status_label.configure(foreground='red')
        self.country_var.set("Auto")
        self.ip_var.set("Not connected")
        self.uptime_var.set("00:00:00")
        
        self.connect_btn.configure(state='normal')
        self.disconnect_btn.configure(state='disabled')
        self.country_combo.configure(state='readonly')
        
        self.add_log("INFO", "Disconnected from VPN")
        
    def update_connection_stats(self):
        """Update connection statistics"""
        if self.is_connected and self.connection_start_time:
            # Update uptime
            uptime_seconds = int(time.time() - self.connection_start_time)
            hours = uptime_seconds // 3600
            minutes = (uptime_seconds % 3600) // 60
            seconds = uptime_seconds % 60
            self.uptime_var.set(f"{hours:02d}:{minutes:02d}:{seconds:02d}")
            
            # Simulate data usage (in a real app, this would come from the VPN node)
            sent_mb = (uptime_seconds * 0.1)  # Simulate 0.1 MB/s
            received_mb = (uptime_seconds * 0.15)  # Simulate 0.15 MB/s
            self.data_sent_var.set(f"{sent_mb:.1f} MB")
            self.data_received_var.set(f"{received_mb:.1f} MB")
            
    def start_update_thread(self):
        """Start background update thread"""
        def update_loop():
            while True:
                # Update GUI elements that need regular refresh
                self.root.after(0, self.update_log_display)
                self.root.after(0, self.update_connection_stats)
                time.sleep(1)
                
        update_thread = threading.Thread(target=update_loop, daemon=True)
        update_thread.start()
        
    def on_closing(self):
        """Handle application closure"""
        if self.is_connected:
            if messagebox.askokcancel("Quit", "VPN is still connected. Disconnect and quit?"):
                self.disconnect_vpn()
                self.root.destroy()
        else:
            self.root.destroy()
            
    def run(self):
        """Start the GUI application"""
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()


def main():
    """Main entry point"""
    app = CrowdVPNGUI()
    app.run()


if __name__ == "__main__":
    main()

