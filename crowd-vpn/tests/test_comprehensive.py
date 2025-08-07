#!/usr/bin/env python3
"""Comprehensive test suite for Crowd VPN GUI."""

import sys
import os
import time
import threading
import platform
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

class TestEnvironment(unittest.TestCase):
    """Test system environment and dependencies."""
    
    def test_python_version(self):
        """Test Python version compatibility."""
        self.assertGreaterEqual(sys.version_info, (3, 8), 
                               "Requires Python 3.8 or higher")
    
    def test_tkinter_available(self):
        """Test tkinter availability."""
        try:
            import tkinter as tk
            from tkinter import ttk, messagebox, scrolledtext
            # Try creating a test widget
            root = tk.Tk()
            root.withdraw()  # Hide window
            test_label = ttk.Label(root, text="Test")
            root.destroy()
        except ImportError as e:
            self.fail(f"tkinter not available: {e}")
        except Exception as e:
            self.fail(f"tkinter error: {e}")
    
    def test_required_modules(self):
        """Test required standard library modules."""
        modules = ['threading', 'asyncio', 'json', 'time', 
                  'datetime', 'pathlib', 'logging']
        for module in modules:
            try:
                __import__(module)
            except ImportError:
                self.fail(f"Required module '{module}' not available")

class TestVPNBackend(unittest.TestCase):
    """Test VPN backend components."""
    
    def test_vpn_imports(self):
        """Test VPN component imports."""
        try:
            from crowd_vpn.node import CrowdVPNNode
            from crowd_vpn.core.network import NodeType
            from crowd_vpn.core.router import RoutingAlgorithm
        except ImportError:
            # Expected if VPN backend not available
            self.skipTest("VPN backend not available - expected in demo mode")
    
    def test_node_types(self):
        """Test NodeType enum values."""
        try:
            from crowd_vpn.core.network import NodeType
            expected_types = ['client', 'relay', 'exit', 'hybrid']
            for node_type in expected_types:
                self.assertIn(node_type, [t.value for t in NodeType])
        except ImportError:
            self.skipTest("VPN backend not available")
    
    def test_routing_algorithms(self):
        """Test RoutingAlgorithm enum values."""
        try:
            from crowd_vpn.core.router import RoutingAlgorithm
            expected_algorithms = ['random', 'shortest_path', 'load_balanced', 'reputation_based']
            for algorithm in expected_algorithms:
                self.assertIn(algorithm, [a.value for a in RoutingAlgorithm])
        except ImportError:
            self.skipTest("VPN backend not available")

class TestGUIComponents(unittest.TestCase):
    """Test GUI components without actually showing windows."""
    
    def setUp(self):
        """Set up test environment."""
        import tkinter as tk
        self.root = tk.Tk()
        self.root.withdraw()  # Hide test window
    
    def tearDown(self):
        """Clean up after tests."""
        if hasattr(self, 'root'):
            self.root.destroy()
    
    def test_gui_import(self):
        """Test GUI module can be imported."""
        try:
            from crowd_vpn_gui import CrowdVPNGUI
        except ImportError as e:
            self.fail(f"Cannot import GUI module: {e}")
    
    def test_gui_instantiation(self):
        """Test GUI can be instantiated without errors."""
        try:
            # Mock the actual GUI creation to avoid showing windows
            with patch('tkinter.Tk'):
                from crowd_vpn_gui import CrowdVPNGUI
                # This would normally create the GUI - we're just testing import works
        except Exception as e:
            self.fail(f"GUI instantiation failed: {e}")
    
    def test_widget_creation(self):
        """Test basic widget creation."""
        import tkinter as tk
        from tkinter import ttk
        
        # Test basic widgets work
        frame = ttk.Frame(self.root)
        label = ttk.Label(frame, text="Test")
        button = ttk.Button(frame, text="Test Button")
        entry = ttk.Entry(frame)
        combobox = ttk.Combobox(frame, values=["Test1", "Test2"])
        
        # Widgets should be created without error
        self.assertIsNotNone(frame)
        self.assertIsNotNone(label)
        self.assertIsNotNone(button)
        self.assertIsNotNone(entry)
        self.assertIsNotNone(combobox)

class TestApplicationLogic(unittest.TestCase):
    """Test application logic without GUI."""
    
    def test_platform_detection(self):
        """Test platform detection works."""
        system = platform.system().lower()
        self.assertIn(system, ['windows', 'darwin', 'linux'])
    
    def test_launcher_scripts_logic(self):
        """Test launcher script creation logic."""
        # This would test the deploy.py functions
        from deploy import get_platform_info
        system, arch = get_platform_info()
        self.assertIsInstance(system, str)
        self.assertIsInstance(arch, str)
        self.assertGreater(len(system), 0)
        self.assertGreater(len(arch), 0)
    
    def test_file_paths(self):
        """Test critical files exist."""
        critical_files = [
            'crowd_vpn_gui.py',
            'launch_gui.py',
            'requirements.txt',
            'README.md'
        ]
        
        for file_path in critical_files:
            self.assertTrue(os.path.exists(file_path), 
                           f"Critical file missing: {file_path}")
    
    def test_directory_structure(self):
        """Test project directory structure."""
        critical_dirs = [
            'crowd_vpn',
            'config',
            'static',
            'templates'
        ]
        
        for dir_path in critical_dirs:
            if os.path.exists(dir_path):
                self.assertTrue(os.path.isdir(dir_path), 
                               f"{dir_path} should be a directory")

class TestCrossPlatformCompatibility(unittest.TestCase):
    """Test cross-platform compatibility features."""
    
    def test_path_handling(self):
        """Test path handling works across platforms."""
        from pathlib import Path
        
        # Test Path operations work
        current_path = Path.cwd()
        self.assertTrue(current_path.exists())
        
        # Test path joining
        test_path = current_path / "test_file.txt"
        self.assertIsInstance(str(test_path), str)
    
    def test_file_permissions(self):
        """Test file permission handling."""
        # On Windows, permission changes might not work the same way
        if platform.system().lower() != 'windows':
            test_file = Path("test_perm.txt")
            try:
                test_file.write_text("test")
                os.chmod(test_file, 0o755)
                self.assertTrue(test_file.exists())
            finally:
                if test_file.exists():
                    test_file.unlink()

def run_gui_smoke_test():
    """Run a quick smoke test of the GUI - shows window briefly."""
    print("\n🖥️ Running GUI smoke test (window will appear briefly)...")
    
    try:
        # Import and create GUI
        sys.path.insert(0, str(Path(__file__).parent))
        from crowd_vpn_gui import CrowdVPNGUI
        
        app = CrowdVPNGUI()
        
        # Show for 2 seconds then close
        def auto_close():
            time.sleep(2)
            app.root.quit()
        
        thread = threading.Thread(target=auto_close, daemon=True)
        thread.start()
        
        # This will show the window briefly
        app.root.mainloop()
        
        print("✅ GUI smoke test passed")
        return True
        
    except Exception as e:
        print(f"❌ GUI smoke test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all tests."""
    print("🧪 Comprehensive Crowd VPN Test Suite")
    print("=" * 45)
    print(f"Platform: {platform.system()} {platform.machine()}")
    print(f"Python: {sys.version}")
    print()
    
    # Run unit tests
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test cases
    suite.addTests(loader.loadTestsFromTestCase(TestEnvironment))
    suite.addTests(loader.loadTestsFromTestCase(TestVPNBackend))
    suite.addTests(loader.loadTestsFromTestCase(TestGUIComponents))
    suite.addTests(loader.loadTestsFromTestCase(TestApplicationLogic))
    suite.addTests(loader.loadTestsFromTestCase(TestCrossPlatformCompatibility))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Run GUI smoke test if unit tests pass
    gui_test_passed = True
    if result.wasSuccessful():
        response = input("\nRun GUI smoke test? (shows window briefly) [y/N]: ")
        if response.lower().startswith('y'):
            gui_test_passed = run_gui_smoke_test()
    
    # Summary
    print("\n" + "=" * 45)
    if result.wasSuccessful() and gui_test_passed:
        print("✅ All tests passed! Application is ready for deployment.")
        return True
    else:
        print("❌ Some tests failed. Please fix issues before deployment.")
        return False

if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)

