import os
import sys
import threading
import queue
import logging
import yaml
from datetime import datetime
from typing import Dict, List, Optional
import json
import time
import signal
import atexit

# Import modules
from edr_network.agent import NetworkMonitor
from static_analysis.file_checker import StaticAnalyzer
from file_monitor.file_monitor import FileMonitor
from data_manager import DataManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('edr_system.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('EDR_System')

class EDRController:
    """
    Main controller for the EDR system that manages all modules and their interactions.
    """
    def __init__(self, config_path: str = 'config.yaml'):
        """
        Initialize the EDR controller with configuration and modules.
        
        Args:
            config_path (str): Path to the configuration file
        """
        self.config = self._load_config(config_path)
        self.modules: Dict[str, threading.Thread] = {}
        self.alert_queue = queue.Queue()
        self.running = False
        self.shutdown_event = threading.Event()
        
        # Initialize data manager
        self.data_manager = DataManager()
        
        # Initialize modules with data manager
        self.network_monitor = NetworkMonitor(data_manager=self.data_manager)
        self.static_analyzer = StaticAnalyzer(data_manager=self.data_manager)
        self.file_monitor = FileMonitor(
            watch_paths=self.config['modules']['file_monitor']['config']['watch_paths'],
            excluded_paths=self.config['modules']['file_monitor']['config']['excluded_paths'],
            alert_on=self.config['modules']['file_monitor']['config']['alert_on'],
            data_manager=self.data_manager
        )
        
        # Register shutdown handler
        atexit.register(self.stop_all)
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
    def _load_config(self, config_path: str) -> dict:
        """
        Load configuration from YAML file.
        
        Args:
            config_path (str): Path to the configuration file
            
        Returns:
            dict: Configuration dictionary
        """
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logger.warning(f"Config file {config_path} not found. Using default configuration.")
            return {
                'modules': {
                    'network_monitor': {'enabled': True},
                    'static_analysis': {'enabled': True},
                    'file_monitor': {'enabled': True}
                }
            }
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        logger.info(f"Received signal {signum}")
        self.stop_all()
        sys.exit(0)
    
    def start_module(self, module_name: str):
        """
        Start a specific module in a separate thread.
        
        Args:
            module_name (str): Name of the module to start
        """
        if module_name in self.modules and self.modules[module_name].is_alive():
            logger.warning(f"Module {module_name} is already running")
            return
            
        if module_name == 'network_monitor':
            thread = threading.Thread(target=self.network_monitor.start_monitoring)
        elif module_name == 'static_analysis':
            thread = threading.Thread(target=self.static_analyzer.start_analysis)
        elif module_name == 'file_monitor':
            thread = threading.Thread(target=self.file_monitor.start_monitoring)
        else:
            logger.error(f"Unknown module: {module_name}")
            return
            
        thread.daemon = True
        thread.start()
        self.modules[module_name] = thread
        logger.info(f"Started {module_name}")
    
    def stop_module(self, module_name: str):
        """
        Stop a specific module gracefully.
        
        Args:
            module_name (str): Name of the module to stop
        """
        if module_name not in self.modules:
            logger.warning(f"Module {module_name} is not running")
            return
            
        if module_name == 'network_monitor':
            self.network_monitor.stop_monitoring()
        elif module_name == 'static_analysis':
            self.static_analyzer.stop_analysis()
        elif module_name == 'file_monitor':
            self.file_monitor.stop_monitoring()
        
        self.modules[module_name].join(timeout=5)
        del self.modules[module_name]
        logger.info(f"Stopped {module_name}")
    
    def start_all(self):
        """Start all enabled modules"""
        self.running = True
        self.shutdown_event.clear()
        
        for module_name, config in self.config['modules'].items():
            if config.get('enabled', True):
                self.start_module(module_name)
        
        # Start alert processing
        self.alert_thread = threading.Thread(target=self.process_alerts)
        self.alert_thread.daemon = True
        self.alert_thread.start()
    
    def stop_all(self):
        """Stop all running modules gracefully"""
        logger.info("Stopping all modules...")
        self.running = False
        self.shutdown_event.set()
        
        for module_name in list(self.modules.keys()):
            self.stop_module(module_name)
        
        logger.info("All modules stopped")
    
    def get_status(self) -> Dict[str, bool]:
        """
        Get status of all modules.
        
        Returns:
            Dict[str, bool]: Dictionary mapping module names to their running status
        """
        return {
            name: thread.is_alive() 
            for name, thread in self.modules.items()
        }
    
    def process_alerts(self):
        """Process alerts from all modules"""
        while self.running and not self.shutdown_event.is_set():
            try:
                alert = self.alert_queue.get(timeout=1)
                logger.warning(f"ALERT: {alert}")
                # Update data manager with new alert
                self.data_manager.add_alert(alert)
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error processing alert: {e}")

def main():
    """Main entry point for the EDR system"""
    controller = EDRController()
    
    try:
        # Start all modules
        controller.start_all()
        
        # Simple console UI
        while True:
            print("\nEDR System Control Panel")
            print("1. Show Status")
            print("2. Start Network Monitor")
            print("3. Stop Network Monitor")
            print("4. Start Static Analysis")
            print("5. Stop Static Analysis")
            print("6. Start File Monitor")
            print("7. Stop File Monitor")
            print("8. Exit")
            
            choice = input("\nEnter your choice (1-8): ")
            
            if choice == '1':
                status = controller.get_status()
                print("\nModule Status:")
                for module, is_running in status.items():
                    print(f"{module}: {'Running' if is_running else 'Stopped'}")
            
            elif choice == '2':
                controller.start_module('network_monitor')
            elif choice == '3':
                controller.stop_module('network_monitor')
            elif choice == '4':
                controller.start_module('static_analysis')
            elif choice == '5':
                controller.stop_module('static_analysis')
            elif choice == '6':
                controller.start_module('file_monitor')
            elif choice == '7':
                controller.stop_module('file_monitor')
            elif choice == '8':
                break
            
    except KeyboardInterrupt:
        print("\nShutting down EDR system...")
    finally:
        controller.stop_all()

if __name__ == "__main__":
    main() 