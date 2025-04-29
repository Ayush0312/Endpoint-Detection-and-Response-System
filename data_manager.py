import threading
import queue
import json
from datetime import datetime
from typing import Dict, List, Any
import logging

logger = logging.getLogger('DataManager')

class DataManager:
    """
    Thread-safe data manager for sharing data between EDR modules.
    """
    def __init__(self):
        """Initialize the data manager with empty data structures"""
        self.network_data = {
            'packets_analyzed': 0,
            'suspicious_connections': 0,
            'blocked_ips': set(),
            'protocol_stats': {
                'HTTP': 0,
                'DNS': 0,
                'FTP': 0,
                'SSH': 0,
                'SMTP': 0,
                'Other': 0
            },
            'traffic_history': []
        }
        
        self.static_analysis_data = {
            'files_analyzed': 0,
            'malicious_files': 0,
            'suspicious_files': 0,
            'file_types': {},
            'detection_history': []
        }
        
        self.file_monitor_data = {
            'monitored_dirs': 0,
            'total_files': 0,
            'suspicious_changes': 0,
            'change_types': {
                'created': 0,
                'modified': 0,
                'deleted': 0,
                'accessed': 0
            },
            'change_history': []
        }
        
        self.alert_history = []
        self.lock = threading.Lock()
        logger.info("DataManager initialized")
    
    def update_network_stats(self, stats: Dict[str, Any]):
        """
        Update network monitoring statistics.
        
        Args:
            stats (Dict[str, Any]): Network statistics to update
        """
        with self.lock:
            logger.info(f"Updating network stats: {stats}")
            self.network_data['packets_analyzed'] = stats.get('packets_analyzed', 0)
            self.network_data['suspicious_connections'] = stats.get('suspicious_connections', 0)
            self.network_data['blocked_ips'].update(stats.get('blocked_ips', []))
            
            # Update protocol stats
            for protocol, count in stats.get('protocol_stats', {}).items():
                self.network_data['protocol_stats'][protocol] = count
            
            # Update traffic history
            if 'traffic' in stats:
                self.network_data['traffic_history'].append({
                    'timestamp': datetime.now(),
                    'traffic': stats['traffic']
                })
                # Keep only last 100 entries
                if len(self.network_data['traffic_history']) > 100:
                    self.network_data['traffic_history'] = self.network_data['traffic_history'][-100:]
    
    def update_static_analysis_stats(self, stats: Dict[str, Any]):
        """
        Update static analysis statistics.
        
        Args:
            stats (Dict[str, Any]): Static analysis statistics to update
        """
        with self.lock:
            logger.info(f"Updating static analysis stats: {stats}")
            self.static_analysis_data['files_analyzed'] = stats.get('files_analyzed', 0)
            self.static_analysis_data['malicious_files'] = stats.get('malicious_files', 0)
            self.static_analysis_data['suspicious_files'] = stats.get('suspicious_files', 0)
            
            # Update file type stats
            for file_type, count in stats.get('file_types', {}).items():
                self.static_analysis_data['file_types'][file_type] = count
            
            # Update detection history
            if 'detection' in stats:
                self.static_analysis_data['detection_history'].append({
                    'timestamp': datetime.now(),
                    'detection': stats['detection']
                })
                # Keep only last 100 entries
                if len(self.static_analysis_data['detection_history']) > 100:
                    self.static_analysis_data['detection_history'] = self.static_analysis_data['detection_history'][-100:]
    
    def update_file_monitor_stats(self, stats: Dict[str, Any]):
        """
        Update file monitoring statistics.
        
        Args:
            stats (Dict[str, Any]): File monitoring statistics to update
        """
        with self.lock:
            logger.info(f"Updating file monitor stats: {stats}")
            self.file_monitor_data['monitored_dirs'] = stats.get('monitored_dirs', 0)
            self.file_monitor_data['total_files'] = stats.get('total_files', 0)
            self.file_monitor_data['suspicious_changes'] = stats.get('suspicious_changes', 0)
            
            # Update change type stats
            for change_type, count in stats.get('change_types', {}).items():
                self.file_monitor_data['change_types'][change_type] = count
            
            # Update change history
            if 'change' in stats:
                self.file_monitor_data['change_history'].append({
                    'timestamp': datetime.now(),
                    'change': stats['change']
                })
                # Keep only last 100 entries
                if len(self.file_monitor_data['change_history']) > 100:
                    self.file_monitor_data['change_history'] = self.file_monitor_data['change_history'][-100:]
    
    def add_alert(self, alert: str):
        """
        Add a new alert to the history.
        
        Args:
            alert (str): Alert message to add
        """
        with self.lock:
            logger.info(f"Adding new alert: {alert}")
            self.alert_history.append({
                'timestamp': datetime.now(),
                'message': alert
            })
            # Keep only last 100 alerts
            if len(self.alert_history) > 100:
                self.alert_history = self.alert_history[-100:]
    
    def get_network_data(self) -> Dict[str, Any]:
        """
        Get current network monitoring data.
        
        Returns:
            Dict[str, Any]: Current network monitoring data
        """
        with self.lock:
            logger.info(f"Getting network data: {self.network_data}")
            return self.network_data.copy()
    
    def get_static_analysis_data(self) -> Dict[str, Any]:
        """
        Get current static analysis data.
        
        Returns:
            Dict[str, Any]: Current static analysis data
        """
        with self.lock:
            logger.info(f"Getting static analysis data: {self.static_analysis_data}")
            return self.static_analysis_data.copy()
    
    def get_file_monitor_data(self) -> Dict[str, Any]:
        """
        Get current file monitoring data.
        
        Returns:
            Dict[str, Any]: Current file monitoring data
        """
        with self.lock:
            logger.info(f"Getting file monitor data: {self.file_monitor_data}")
            return self.file_monitor_data.copy()
    
    def get_alert_history(self) -> List[Dict[str, Any]]:
        """
        Get alert history.
        
        Returns:
            List[Dict[str, Any]]: List of alerts
        """
        with self.lock:
            logger.info(f"Getting alert history: {self.alert_history}")
            return self.alert_history.copy() 