import os
import time
import logging
import threading
from typing import List, Set, Optional
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileModifiedEvent, FileDeletedEvent
from data_manager import DataManager
from static_analysis.file_checker import StaticAnalyzer

logger = logging.getLogger('FileMonitor')

class FileMonitorHandler(FileSystemEventHandler):
    def __init__(self, watch_paths: List[str], excluded_paths: List[str], alert_on: List[str], data_manager: DataManager):
        self.watch_paths = watch_paths
        self.excluded_paths = excluded_paths
        self.alert_on = alert_on
        self.data_manager = data_manager
        self.observer = None
        self.running = False
        self.static_analyzer = StaticAnalyzer(data_manager)
        self.stats = {
            'monitored_dirs': len(watch_paths),
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
        
    def should_monitor(self, path: str) -> bool:
        """Check if the path should be monitored"""
        # Check if path is in excluded paths
        for excluded in self.excluded_paths:
            if path.startswith(excluded):
                return False
        return True
    
    def _update_stats(self, change_type: str, path: str):
        """Update statistics for file system changes"""
        self.stats['change_types'][change_type] += 1
        self.stats['total_files'] = sum(1 for path in self.watch_paths 
                                      for root, _, files in os.walk(path) 
                                      for file in files)
        
        # Add to change history
        self.stats['change_history'].append({
            'timestamp': time.time(),
            'change': 1,
            'type': change_type,
            'path': path
        })
        
        # Keep only last 100 entries
        if len(self.stats['change_history']) > 100:
            self.stats['change_history'] = self.stats['change_history'][-100:]
        
        # Update data manager
        self.data_manager.update_file_monitor_stats(self.stats)
    
    def _should_analyze_file(self, file_path: str) -> bool:
        """Check if a file should be analyzed"""
        # Check file extension
        _, ext = os.path.splitext(file_path)
        ext = ext.lower()
        
        # List of file types to analyze
        analyzable_types = ['.exe', '.dll', '.bat', '.ps1', '.vbs']
        
        return ext in analyzable_types
    
    def _analyze_file(self, file_path: str):
        """Trigger static analysis for a file"""
        try:
            if not os.path.exists(file_path):
                logger.warning(f"File no longer exists: {file_path}")
                return
                
            if not self._should_analyze_file(file_path):
                logger.info(f"Skipping analysis of non-analyzable file: {file_path}")
                return
                
            logger.info(f"Analyzing file: {file_path}")
            # Start static analysis in a separate thread
            analysis_thread = threading.Thread(
                target=self.static_analyzer.analyze_file,
                args=(file_path,)
            )
            analysis_thread.daemon = True
            analysis_thread.start()
        except Exception as e:
            logger.error(f"Error analyzing file {file_path}: {e}")
    
    def on_created(self, event: FileCreatedEvent):
        if not isinstance(event, FileCreatedEvent):
            return
        if self.should_monitor(event.src_path) and 'file_creation' in self.alert_on:
            logger.warning(f"File created: {event.src_path}")
            self._update_stats('created', event.src_path)
            # Trigger static analysis for new files
            self._analyze_file(event.src_path)
    
    def on_modified(self, event: FileModifiedEvent):
        if not isinstance(event, FileModifiedEvent):
            return
        if self.should_monitor(event.src_path) and 'file_modification' in self.alert_on:
            logger.warning(f"File modified: {event.src_path}")
            self._update_stats('modified', event.src_path)
            # Trigger static analysis for modified files
            self._analyze_file(event.src_path)
    
    def on_deleted(self, event: FileDeletedEvent):
        if not isinstance(event, FileDeletedEvent):
            return
        if self.should_monitor(event.src_path) and 'file_deletion' in self.alert_on:
            logger.warning(f"File deleted: {event.src_path}")
            self._update_stats('deleted', event.src_path)

class FileMonitor:
    def __init__(self, watch_paths: List[str], excluded_paths: List[str], alert_on: List[str], data_manager: DataManager):
        self.handler = FileMonitorHandler(watch_paths, excluded_paths, alert_on, data_manager)
        self.observer = Observer()
        self.running = False
        
    def start_monitoring(self):
        """Start monitoring the specified paths"""
        if self.running:
            logger.warning("File monitor is already running")
            return
            
        self.running = True
        for path in self.handler.watch_paths:
            if os.path.exists(path):
                self.observer.schedule(self.handler, path, recursive=True)
                logger.info(f"Started monitoring: {path}")
            else:
                logger.warning(f"Path does not exist: {path}")
        
        self.observer.start()
        logger.info("File monitor started")
        
    def stop_monitoring(self):
        """Stop monitoring"""
        if not self.running:
            logger.warning("File monitor is not running")
            return
            
        self.running = False
        self.observer.stop()
        self.observer.join()
        logger.info("File monitor stopped")

if __name__ == "__main__":
    # Create a data manager instance for standalone testing
    data_manager = DataManager()
    monitor = FileMonitor(
        watch_paths=["."],
        excluded_paths=[],
        alert_on=['file_creation', 'file_modification', 'file_deletion'],
        data_manager=data_manager
    )
    monitor.start_monitoring()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        monitor.stop_monitoring() 