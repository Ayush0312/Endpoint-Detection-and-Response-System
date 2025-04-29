import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import yaml
import json
import os
import time
from typing import Dict, List
import logging
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
logger = logging.getLogger('EDR_Dashboard')

class EDRDashboard:
    def __init__(self):
        self.config = self._load_config()
        self.module_status = {}
        self.last_update = datetime.now()
        self.data_manager = DataManager()
        logger.info("EDRDashboard initialized")
        
    def _load_config(self) -> dict:
        """Load configuration from YAML file"""
        try:
            with open('config.yaml', 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logger.warning("Config file not found. Using default configuration.")
            return {
                'modules': {
                    'network_monitor': {'enabled': True},
                    'static_analysis': {'enabled': True},
                    'file_monitor': {'enabled': True}
                }
            }
    
    def update_module_status(self, status: Dict[str, bool]):
        """Update module status"""
        self.module_status = status
        self.last_update = datetime.now()
        logger.info(f"Updated module status: {status}")
    
    def run(self):
        """Run the Streamlit dashboard"""
        st.set_page_config(
            page_title="EDR System Dashboard",
            page_icon="🛡️",
            layout="wide"
        )
        
        st.title("EDR System Dashboard")
        logger.info("Starting dashboard")
        
        # Sidebar
        st.sidebar.title("Controls")
        refresh_interval = st.sidebar.slider(
            "Refresh Interval (seconds)",
            min_value=1,
            max_value=60,
            value=5
        )
        
        # Main content
        st.subheader("System Overview")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Active Modules", sum(self.module_status.values()))
        with col2:
            st.metric("Total Alerts", len(self.data_manager.get_alert_history()))
        with col3:
            st.metric("Last Update", self.last_update.strftime('%H:%M:%S'))
        
        # Module Status
        st.subheader("Module Status")
        status_data = []
        for module, is_running in self.module_status.items():
            status_data.append({
                "Module": module.replace('_', ' ').title(),
                "Status": "Running" if is_running else "Stopped",
                "Last Update": self.last_update.strftime('%Y-%m-%d %H:%M:%S')
            })
        
        status_df = pd.DataFrame(status_data)
        st.dataframe(status_df, use_container_width=True)
        
        # Module Details
        st.subheader("Module Details")
        
        # Network Monitor Section
        st.write("### Network Monitor")
        network_col1, network_col2 = st.columns(2)
        
        with network_col1:
            st.write("#### Network Traffic Analysis")
            network_data = self.data_manager.get_network_data()
            logger.info(f"Displaying network data: {network_data}")
            st.write(f"Packets Analyzed: {network_data['packets_analyzed']}")
            st.write(f"Suspicious Connections: {network_data['suspicious_connections']}")
            st.write(f"Blocked IPs: {len(network_data['blocked_ips'])}")
            
            # Network Protocol Distribution
            protocol_stats = network_data['protocol_stats']
            fig_protocols = px.pie(
                values=list(protocol_stats.values()),
                names=list(protocol_stats.keys()),
                title="Network Protocol Distribution"
            )
            st.plotly_chart(fig_protocols)
        
        with network_col2:
            st.write("#### Network Statistics")
            # Traffic Over Time
            traffic_history = network_data['traffic_history']
            if traffic_history:
                df_traffic = pd.DataFrame(traffic_history)
                fig_traffic = px.line(
                    df_traffic,
                    x='timestamp',
                    y='traffic',
                    title="Network Traffic Over Time",
                    labels={'timestamp': 'Time', 'traffic': 'Traffic Volume'}
                )
                st.plotly_chart(fig_traffic)
        
        # Static Analysis Section
        st.write("### Static Analysis")
        static_col1, static_col2 = st.columns(2)
        
        with static_col1:
            st.write("#### File Analysis Results")
            static_data = self.data_manager.get_static_analysis_data()
            logger.info(f"Displaying static analysis data: {static_data}")
            st.write(f"Files Analyzed: {static_data['files_analyzed']}")
            st.write(f"Malicious Files: {static_data['malicious_files']}")
            st.write(f"Suspicious Files: {static_data['suspicious_files']}")
            
            # File Type Distribution
            file_types = static_data['file_types']
            if file_types:
                fig_types = px.bar(
                    x=list(file_types.keys()),
                    y=list(file_types.values()),
                    title="File Type Distribution",
                    labels={'x': 'File Type', 'y': 'Count'}
                )
                st.plotly_chart(fig_types)
        
        with static_col2:
            st.write("#### Analysis Statistics")
            # Detection Rate Over Time
            detection_history = static_data['detection_history']
            if detection_history:
                df_detections = pd.DataFrame(detection_history)
                fig_detections = px.line(
                    df_detections,
                    x='timestamp',
                    y='detection',
                    title="Detection Rate Over Time",
                    labels={'timestamp': 'Time', 'detection': 'Detections'}
                )
                st.plotly_chart(fig_detections)
        
        # File Monitor Section
        st.write("### File Monitor")
        file_col1, file_col2 = st.columns(2)
        
        with file_col1:
            st.write("#### File System Changes")
            file_data = self.data_manager.get_file_monitor_data()
            logger.info(f"Displaying file monitor data: {file_data}")
            st.write(f"Monitored Directories: {file_data['monitored_dirs']}")
            st.write(f"Total Files: {file_data['total_files']}")
            st.write(f"Suspicious Changes: {file_data['suspicious_changes']}")
            
            # File Change Types
            change_types = file_data['change_types']
            fig_changes = px.pie(
                values=list(change_types.values()),
                names=list(change_types.keys()),
                title="File Change Distribution"
            )
            st.plotly_chart(fig_changes)
        
        with file_col2:
            st.write("#### Monitoring Statistics")
            # File Changes Over Time
            change_history = file_data['change_history']
            if change_history:
                df_changes = pd.DataFrame(change_history)
                fig_changes_time = px.line(
                    df_changes,
                    x='timestamp',
                    y='change',
                    title="File Changes Over Time",
                    labels={'timestamp': 'Time', 'change': 'Number of Changes'}
                )
                st.plotly_chart(fig_changes_time)
        
        # Recent Alerts
        st.subheader("Recent Alerts")
        alert_history = self.data_manager.get_alert_history()
        logger.info(f"Displaying alert history: {alert_history}")
        if alert_history:
            alert_df = pd.DataFrame(alert_history)
            st.dataframe(alert_df, use_container_width=True)
        else:
            st.info("No alerts yet")
        
        # Auto-refresh
        time.sleep(refresh_interval)
        st.rerun()

def main():
    dashboard = EDRDashboard()
    dashboard.run()

if __name__ == "__main__":
    main() 