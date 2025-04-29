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

def initialize_data():
    """Initialize or get existing data manager"""
    if 'data_manager' not in st.session_state:
        st.session_state.data_manager = DataManager()
        logger.info("Initialized new data manager")
    return st.session_state.data_manager

def main():
    """Run the Streamlit dashboard"""
    st.set_page_config(
        page_title="EDR System Dashboard",
        page_icon="🛡️",
        layout="wide"
    )
    
    st.title("EDR System Dashboard")
    logger.info("Starting dashboard")
    
    # Initialize data manager
    data_manager = initialize_data()
    
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
        st.metric("Active Modules", 3)  # Hardcoded for now
    with col2:
        alert_history = data_manager.get_alert_history()
        st.metric("Total Alerts", len(alert_history))
    with col3:
        st.metric("Last Update", datetime.now().strftime('%H:%M:%S'))
    
    # Module Status
    st.subheader("Module Status")
    status_data = [
        {"Module": "Network Monitor", "Status": "Running", "Last Update": datetime.now().strftime('%Y-%m-%d %H:%M:%S')},
        {"Module": "Static Analysis", "Status": "Running", "Last Update": datetime.now().strftime('%Y-%m-%d %H:%M:%S')},
        {"Module": "File Monitor", "Status": "Running", "Last Update": datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    ]
    
    status_df = pd.DataFrame(status_data)
    st.dataframe(status_df, use_container_width=True)
    
    # Module Details
    st.subheader("Module Details")
    
    # Network Monitor Section
    st.write("### Network Monitor")
    network_col1, network_col2 = st.columns(2)
    
    with network_col1:
        st.write("#### Network Traffic Analysis")
        try:
            network_data = data_manager.get_network_data()
            logger.info(f"Displaying network data: {network_data}")
            st.write(f"Packets Analyzed: {network_data['packets_analyzed']}")
            st.write(f"Suspicious Connections: {network_data['suspicious_connections']}")
            st.write(f"Blocked IPs: {len(network_data['blocked_ips'])}")
            
            # Network Protocol Distribution
            protocol_stats = network_data['protocol_stats']
            if any(protocol_stats.values()):
                fig_protocols = px.pie(
                    values=list(protocol_stats.values()),
                    names=list(protocol_stats.keys()),
                    title="Network Protocol Distribution"
                )
                st.plotly_chart(fig_protocols)
            else:
                st.info("No network protocol data available yet")
        except Exception as e:
            st.error(f"Error displaying network data: {e}")
    
    with network_col2:
        st.write("#### Network Statistics")
        try:
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
            else:
                st.info("No traffic history available yet")
        except Exception as e:
            st.error(f"Error displaying network statistics: {e}")
    
    # Static Analysis Section
    st.write("### Static Analysis")
    static_col1, static_col2 = st.columns(2)
    
    with static_col1:
        st.write("#### File Analysis Results")
        try:
            static_data = data_manager.get_static_analysis_data()
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
            else:
                st.info("No file type data available yet")
        except Exception as e:
            st.error(f"Error displaying static analysis data: {e}")
    
    with static_col2:
        st.write("#### Analysis Statistics")
        try:
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
            else:
                st.info("No detection history available yet")
        except Exception as e:
            st.error(f"Error displaying analysis statistics: {e}")
    
    # File Monitor Section
    st.write("### File Monitor")
    file_col1, file_col2 = st.columns(2)
    
    with file_col1:
        st.write("#### File System Changes")
        try:
            file_data = data_manager.get_file_monitor_data()
            logger.info(f"Displaying file monitor data: {file_data}")
            st.write(f"Monitored Directories: {file_data['monitored_dirs']}")
            st.write(f"Total Files: {file_data['total_files']}")
            st.write(f"Suspicious Changes: {file_data['suspicious_changes']}")
            
            # File Change Types
            change_types = file_data['change_types']
            if any(change_types.values()):
                fig_changes = px.pie(
                    values=list(change_types.values()),
                    names=list(change_types.keys()),
                    title="File Change Distribution"
                )
                st.plotly_chart(fig_changes)
            else:
                st.info("No file changes detected yet")
        except Exception as e:
            st.error(f"Error displaying file monitor data: {e}")
    
    with file_col2:
        st.write("#### Monitoring Statistics")
        try:
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
            else:
                st.info("No change history available yet")
        except Exception as e:
            st.error(f"Error displaying monitoring statistics: {e}")
    
    # Recent Alerts
    st.subheader("Recent Alerts")
    try:
        alert_history = data_manager.get_alert_history()
        logger.info(f"Displaying alert history: {alert_history}")
        if alert_history:
            alert_df = pd.DataFrame(alert_history)
            st.dataframe(alert_df, use_container_width=True)
        else:
            st.info("No alerts yet")
    except Exception as e:
        st.error(f"Error displaying alerts: {e}")
    
    # Auto-refresh
    time.sleep(refresh_interval)
    st.rerun()

if __name__ == "__main__":
    main() 