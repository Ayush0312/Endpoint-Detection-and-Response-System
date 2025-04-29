# EDR (Endpoint Detection and Response) System

A comprehensive endpoint detection and response system built in Python that provides real-time monitoring, threat detection, and analysis capabilities for endpoint security.

## Features

### Network Monitoring
- Real-time network traffic analysis
- Protocol-specific monitoring (HTTP, DNS, FTP, SSH, SMTP)
- Suspicious pattern detection
- Network anomaly alerts

### Static Analysis
- Automated file scanning and analysis
- Machine learning-based threat detection
- Support for multiple file types (.exe, .dll, .bat, .ps1, .vbs)
- Periodic scanning of specified directories

### File System Monitoring
- Real-time file system activity monitoring
- Detection of file creation, modification, and deletion events
- Configurable watch paths and exclusions
- File size monitoring

### Interactive Dashboard
- Real-time visualization of system status
- Threat detection analytics
- System performance metrics
- Alert management interface

## Requirements

- Python 3.8 or higher
- Windows 10/11 (Some features are platform-specific)
- Network interface card for network monitoring
- Sufficient disk space for logs and analysis data

## Installation

1. Clone the repository:
```bash
git clone [repository-url]
cd edr_final
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
# Windows
.\venv\Scripts\activate
# Linux/MacOS
source venv/bin/activate
```

3. Install dependencies:
```bash
python install_dependencies.py
```

## Configuration

The system can be configured through the `config.yaml` file. Key configuration sections include:

- Network monitoring settings
- Static analysis parameters
- File monitoring paths
- Logging preferences
- Dashboard configuration

Example configuration:
```yaml
modules:
  network_monitor:
    enabled: true
    config:
      interface: "any"
      alert_threshold: 100
  
  static_analysis:
    enabled: true
    config:
      scan_interval: 300
      
  file_monitor:
    enabled: true
    config:
      watch_paths:
        - "."
```

## Usage

1. Start the EDR system:
```bash
python main.py
```

2. Launch the dashboard:
```bash
python -m streamlit run run_dashboard.py
```

3. Monitor the system through:
- Web dashboard (default: http://localhost:8501)
- System logs (edr_system.log)
- Console output

## Logging

Logs are stored in `edr_system.log` with the following information:
- System events
- Detected threats
- Module status
- Error messages

## Security Considerations

- The system requires administrative privileges for some features
- Network monitoring may require additional firewall configurations
- Ensure proper access controls for the dashboard
- Regularly update the system and its dependencies

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
