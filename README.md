# Enhanced DDoS Protection System v2.0.0

A comprehensive DDoS protection system that combines adaptive threshold detection, connection tracking, resource monitoring, and advanced alerting features. This system is designed for production use and offers robust protection against various types of DDoS attacks.

## Key Features

- **Adaptive Threshold Detection**
  - Automatically adjusts detection thresholds based on traffic patterns
  - Uses statistical analysis with 3-sigma rule for anomaly detection
  - Learning rate adjustment for dynamic environments

- **Multi-Protocol Protection**
  - ICMP flood detection
  - SYN flood protection
  - UDP flood mitigation 
  - HTTP GET flood detection
  - DNS amplification attack prevention
  - Slowloris attack protection

- **Advanced Connection Tracking**
  - Monitors half-open connections
  - Tracks connection duration and patterns
  - Detects slow connection attacks
  - Configurable connection limits

- **Resource Monitoring**
  - Self-protection against resource exhaustion
  - CPU usage monitoring
  - Memory usage tracking
  - Automatic restart on resource threshold breach

- **Alerting System**
  - Email notifications with rate limiting
  - Telegram integration (optional)
  - Detailed attack information
  - Configurable alert intervals
  - Rate-limited notifications to prevent alert flooding

- **Health Check System**
  - HTTP API endpoints for monitoring
  - Real-time statistics
  - System status checks
  - Prometheus metrics support
  - Secure configuration endpoint

- **IP Management**
  - Automatic IP blocking
  - Configurable block duration
  - Persistent blocklist across restarts
  - IP whitelisting support
  - Automatic cleanup of expired blocks

## Requirements

### System Requirements
- Python 3.6+
- Linux system with iptables support
- Root/sudo privileges

### System Packages
```bash
# Debian/Ubuntu
apt-get install python3 python3-pip tcpdump iptables msmtp mailutils

# CentOS/RHEL
yum install python3 python3-pip tcpdump iptables msmtp mailx
```

### Python Dependencies
- See requirements.txt for complete list

## Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd ddos-protection
   ```

2. Install dependencies:
   ```bash
   sudo pip3 install -r requirements.txt
   ```

3. Run the installer:
   ```bash
   sudo ./install.sh
   ```

4. Configure the system:
   ```bash
   sudo cp config.yaml.example /etc/ddos_protection/config.yaml
   sudo nano /etc/ddos_protection/config.yaml
   ```

## Configuration

The system can be configured through:
- YAML configuration file (`/etc/ddos_protection/config.yaml`)
- Environment variables
- Command-line arguments

### Key Configuration Options

```yaml
# Attack thresholds
icmp_threshold: 20
syn_threshold: 30
udp_threshold: 40
http_get_threshold: 100
adaptive_factor: 1.5

# Resource limits
max_memory_mb: 512
max_cpu_percent: 80
max_tracked_ips: 10000

# Alert settings
smtp_server: "smtp.gmail.com"
smtp_port: 587
alert_interval: 600
enable_telegram: false

# Advanced features
enable_adaptive_thresholds: true
enable_connection_tracking: true
enable_resource_monitoring: true
```

## Usage

### Running as a Service

The system installs as a systemd service and starts automatically on boot:

```bash
# Start the service
sudo systemctl start ddos_protection

# Check status
sudo systemctl status ddos_protection

# View logs
sudo journalctl -u ddos_protection
```

### Manual Operation

Run directly with custom configuration:
```bash
sudo python3 flood_detector.py --config /path/to/config.yaml
```

### Health Check API

When enabled, provides HTTP endpoints:

- `GET /health` - Basic health check
- `GET /stats` - Current statistics and metrics
- `GET /config` - Current configuration (localhost only)

Example stats response:
```json
{
  "uptime": 3600,
  "blocked_ips_count": 5,
  "blocked_ips": {
    "192.168.1.100": 2,
    "10.0.0.5": 1
  },
  "attacks_detected": {
    "SYN_flood": 3,
    "ICMP_flood": 2
  }
}
```

## Monitoring

The system monitors:
- Network packet rates and patterns
- Connection states and durations
- System resource usage
- Request distributions
- Attack patterns and frequencies

### Logging

- Main log: `/var/log/ddos_protection.log`
- Error log: `/var/log/ddos_protection.error.log`
- Health check access log (if enabled)
- Rotated logs with configurable retention

## Security Considerations

1. **Permissions**
   - Run with appropriate privileges
   - Secure config file permissions
   - Protect log files

2. **Network Security**
   - Health check API restricted to localhost
   - Secure SMTP credentials
   - Protected configuration endpoint

3. **Resource Protection**
   - Memory usage limits
   - CPU usage monitoring
   - Connection tracking limits
   - Auto-cleanup of old data

## Troubleshooting

1. Check service status:
   ```bash
   sudo systemctl status ddos_protection
   ```

2. View logs:
   ```bash
   sudo tail -f /var/log/ddos_protection.log
   ```

3. Test configuration:
   ```bash
   sudo python3 flood_detector.py --test
   ```

4. Verify iptables rules:
   ```bash
   sudo iptables -L FLOOD_BLOCK -n
   ```

## Contributing

1. Fork the repository
2. Create your feature branch
3. Add tests for new features
4. Submit a pull request

## License

MIT License - See LICENSE file for details