#!/usr/bin/env python3
import os
import time
import smtplib
import subprocess
import threading
import re
import signal
import sys
import shutil
import json
import socket
import logging
import logging.handlers
import ipaddress
import argparse
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import defaultdict, deque, Counter
from datetime import datetime
from netfilterqueue import NetfilterQueue
from scapy.all import IP, IPv6, TCP, ICMP, UDP
import requests
import math
from typing import Dict, Deque, Tuple, Optional
import numpy as np
from dataclasses import dataclass
from functools import wraps

# Optional imports with graceful fallback
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Global variables and statistics
VERSION = "2.0.0"
DEFAULT_CONFIG_FILE = "./config.yaml"
STATS = {
    "start_time": time.time(),
    "blocked_ips": Counter(),
    "alerts_sent": 0,
    "attacks_detected": Counter(),
    "errors": Counter(),
    "traffic_baseline": defaultdict(lambda: deque(maxlen=1000))
}

# Global shared resources
blocked_ips_set = set()
alerted_ips = {}
resource_lock = threading.RLock()
MAX_TRACKED_IPS = 10000
CLEANUP_INTERVAL = 3600
packet_counts = defaultdict(lambda: defaultdict(int))

# Set up main logger
logger = logging.getLogger("ddos_protection.detector")

# Default configuration
DEFAULT_CONFIG = {
    # Log settings
    "log_file": "./ddos_protection.log",
    "log_level": "INFO",
    "log_max_size": 10485760,  # 10MB
    "log_backup_count": 5,
    
    # Resource limits
    "max_memory_mb": 512,
    "max_cpu_percent": 80,
    "max_tracked_ips": MAX_TRACKED_IPS,
    "cleanup_interval": CLEANUP_INTERVAL,
    
    # Attack thresholds
    "icmp_threshold": 20,
    "syn_threshold": 30,
    "udp_threshold": 40,
    "http_get_threshold": 100,
    "adaptive_factor": 1.5,
    
    # Monitoring settings
    "monitor_interval": 1,
    "block_time": 60,
    "alert_interval": 600,
    
    # Email settings
    "smtp_server": "",
    "smtp_port": 587,
    "smtp_user": "",
    "smtp_password": "",
    "alert_email": "admin@example.com",
    
    # Telegram settings
    "enable_telegram": False,
    "telegram_bot_token": "", #add telegram bot-token here
    "telegram_chat_id": "",   #add telegram chat_id here
    
    # Advanced features
    "enable_adaptive_thresholds": True,
    "enable_connection_tracking": True,
    "enable_resource_monitoring": True,
    "enable_request_distribution": True,
    
    # Chain name
    "iptables_chain_name": "FLOOD_BLOCK"
}

@dataclass
class TrafficStats:
    mean: float = 0.0
    std_dev: float = 0.0
    last_update: float = 0.0

class AdaptiveThresholdDetector:
    def __init__(self, min_threshold: int, window_size: int = 60, learning_rate: float = 0.1):
        self.min_threshold = min_threshold
        self.window_size = window_size
        self.learning_rate = learning_rate
        self.traffic_stats: Dict[str, TrafficStats] = defaultdict(TrafficStats)
        self.traffic_history: Dict[str, Deque[Tuple[float, int]]] = defaultdict(
            lambda: deque(maxlen=1000)
        )

    def update_baseline(self, ip: str, current_time: float) -> None:
        """Update baseline statistics for an IP"""
        history = self.traffic_history[ip]
        if not history:
            return

        # Remove old entries
        while history and (current_time - history[0][0]) > self.window_size:
            history.popleft()

        if not history:
            return

        # Calculate rates
        rates = [count for _, count in history]
        
        # Update running statistics using exponential moving average
        stats = self.traffic_stats[ip]
        if stats.last_update == 0:
            stats.mean = np.mean(rates)
            stats.std_dev = np.std(rates) if len(rates) > 1 else 0
        else:
            stats.mean = (1 - self.learning_rate) * stats.mean + self.learning_rate * rates[-1]
            stats.std_dev = (1 - self.learning_rate) * stats.std_dev + self.learning_rate * abs(rates[-1] - stats.mean)
        
        stats.last_update = current_time

    def is_attack(self, ip: str, count: int, current_time: float) -> Tuple[bool, Optional[str]]:
        """
        Detect if current traffic constitutes an attack using adaptive thresholds
        Returns: (is_attack, detail_message)
        """
        # Update traffic history
        self.traffic_history[ip].append((current_time, count))
        self.update_baseline(ip, current_time)
        
        stats = self.traffic_stats[ip]
        
        # Use dynamic threshold based on statistical properties
        dynamic_threshold = max(
            self.min_threshold,
            math.ceil(stats.mean + 3 * stats.std_dev)  # 3-sigma rule
        )
        
        if count > dynamic_threshold:
            detail = (
                f"Traffic rate {count}/s exceeds dynamic threshold {dynamic_threshold}/s "
                f"(baseline: {stats.mean:.1f}/s ± {stats.std_dev:.1f})"
            )
            return True, detail
        
        return False, None

class RequestDistributionDetector:
    """Detects unusual patterns in request distribution"""
    
    def __init__(self, window_size: int = 60):
        self.window_size = window_size
        self.request_patterns: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self.last_cleanup = time.time()

    def add_request(self, ip: str, path: str, method: str, user_agent: str) -> Tuple[bool, Optional[str]]:
        """
        Analyze a request for suspicious patterns
        Returns: (is_suspicious, detail_message)
        """
        current_time = time.time()
        
        # Cleanup old patterns periodically
        if current_time - self.last_cleanup > 3600:  # Every hour
            self._cleanup_old_patterns()
            self.last_cleanup = current_time
        
        # Track patterns
        pattern_key = f"{method}:{path}:{user_agent}"
        self.request_patterns[ip][pattern_key] += 1
        
        # Check for suspicious patterns
        patterns = self.request_patterns[ip]
        total_requests = sum(patterns.values())
        
        # Detect highly repetitive patterns
        if total_requests > 100:  # Only check after sufficient samples
            most_common = max(patterns.values())
            if most_common / total_requests > 0.95:  # 95% same pattern
                return True, f"Highly repetitive traffic pattern detected ({most_common}/{total_requests} identical requests)"
        
        return False, None

    def _cleanup_old_patterns(self) -> None:
        """Remove old pattern data to prevent memory growth"""
        self.request_patterns.clear()

class ConnectionTracker:
    """Tracks connection statistics for detecting slow attacks"""
    
    def __init__(self, max_tracking_time: int = 3600):
        self.max_tracking_time = max_tracking_time
        self.connections: Dict[str, Dict[str, float]] = defaultdict(dict)
        self.last_cleanup = time.time()

    def track_connection(self, ip: str, conn_id: str, current_time: float) -> None:
        """Track a new connection"""
        self.connections[ip][conn_id] = current_time
        
        # Periodic cleanup
        if current_time - self.last_cleanup > 300:  # Every 5 minutes
            self._cleanup_old_connections(current_time)
            self.last_cleanup = current_time

    def get_connection_stats(self, ip: str, current_time: float) -> Tuple[int, float]:
        """
        Get connection statistics for an IP
        Returns: (active_connections, oldest_connection_age)
        """
        if ip not in self.connections:
            return 0, 0
        
        # Clean up old connections first
        connections = self.connections[ip]
        active_conns = {
            conn_id: start_time 
            for conn_id, start_time in connections.items()
            if current_time - start_time <= self.max_tracking_time
        }
        
        if not active_conns:
            return 0, 0
        
        oldest_age = current_time - min(active_conns.values())
        return len(active_conns), oldest_age

    def _cleanup_old_connections(self, current_time: float) -> None:
        """Remove old connection data"""
        for ip in list(self.connections.keys()):
            conns = self.connections[ip]
            active_conns = {
                conn_id: start_time
                for conn_id, start_time in conns.items()
                if current_time - start_time <= self.max_tracking_time
            }
            if active_conns:
                self.connections[ip] = active_conns
            else:
                del self.connections[ip]

class ResourceMonitor:
    """Monitors system resource usage patterns"""
    
    def __init__(self, window_size: int = 300):  # 5-minute window
        self.window_size = window_size
        self.resource_history: Dict[str, Deque[Tuple[float, float]]] = defaultdict(
            lambda: deque(maxlen=100)
        )

    def add_measurement(self, resource_type: str, value: float, current_time: float) -> Tuple[bool, Optional[str]]:
        """
        Add a resource measurement and check for unusual patterns
        Returns: (is_suspicious, detail_message)
        """
        history = self.resource_history[resource_type]
        history.append((current_time, value))
        
        # Remove old entries
        while history and (current_time - history[0][0]) > self.window_size:
            history.popleft()
        
        # Need at least 10 measurements for meaningful analysis
        if len(history) < 10:
            return False, None
        
        values = [v for _, v in history]
        mean = np.mean(values)
        std_dev = np.std(values)
        
        # Check for sudden spikes
        if abs(value - mean) > 3 * std_dev:
            return True, f"Unusual {resource_type} usage pattern detected: {value:.1f} (baseline: {mean:.1f} ± {std_dev:.1f})"
        
        return False, None

def process_packet(pkt):
    """Enhanced packet processing with adaptive thresholds"""
    global packet_counts
    pkt_data = pkt.get_payload()
    scapy_pkt = IP(pkt_data) if pkt_data[0] >> 4 == 4 else IPv6(pkt_data)
    
    ip_src = scapy_pkt.src
    current_time = time.time()

    with resource_lock:
        if ICMP in scapy_pkt:
            packet_counts[ip_src]['ICMP'] += 1
            if config["enable_adaptive_thresholds"]:
                is_attack, detail = adaptive_detector.is_attack(ip_src, packet_counts[ip_src]['ICMP'], current_time)
                if is_attack:
                    block_ip(ip_src, "ICMP (Adaptive)", detail)
        
        elif TCP in scapy_pkt:
            tcp = scapy_pkt[TCP]
            if tcp.flags & 0x02 and not tcp.flags & 0x10:  # SYN set and ACK not set
                packet_counts[ip_src]['SYN'] += 1
                if config["enable_connection_tracking"]:
                    conn_id = f"{ip_src}:{tcp.sport}->{scapy_pkt[IP].dst}:{tcp.dport}"
                    connection_tracker.track_connection(ip_src, conn_id, current_time)
                    conn_count, oldest_age = connection_tracker.get_connection_stats(ip_src, current_time)
                    if conn_count > config.get("max_concurrent_connections", 1000):
                        block_ip(ip_src, "Connection Flood", f"{conn_count} concurrent connections")
        
        elif UDP in scapy_pkt:
            packet_counts[ip_src]['UDP'] += 1
            if config["enable_adaptive_thresholds"]:
                is_attack, detail = adaptive_detector.is_attack(ip_src, packet_counts[ip_src]['UDP'], current_time)
                if is_attack:
                    block_ip(ip_src, "UDP (Adaptive)", detail)
    
    pkt.accept()

def monitor_loop():
    """Enhanced monitoring loop with all detection features"""
    while True:
        time.sleep(config["monitor_interval"])
        current_time = time.time()
        
        with resource_lock:
            for ip, counts in packet_counts.items():
                # Check ICMP flood
                if counts['ICMP'] > config["icmp_threshold"]:
                    block_ip(ip, "ICMP Flood", f"{counts['ICMP']} packets/sec")
                
                # Check SYN flood
                if counts['SYN'] > config["syn_threshold"]:
                    block_ip(ip, "SYN Flood", f"{counts['SYN']} packets/sec")
                
                # Check UDP flood
                if counts['UDP'] > config["udp_threshold"]:
                    block_ip(ip, "UDP Flood", f"{counts['UDP']} packets/sec")
                
                # Resource monitoring
                if config["enable_resource_monitoring"]:
                    for resource_type in ["memory", "cpu", "connections"]:
                        is_suspicious, detail = resource_monitor.add_measurement(
                            resource_type, 
                            sum(counts.values()), 
                            current_time
                        )
                        if is_suspicious:
                            logger.warning(f"Resource alert for {ip}: {detail}")
            
            packet_counts.clear()

def block_ip(ip: str, attack_type: str = "unknown", detail: str = ""):
    """Enhanced IP blocking with alerts"""
    if not validate_ip_address(ip):
        logger.warning(f"Invalid IP address, not blocking: {ip}")
        return False
    
    with resource_lock:
        if ip in blocked_ips_set:
            return True
        
        try:
            subprocess.run(
                ["iptables", "-A", config["iptables_chain_name"], "-s", ip, "-j", "DROP"],
                check=True, capture_output=True
            )
            blocked_ips_set.add(ip)
            STATS["blocked_ips"][ip] += 1
            STATS["attacks_detected"][attack_type] += 1
            
            logger.info(f"Blocked {ip} - {attack_type}: {detail}")
            
            # Send alerts
            if config.get("enable_email_alerts"):
                send_email_alert(ip, attack_type, detail)
            
            if config.get("enable_telegram") and config.get("telegram_bot_token"):
                send_telegram_alert(ip, attack_type, detail)
            
            # Set unblock timer
            threading.Timer(config["block_time"], unblock_ip, args=[ip]).start()
            
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to block {ip}: {e.stderr.decode().strip()}")
            return False

def send_telegram_alert(ip: str, attack_type: str, detail: str):
    """Send alert via Telegram"""
    if not config.get("telegram_bot_token") or not config.get("telegram_chat_id"):
        return
    
    with resource_lock:
        now = time.time()
        if ip in alerted_ips and now - alerted_ips[ip] < config["alert_interval"]:
            return
        alerted_ips[ip] = now
    
    text = f"🚨 *DDoS Alert*\nType: {attack_type}\nIP: `{ip}`\nDetail: {detail}"
    
    try:
        url = f"https://api.telegram.org/bot{config['telegram_bot_token']}/sendMessage"
        data = {
            "chat_id": config["telegram_chat_id"],
            "text": text,
            "parse_mode": "Markdown"
        }
        requests.post(url, json=data, timeout=5)
        logger.info(f"Telegram alert sent for {ip}")
    except Exception as e:
        logger.error(f"Failed to send Telegram alert: {e}")

def setup_iptables():
    """Setup iptables chain for packet filtering"""
    chain_name = config["iptables_chain_name"]
    
    try:
        # Create chain if it doesn't exist
        subprocess.run(["iptables", "-N", chain_name], stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        pass  # Chain might already exist
    
    try:
        # Add jump rule if it doesn't exist
        subprocess.run(["iptables", "-C", "INPUT", "-j", chain_name], stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        subprocess.run(["iptables", "-I", "INPUT", "-j", chain_name], check=True)
    
    logger.info(f"Initialized iptables chain: {chain_name}")
    return True

def graceful_exit(signum, frame):
    """Cleanup and exit gracefully"""
    logger.info("Shutting down gracefully...")
    
    try:
        # Clean up iptables
        subprocess.run(["iptables", "-F", config["iptables_chain_name"]], stderr=subprocess.DEVNULL)
        subprocess.run(["iptables", "-X", config["iptables_chain_name"]], stderr=subprocess.DEVNULL)
    except Exception as e:
        logger.error(f"Error cleaning up iptables: {e}")
    
    sys.exit(0)

def setup_logging():
    """Configure logging with rotation"""
    logger.setLevel(getattr(logging, config["log_level"]))
    
    # Console handler
    console = logging.StreamHandler()
    console.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
    logger.addHandler(console)
    
    # File handler with rotation
    if config["log_file"]:
        file_handler = logging.handlers.RotatingFileHandler(
            config["log_file"],
            maxBytes=config["log_max_size"],
            backupCount=config["log_backup_count"]
        )
        file_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
        logger.addHandler(file_handler)

def load_config(config_file=None):
    """Load configuration from file and environment variables"""
    cfg = DEFAULT_CONFIG.copy()
    
    if config_file and os.path.exists(config_file) and YAML_AVAILABLE:
        try:
            with open(config_file, 'r') as f:
                file_config = yaml.safe_load(f)
                if file_config:
                    cfg.update(file_config)
        except Exception as e:
            logger.error(f"Error loading config file: {e}")
    
    # Override with environment variables
    env_mapping = {
        "SMTP_SERVER": "smtp_server",
        "SMTP_PORT": ("smtp_port", int),
        "SMTP_USER": "smtp_user",
        "SMTP_PASSWORD": "smtp_password",
        "ALERT_EMAIL": "alert_email",
        "ICMP_THRESHOLD": ("icmp_threshold", int),
        "SYN_THRESHOLD": ("syn_threshold", int),
        "UDP_THRESHOLD": ("udp_threshold", int),
        "BLOCK_TIME": ("block_time", int),
        "LOG_FILE": "log_file",
        "IPTABLES_CHAIN_NAME": "iptables_chain_name"
    }
    
    for env_var, config_key in env_mapping.items():
        if isinstance(config_key, tuple):
            config_key, converter = config_key
        else:
            converter = str
            
        if os.getenv(env_var):
            try:
                cfg[config_key] = converter(os.getenv(env_var))
            except Exception as e:
                logger.error(f"Error converting environment variable {env_var}: {e}")
    
    return cfg

def monitor_resource_usage():
    """Monitor the script's own resource usage"""
    logger.info("Starting resource usage monitor...")
    
    while True:
        try:
            # Check memory usage
            result = subprocess.run(['ps', '-o', '%mem', '-p', str(os.getpid())], 
                                  capture_output=True, text=True, check=True)
            output = result.stdout.strip().split('\n')
            if len(output) >= 2:
                mem_percent = float(output[1].strip())
                if mem_percent > config["max_memory_mb"] / os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES') * 100:
                    logger.critical(f"Memory usage too high ({mem_percent}%). Restarting...")
                    os.kill(os.getpid(), signal.SIGTERM)
            
            # Check CPU usage
            result = subprocess.run(['ps', '-o', '%cpu', '-p', str(os.getpid())], 
                                  capture_output=True, text=True, check=True)
            output = result.stdout.strip().split('\n')
            if len(output) >= 2:
                cpu_percent = float(output[1].strip())
                if cpu_percent > config["max_cpu_percent"]:
                    logger.critical(f"CPU usage too high ({cpu_percent}%). Restarting...")
                    os.kill(os.getpid(), signal.SIGTERM)
            
        except Exception as e:
            logger.error(f"Error monitoring resource usage: {e}")
        
        time.sleep(30)  # Check every 30 seconds

def start_health_check_server():
    """Start health check server for monitoring"""
    if not config.get("enable_health_check"):
        return
    
    try:
        import http.server
        import socketserver
        from urllib.parse import urlparse
        
        class HealthCheckHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass
            
            def do_GET(self):
                parsed_path = urlparse(self.path)
                path = parsed_path.path
                
                if path == '/health':
                    self.send_response(200)
                    self.send_header('Content-type', 'text/plain')
                    self.end_headers()
                    self.wfile.write(b"OK")
                
                elif path == '/stats':
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    
                    with resource_lock:
                        stats_data = {
                            "uptime": int(time.time() - STATS["start_time"]),
                            "blocked_ips_count": len(blocked_ips_set),
                            "blocked_ips": dict(STATS["blocked_ips"]),
                            "alerts_sent": STATS["alerts_sent"],
                            "attacks_detected": dict(STATS["attacks_detected"]),
                            "errors": dict(STATS["errors"]),
                            "version": VERSION
                        }
                    
                    self.wfile.write(json.dumps(stats_data, indent=2).encode())
                
                else:
                    self.send_response(404)
                    self.send_header('Content-type', 'text/plain')
                    self.end_headers()
                    self.wfile.write(b"Not Found")
        
        def run_server():
            port = config.get("health_check_port", 8080)
            with socketserver.TCPServer(("localhost", port), HealthCheckHandler) as httpd:
                logger.info(f"Health check server started on port {port}")
                httpd.serve_forever()
        
        threading.Thread(target=run_server, daemon=True).start()
    
    except Exception as e:
        logger.error(f"Failed to start health check server: {e}")

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="Enhanced DDoS Protection System")
    parser.add_argument("--config", "-c", help="Path to configuration file", default=DEFAULT_CONFIG_FILE)
    parser.add_argument("--version", "-v", action="version", version=f"DDoS Protection v{VERSION}")
    parser.add_argument("--test", "-t", action="store_true", help="Test mode - validate config and exit")
    return parser.parse_args()

def print_banner():
    """Print a startup banner with basic info"""
    banner = f"""
    ╔══════════════════════════════════════════════════╗
    ║           Enhanced DDoS Protection v{VERSION}         ║
    ║                by TechGirlNerd                   ║
    ╚══════════════════════════════════════════════════╝
    
    Monitoring for:
    - HTTP GET floods
    - Slowloris attacks
    - DNS amplification
    - SYN floods
    - UDP floods
    
    Press Ctrl+C to exit
    """
    print(banner)

# Update main() function with new features
def main():
    """Enhanced main function with all features enabled"""
    global config
    
    # Parse arguments and load config
    args = parse_arguments()
    config = load_config(args.config)
    
    # Setup logging
    setup_logging()
    
    # Print banner
    print_banner()
    
    # Initialize detectors
    adaptive_detector = AdaptiveThresholdDetector(
        min_threshold=min(
            config["icmp_threshold"],
            config["syn_threshold"],
            config["udp_threshold"]
        )
    )
    connection_tracker = ConnectionTracker()
    resource_monitor = ResourceMonitor()
    
    # Register signal handlers
    signal.signal(signal.SIGINT, graceful_exit)
    signal.signal(signal.SIGTERM, graceful_exit)
    
    # Setup components
    setup_iptables()
    start_health_check_server()
    
    # Start monitoring threads
    monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
    monitor_thread.start()
    
    if config["enable_resource_monitoring"]:
        resource_thread = threading.Thread(target=monitor_resource_usage, daemon=True)
        resource_thread.start()
    
    logger.info(f"Enhanced DDoS Protection v{VERSION} initialized and running")
    
    try:
        nfqueue = NetfilterQueue()
        nfqueue.bind(0, process_packet)
        nfqueue.run()
    except KeyboardInterrupt:
        graceful_exit(None, None)

if __name__ == '__main__':
    main()
