#!/bin/bash

echo "[*] Enhanced DDoS Protection System Installer"
echo "----------------------------------------"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "This script must be run as root"
    exit 1
fi

# Install system dependencies
echo "[*] Installing system dependencies..."
if command -v apt-get &> /dev/null; then
    apt-get update
    apt-get install -y python3 python3-pip tcpdump iptables msmtp mailutils
elif command -v yum &> /dev/null; then
    yum install -y python3 python3-pip tcpdump iptables msmtp mailx
else
    echo "Unsupported package manager. Please install dependencies manually."
    exit 1
fi

# Install Python dependencies
echo "[*] Installing Python packages..."
pip3 install -r requirements.txt

# Create necessary directories
echo "[*] Setting up directories and files..."
mkdir -p /etc/ddos_protection
mkdir -p /var/log/ddos_protection

# Copy files to their locations
cp flood_detector.py /usr/local/bin/
cp config.yaml.example /etc/ddos_protection/config.yaml
cp ddos_protection.service /etc/systemd/system/

# Set permissions
chmod +x /usr/local/bin/flood_detector.py
chown root:root /usr/local/bin/flood_detector.py
chmod 644 /etc/systemd/system/ddos_protection.service
chmod 644 /etc/ddos_protection/config.yaml

# Create log files
touch /var/log/ddos_protection.log
touch /var/log/ddos_protection.error.log
chmod 644 /var/log/ddos_protection.log
chmod 644 /var/log/ddos_protection.error.log

# Reload systemd and enable service
echo "[*] Enabling and starting service..."
systemctl daemon-reload
systemctl enable ddos_protection.service
systemctl start ddos_protection.service

echo "[✓] Installation complete!"
echo "Edit /etc/ddos_protection/config.yaml to configure the system"
echo "View logs at /var/log/ddos_protection.log"
echo "Service status: systemctl status ddos_protection"