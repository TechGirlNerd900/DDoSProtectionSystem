#!/usr/bin/env python3
import os
import json
import time
from datetime import datetime
from flask import Flask, render_template, jsonify, send_from_directory
import threading
import logging
from collections import defaultdict
import queue

app = Flask(__name__)
log_queue = queue.Queue(maxsize=1000)  # Store last 1000 log entries
stats_data = {
    "attacks_by_type": defaultdict(int),
    "blocked_ips": defaultdict(int),
    "traffic_patterns": defaultdict(list),
    "resource_usage": {
        "cpu": [],
        "memory": []
    }
}

# Create templates directory
os.makedirs(os.path.join(os.path.dirname(__file__), 'templates'), exist_ok=True)

class WebLogHandler(logging.Handler):
    def emit(self, record):
        try:
            log_entry = {
                'timestamp': datetime.fromtimestamp(record.created).strftime('%Y-%m-%d %H:%M:%S'),
                'level': record.levelname,
                'message': record.getMessage(),
                'source': record.name
            }
            log_queue.put(log_entry)
        except queue.Full:
            # Remove oldest entry if queue is full
            try:
                log_queue.get_nowait()
                log_queue.put(log_entry)
            except:
                pass

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/logs')
def get_logs():
    logs = list(log_queue.queue)
    return jsonify(logs)

@app.route('/stats')
def get_stats():
    return jsonify(stats_data)

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

def update_stats(attack_type=None, blocked_ip=None, traffic_data=None, resource_data=None):
    """Update statistics data"""
    if attack_type:
        stats_data["attacks_by_type"][attack_type] += 1
    if blocked_ip:
        stats_data["blocked_ips"][blocked_ip] += 1
    if traffic_data:
        timestamp = int(time.time())
        for protocol, count in traffic_data.items():
            stats_data["traffic_patterns"][protocol].append([timestamp, count])
            # Keep only last hour of data
            if len(stats_data["traffic_patterns"][protocol]) > 3600:
                stats_data["traffic_patterns"][protocol].pop(0)
    if resource_data:
        timestamp = int(time.time())
        for resource_type, value in resource_data.items():
            stats_data["resource_usage"][resource_type].append([timestamp, value])
            if len(stats_data["resource_usage"][resource_type]) > 3600:
                stats_data["resource_usage"][resource_type].pop(0)

def run_dashboard(host='localhost', port=5000):
    """Run the web dashboard"""
    app.run(host=host, port=port, debug=False)