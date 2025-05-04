import psutil
import scapy.all as scapy
import threading
import time
import json
import logging
import numpy as np
import psycopg2
import tensorflow as tf
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from flask import Flask, jsonify, render_template, request
from flask_socketio import SocketIO, emit
from kafka import KafkaProducer
import random

# Setup logging
logging.basicConfig(level=logging.INFO)

# Cloud and Kafka Integration (Event Streaming)
def send_to_kafka(topic, message):
    """Send data to Kafka for real-time processing."""
    producer = KafkaProducer(bootstrap_servers='localhost:9092', value_serializer=lambda m: json.dumps(m).encode('utf-8'))
    producer.send(topic, message)
    producer.flush()

# Machine Learning Traffic Classifier
class TrafficClassifier:
    def __init__(self):
        self.model = RandomForestClassifier()  # Placeholder for model, can be replaced with deep learning models
        self.scaler = StandardScaler()

    def train_model(self, data, labels):
        """ Train the model with network traffic data."""
        data_scaled = self.scaler.fit_transform(data)
        self.model.fit(data_scaled, labels)

    def predict(self, features):
        """ Predict if the traffic is benign or malicious."""
        features_scaled = self.scaler.transform([features])
        return self.model.predict(features_scaled)[0]

# Network Sniffer with Advanced Analytics
class NetworkSniffer:
    def __init__(self):
        self.device_list = []
        self.packet_data = []
        self.interfaces = self.get_network_interfaces()
        self.classifier = TrafficClassifier()

    def get_network_interfaces(self):
        """ Get all network interfaces on the machine."""
        interfaces = []
        for interface, addrs in psutil.net_if_addrs().items():
            interfaces.append(interface)
        return interfaces

    def discover_devices(self):
        """ Discover devices connected to the network."""
        logging.info("Scanning for connected devices...")
        arp_request = scapy.ARP(pdst="192.168.1.0/24")
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        
        for element in answered_list:
            device = {"IP": element[1].psrc, "MAC": element[1].hwsrc}
            self.device_list.append(device)

    def packet_callback(self, packet):
        """ Capture packets, perform analysis, and send results to Kafka."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        packet_info = {
            'timestamp': timestamp,
            'src': packet[scapy.IP].src if scapy.IP in packet else 'N/A',
            'dst': packet[scapy.IP].dst if scapy.IP in packet else 'N/A',
            'protocol': packet.proto if hasattr(packet, 'proto') else 'Unknown'
        }

        # Send packet info to Kafka for real-time processing
        send_to_kafka("network-traffic", packet_info)

        # Analyze packet behavior
        features = self.extract_packet_features(packet)
        prediction = self.classifier.predict(features)
        if prediction == 1:  # Malicious traffic detected
            self.send_alert(f"Malicious traffic detected: {packet.summary()}")

    def extract_packet_features(self, packet):
        """ Extract features from a packet for model prediction."""
        return [len(packet), packet.proto]  # Simple features, can be extended

    def send_alert(self, alert_message):
        """ Send alert about malicious activity."""
        logging.info(f"ALERT: {alert_message}")
        emit('alert', {'data': alert_message})

    def start_sniffing(self, interface='eth0'):
        """ Start sniffing on a specific network interface."""
        logging.info(f"Sniffing started on {interface}...")
        scapy.sniff(iface=interface, prn=self.packet_callback, store=False)

    def start(self):
        """ Start the sniffer and web server."""
        self.discover_devices()
        self.start_sniffing(interface="eth0")  # Choose appropriate interface

# Web Frontend with Flask + WebSocket for Real-Time Alerts
app = Flask(__name__)
socketio = SocketIO(app)

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('connect')
def handle_connect():
    emit('response', {'data': 'Connected to Network Sniffer'})

def start_web_server():
    """ Start the Flask web server with WebSocket support."""
    socketio.run(app, host="0.0.0.0", port=5000)

# Run backend and web server in separate threads
if __name__ == '__main__':
    sniffer = NetworkSniffer()
    threading.Thread(target=sniffer.start).start()
    threading.Thread(target=start_web_server).start()
