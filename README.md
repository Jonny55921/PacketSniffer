# 🛡️ Packet Sniffer using Python & Scapy

A lightweight packet sniffer built in Python using Scapy, developed on Kali Linux. This tool captures real-time network traffic, filters by protocol, logs each packet to a file, and tracks protocol counts live in the terminal.

## 🔧 Features

- 📡 Real-time packet capture
- 🔎 Protocol-based filtering (e.g., TCP, ICMP, DNS)
- 🧾 Logs each packet with a timestamp to `logs/packets.log`
- 📊 Tracks and displays live packet type counts

## 📁 Project Structure
PacketSniffer/

├── logs/
│ ──> packets.log # Captured packets log (auto-created)

├── sniffer.py # Main packet sniffer script

└── README.md # This file


## 🚀 Getting Started

### 🔨 Prerequisites
- Python 3.x
- Kali Linux or any Linux distro with root access
- Scapy (install with pip if needed)

```bash
sudo apt install python3-pip
pip3 install scapy
```
## 🔧 Usage
# Run with sudo to capture packets
sudo python3 sniffer.py

start_sniffing("icmp")  # Options: "tcp", "udp", "icmp", or "" for all

