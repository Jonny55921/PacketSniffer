from scapy.all import sniff
from collections import defaultdict     # Tracking Packing Type Counter
from datetime import datetime           # Timestamping
import os

# Ensure log folder exists
os.makedirs("logs", exist_ok=True)

# Dictionary to story protocol counts
protocol_counts = defaultdict(int)

# Callback function that runs for each packet
def packet_callback(packet):
    proto = packet.summary().split()[0]
    protocol_counts[proto] += 1
    # Get Protocol name and increase counter

    summary = f"[{datetime.now()}] {packet.summary()}"
    print(f"{summary} | Counts: {dict(protocol_counts)}")
    # Print packet with timestamp

    with open("logs/packets.log", "a") as log_file:
        log_file.write(summary + "\n")
    # Writes packet to log file

def start_sniffing(proto_filter=""):
    print(f"🔍 Starting packet capture (filter: {proto_filter or 'none'})")
    sniff(filter=proto_filter, prn=packet_callback, store=False)
    # Starts sniffing packets with user defined options

# Example: filter options - "tcp", "icmp", "udp port 53", or leave blank
start_sniffing("")

"""
"tcp" – captures TCP packets only

"icmp" – captures ping/echo packets

"udp port 53" – captures DNS requests

"" – captures everything (no filter)
"""