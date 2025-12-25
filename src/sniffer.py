import os
from datetime import datetime

import pandas as pd
import scapy.all as scapy

# Robust import for Windows interfaces
try:
    from scapy.arch.windows import get_working_ifaces
except ImportError:
    try:
        from scapy.arch import get_working_ifaces
    except ImportError:
        # Fallback for older Scapy versions
        from scapy.all import conf
        def get_working_ifaces():
            return conf.ifaces.values()

# Path setup
DATA_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'captured_packets.csv')
os.makedirs(os.path.dirname(DATA_PATH), exist_ok=True)

packet_buffer = []
BUFFER_SIZE = 10

def extract_features(packet):
    if not packet.haslayer(scapy.IP):
        return None

    ip_layer = packet[scapy.IP]
    proto = ip_layer.proto
    protocol = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(proto, str(proto))

    src_port = dst_port = None
    if protocol == 'TCP' and packet.haslayer(scapy.TCP):
        src_port = packet[scapy.TCP].sport
        dst_port = packet[scapy.TCP].dport
    elif protocol == 'UDP' and packet.haslayer(scapy.UDP):
        src_port = packet[scapy.UDP].sport
        dst_port = packet[scapy.UDP].dport

    return {
        'timestamp': datetime.now().isoformat(),
        'src_ip': ip_layer.src,
        'dst_ip': ip_layer.dst,
        'src_port': src_port,
        'dst_port': dst_port,
        'protocol': protocol,
        'packet_length': len(packet)
    }

def packet_callback(packet):
    global packet_buffer
    feat = extract_features(packet)

    if feat:
        packet_buffer.append(feat)
        print(f"[{feat['protocol']}] {feat['src_ip']} -> {feat['dst_ip']} | {feat['packet_length']} bytes")

        if len(packet_buffer) >= BUFFER_SIZE:
            df = pd.DataFrame(packet_buffer)
            file_exists = os.path.isfile(DATA_PATH)
            df.to_csv(DATA_PATH, index=False, mode='a', header=not file_exists)
            packet_buffer = []

def get_best_interface():
    print("Searching for active network interfaces...")
    try:
        interfaces = get_working_ifaces()
        # Filter for interfaces that have a valid IP and aren't loopback
        valid_ifaces = [i for i in interfaces if hasattr(i, 'ip') and i.ip and i.ip != '127.0.0.1']

        if not valid_ifaces:
            return None

        # Prefer Wi-Fi or Ethernet
        for i in valid_ifaces:
            desc = getattr(i, 'description', '').lower()
            if "wi-fi" in desc or "ethernet" in desc:
                return i
        return list(valid_ifaces)[0]
    except Exception as e:
        print(f"Error detection interfaces: {e}")
        return None

if __name__ == '__main__':
    print('--- AI-Powered IDS Sniffer (Manual Selector) ---')

    # 1. Get all interfaces
    interfaces = scapy.conf.ifaces.values()
    ifaces_list = list(interfaces)

    print("\nAvailable Interfaces:")
    for i, iface in enumerate(ifaces_list):
        print(f"{i}: {iface.description} [IP: {getattr(iface, 'ip', 'None')}]")

    # 2. Let you choose
    try:
        choice = int(input("\nEnter the number of your Wi-Fi or Ethernet interface: "))
        target_iface = ifaces_list[choice]
    except (ValueError, IndexError):
        print("Invalid choice. Attempting to auto-select...")
        target_iface = next((i for i in ifaces_list if "wi-fi" in i.description.lower()), None)

    if target_iface:
        print(f"\nTargeting: {target_iface.description}")
        print(f"IP: {target_iface.ip}")
        print('Sniffing started... Press Ctrl+C to stop.')

        try:
            # We use target_iface.name because Windows needs the GUID string
            scapy.sniff(iface=target_iface.name, prn=packet_callback, store=0)
        except PermissionError:
            print("\nERROR: Please run as ADMINISTRATOR.")
    else:
        print("No valid interface selected.")
