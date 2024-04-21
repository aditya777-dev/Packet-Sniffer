# Import necessary libraries
import socket  # For resolving port numbers to service names
from scapy.all import sniff  # For packet sniffing
from scapy.layers.inet import TCP, UDP, IP  # For working with TCP, UDP, and IP packets
from datetime import datetime  # For converting packet timestamps to human-readable format

# Function to get the application protocol based on the packet's transport layer
def get_application_protocol(packet):
    # Check if the packet is TCP
    if packet.haslayer(TCP):
        port = packet[TCP].dport  # Get the destination port number
    # Check if the packet is UDP
    elif packet.haslayer(UDP):
        port = packet[UDP].dport  # Get the destination port number
    else:
        return None  # Return None if the transport layer protocol is neither TCP nor UDP

    try:
        # Try to resolve the port number to the corresponding service name
        return socket.getservbyport(port)
    except OSError:
        return None  # Return None if the service name cannot be resolved

# Callback function to process each sniffed packet
def packet_callback(packet):
    # Extract source and destination IP addresses from the packet
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
    else:
        src_ip = "N/A"
        dst_ip = "N/A"

    transport_proto = None  # Initialize transport protocol to None
    src_port = "N/A"  # Initialize source port to "N/A"
    dst_port = "N/A"  # Initialize destination port to "N/A"

    # Check if the packet is TCP
    if packet.haslayer(TCP):
        transport_proto = 'TCP'  # Set transport protocol to TCP
        src_port = packet[TCP].sport  # Get the source port number
        dst_port = packet[TCP].dport  # Get the destination port number
    # Check if the packet is UDP
    elif packet.haslayer(UDP):
        transport_proto = 'UDP'  # Set transport protocol to UDP
        src_port = packet[UDP].sport  # Get the source port number
        dst_port = packet[UDP].dport  # Get the destination port number

    # Get the application protocol based on the packet's transport layer
    application_proto = get_application_protocol(packet)

    # Get the length of the packet
    packet_length = len(packet)

    # Convert the packet timestamp to a human-readable format
    timestamp = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S')

    # Print packet details
    print("Packet Details:")
    print(f"  Source IP: {src_ip}")
    print(f"  Destination IP: {dst_ip}")
    print(f"  Source Port: {src_port}")
    print(f"  Destination Port: {dst_port}")
    print(f"  Transport Protocol: {transport_proto}")
    print(f"  Application Protocol: {application_proto}")
    print(f"  Packet Length: {packet_length}")
    print(f"  Timestamp: {timestamp}")

# Function to start packet sniffing on a specified interface
def start_sniffing(interface):
    # Start sniffing packets on the specified interface
    sniff(iface=interface, prn=packet_callback, store=False)

# Entry point of the program
if __name__ == "__main__":
    interface = "Wi-Fi"  # Change this to the name of your network interface
    start_sniffing(interface)  # Start sniffing packets on the specified interface
