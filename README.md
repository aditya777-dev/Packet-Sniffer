# Simple-Network-Packet-Analyzer


# Prerequisites:
1. install npcap
2. libraries: socket, scapy, datetime


# Code Functionality:

Imports necessary libraries: socket for network communication, scapy for packet manipulation, and datetime for time handling.
Defines functions:
get_application_protocol: Identifies the application protocol based on the destination port number.
packet_callback: Extracts details like source/destination IPs, ports, protocols, packet length, and timestamp for each captured packet.
start_sniffing: Starts sniffing packets on the specified interface ("Wi-Fi") and calls packet_callback for each captured packet.

While the Python code has the potential to capture and print network traffic, capturing all traffic on the Wi-Fi interface has limitations due to Wi-Fi adapter operation in user mode.


# Limitations:

Wi-Fi Adapter Mode: Standard Wi-Fi adapters in user mode primarily focus on communication with the designated access point and filter out most other traffic on the channel. This means the code won't capture all traffic by default.

To capture all traffic on the Wi-Fi interface, you'll need to switch the adapter to monitor mode (also known as rfmon mode). However, this process varies depending on your operating system and may require additional tools:

Scapy Support (Limited): Scapy might offer monitor mode functionality in some cases, but it depends on the specific OS and adapter capabilities.

OS-Specific Tools: Tools like airmon-ng (Linux) or third-party utilities can be used to switch the adapter to monitor mode before running the sniffing code.
Important Considerations:

Monitor Mode Cautions: Enabling monitor mode on public Wi-Fi networks can violate network policies and raise security concerns. It's generally recommended to use monitor mode only on private networks with permission.

Ethical Considerations: Be mindful of ethical implications when capturing network traffic. Ensure you have the necessary permissions.
