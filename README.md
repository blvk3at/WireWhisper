# WireWhisper: The Packet Sniffer
WireWhisper is an advanced packet sniffer, designed to capture, analyze, and decode network traffic with precision and efficiency. Built with Python and the scapy library, WireWhisper offers a comprehensive insight into the whispers of your network.

# Features
## 1. Packet Reassembly
Handles fragmented packets, ensuring complete data capture.
## 2. Content Extraction
Extracts and displays HTTP headers for a deeper look into web traffic.
## 3. Protocol Decoders
Decodes application layer protocols like DNS, revealing the domains queried.
## 4. Save Captured Data
Saves the captured packets to a file in PCAP format for further analysis.
## 5. Filtering Options
Allows capturing only packets from specific IPs or ports, providing targeted insights.
## 6. Statistics
Offers statistics on captured traffic, helping you understand network patterns.
## 7. MAC Address Resolution
Resolves MAC addresses to vendor names, identifying device manufacturers.
## 8. Geolocation
Resolves IP addresses to physical locations, giving a geographical context to the traffic (a dummy function was implemented for this project).
## 9. Rate Limiting
Limits the rate at which packets are captured and analyzed, ensuring system stability.
## 10. Whitelisting and Blacklisting
Allows or blocks specific IP addresses, tailoring the capture to your needs.

# Installation
Clone the Repository:
git clone https://github.com/blvk3at/WireWhisper.git
# Navigate to the Project Directory:
cd WireWhisper
# Install the Required Python Packages:
pip install scapy
# Usage
Run WireWhisper with Administrative Privileges:
sudo python3 sniffer.py

By default, WireWhisper captures all TCP traffic. You can modify the code for specific filters or to whitelist/blacklist specific IP addresses.

# Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you'd like to change.

# License
MIT
