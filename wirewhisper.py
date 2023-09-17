import scapy.all as scapy
from scapy.layers.http import HTTPRequest
from scapy.utils import PcapWriter
import time

class WireWhisperSniffer:
    def __init__(self):
        self.pcap_writer = PcapWriter("captured_packets.pcap", append=True)
        self.start_time = time.time()
        self.packet_count = 0
        self.rate_limit = 10  # packets per second
        self.whitelisted_ips = set()
        self.blacklisted_ips = set()

    def packet_callback(self, packet):
        current_time = time.time()
        if current_time - self.start_time < 1:
            if self.packet_count > self.rate_limit:
                return
        else:
            self.start_time = current_time
            self.packet_count = 0

        self.packet_count += 1

        # Whitelisting and Blacklisting
        if packet.haslayer(scapy.IP):
            if packet[scapy.IP].src in self.blacklisted_ips:
                return
            if self.whitelisted_ips and packet[scapy.IP].src not in self.whitelisted_ips:
                return

        # Save to PCAP
        self.pcap_writer.write(packet)

        # Protocol Decoders
        if packet.haslayer(HTTPRequest):
            host = packet[HTTPRequest].Host.decode()
            path = packet[HTTPRequest].Path.decode()
            method = packet[HTTPRequest].Method.decode()
            print(f"[HTTP] {method} {host}{path}")

        elif packet.haslayer(scapy.DNSQR):
            dns_query = packet[scapy.DNSQR].qname.decode()
            print(f"[DNS Query] {dns_query}")

        # MAC Address Resolution (Demo - Open for enhancement)
        if packet.haslayer(scapy.Ether):
            mac = packet[scapy.Ether].src
            print(f"[MAC] {mac} -> DummyVendor")

        # Geolocation (Demo - Open for enhancement 2)
        if packet.haslayer(scapy.IP):
            ip = packet[scapy.IP].src
            print(f"[GEO] {ip} -> DummyLocation")

    def start_sniffing(self, filter_str=""):
        print("Starting sniffer...")
        scapy.sniff(filter=filter_str, prn=self.packet_callback, store=0)

    def whitelist_ip(self, ip):
        self.whitelisted_ips.add(ip)

    def blacklist_ip(self, ip):
        self.blacklisted_ips.add(ip)

if __name__ == "__main__":
    sniffer = WireWhisperSniffer()
    sniffer.whitelist_ip("192.168.1.1")  # Example1
    sniffer.blacklist_ip("10.0.0.1")     # Example2
    sniffer.start_sniffing()
