#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers.http import HTTPRequest  # Import HTTP layer
from scapy.layers.inet import TCP, UDP
import argparse


def sniffing(interface, packet_filter):
    scapy.sniff(iface=interface, filter=packet_filter, store=False, prn=process_packet)


def process_packet(packet):
    # Display basic packet summary
    print(packet.summary())

    # Display HTTP request details if present
    if packet.haslayer(HTTPRequest):
        print("[*] HTTP Request detected:")
        print(f"  Host: {packet[HTTPRequest].Host.decode()}")
        print(f"  Path: {packet[HTTPRequest].Path.decode()}")
    # Display DNS request details if present
    elif packet.haslayer(scapy.DNS):
        print("[*] DNS Packet detected:")
        print(f"  Query: {packet[scapy.DNS].qd.qname.decode()}")
    # Display TCP/UDP port numbers if present
    elif packet.haslayer(TCP):
        print("[*] TCP Packet detected:")
        print(f"  Source Port: {packet[TCP].sport}")
        print(f"  Destination Port: {packet[TCP].dport}")
    elif packet.haslayer(UDP):
        print("[*] UDP Packet detected:")
        print(f"  Source Port: {packet[UDP].sport}")
        print(f"  Destination Port: {packet[UDP].dport}")
    else:
        print("[*] Other Packet:")

    # Save the packet to a pcap file
    save_packet(packet)


def save_packet(packet):
    scapy.wrpcap('captured_packets.pcap', packet, append=True)


def main():
    parser = argparse.ArgumentParser(description="A simple packet sniffer")
    parser.add_argument("interface", help="Interface to sniff on")
    parser.add_argument("-f", "--filter", default="", help="Packet filter (e.g., 'tcp', 'udp', 'port 80')")
    args = parser.parse_args()

    print(f"[*] Starting packet sniffer on {args.interface} with filter '{args.filter}'")
    sniffing(args.interface, args.filter)


if __name__ == "__main__":
    main()
