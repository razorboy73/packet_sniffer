#!/usr/bin/env python3

import scapy.all as scapy
from scapy.layers import http

def main():
    sniff("eth0")


def sniff(interface):
    # added in filtering  based on specific criteria using BPF (Berkeley Packet Filter) syntax
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet, filter="port 80")


def process_sniffed_packet(packet):
    print(packet)





if __name__ == "__main__":
    main()

