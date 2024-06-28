#!/usr/bin/env python3

import scapy.all as scapy
from scapy.layers import http

def main():
    sniff("eth0")

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        # password is in the raw layer
        if packet.haslayer(scapy.Raw):
            print("********************************************")
            # print(packet.show())
            # print out the name of the layer and field we are interested in
            print(packet[scapy.Raw].load)
            print("********************************************")
    # if packet.haslayer(http.HTTPResponse):
    #     http_layer = packet[http.HTTPResponse]
    #     headers = {header: value for header, value in http_layer.fields.items() if header != 'Payload'}
    #     print("HTTP Response Headers:")
    #     for header, value in headers.items():
    #         print(f"{header}: {value}")
    #     print("\n" + "-" * 50 + "\n")
def sniff(interface):
    # added in filtering  based on specific criteria using BPF (Berkeley Packet Filter) syntax
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)








if __name__ == "__main__":
    main()

