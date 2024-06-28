from scapy.all import sniff
from scapy.layers.http import HTTPRequest, HTTPResponse  # Import HTTP packet structures
from scapy.layers.inet import TCP

# Define a callback function to process the packets
def packet_callback(pkt):
    if pkt.haslayer(HTTPRequest):
        http_layer = pkt[HTTPRequest]
        print(f"\nHTTP Request\nMethod: {http_layer.Method.decode()}\nHost: {http_layer.Host.decode()}\nPath: {http_layer.Path.decode()}")
        print(f"Headers: {http_layer.fields}")

    elif pkt.haslayer(HTTPResponse):
        http_layer = pkt[HTTPResponse]
        print(f"\nHTTP Response\nStatus Code: {http_layer.Status_Code.decode()}\nReason Phrase: {http_layer.Reason_Phrase.decode()}")
        print(f"Headers: {http_layer.fields}")

# Start sniffing with a BPF filter for HTTP packets (port 80)
sniff(filter="tcp port 80", prn=packet_callback, store=0)

