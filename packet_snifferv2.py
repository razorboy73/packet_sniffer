import scapy.all as scapy
from scapy.layers import http #for filtering packets

def main():
    sniff("eth0")
    
    
def sniff(interface):
    scapy.sniff(iface=interface,store=False, prn=process_sniffed_packet, filter="port 80")
    
    
def process_sniffed_packet(packet):
    # if packet.haslayer(http.HTTPRequest):
    print(packet)
    




if __name__ == "__main__":
    main()

