from scapy.all import IP, UDP, DNS, DNSQR, send, sniff
from stegnet.core.steg_base import StegNetBase
from stegnet.core.packet_utils import PacketUtils

class DNSHandler(StegNetBase):
    def __init__(self, encryption_key):
        super().__init__(encryption_key)

    def send_covert_message(self, target_domain, message):
        """Encodes a hidden message inside a DNS query subdomain."""
        encrypted_msg = self.encrypt(message)
        encoded_msg = PacketUtils.encode_payload(encrypted_msg).decode()
        query = f"{encoded_msg}.{target_domain}"
        packet = IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=query))
        send(packet, verbose=False)
        print(f"[*] Sent covert DNS message to {target_domain}")

    def receive_covert_message(self):
        """Sniffs DNS queries and extracts hidden messages."""
        def packet_callback(packet):
            if packet.haslayer(DNS) and packet[DNS].qd:
                qname = packet[DNS].qd.qname.decode()
                encoded_msg = qname.split(".")[0]
                extracted_msg = PacketUtils.decode_payload(encoded_msg.encode())
                hidden_msg = self.decrypt(extracted_msg)
                if hidden_msg:
                    print(f"[+] Extracted DNS message: {hidden_msg}")

        print("[*] Listening for covert DNS messages. Press Ctrl+C to stop.")
        try:
            sniff(filter="udp port 53", prn=packet_callback, store=False)
        except KeyboardInterrupt:
            print("\n[!] Sniffing stopped by user.")