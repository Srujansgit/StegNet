from scapy.all import IP, ICMP, Raw, send, sniff
from stegnet.core.steg_base import StegNetBase
from stegnet.core.packet_utils import PacketUtils

class ICMPHandler(StegNetBase):
    def __init__(self, encryption_key):
        super().__init__(encryption_key)

    def send_covert_message(self, target_ip, message):
        """Hides an encrypted message inside an ICMP packet."""
        encrypted_msg = self.encrypt(message)
        packet = IP(dst=target_ip) / ICMP(type=8) / Raw(load=PacketUtils.encode_payload(encrypted_msg))
        send(packet, verbose=False)
        print(f"[*] Sent covert ICMP message to {target_ip}")

    def receive_covert_message(self):
        """Sniffs ICMP packets and extracts hidden messages."""
        def packet_callback(packet):
            if packet.haslayer(Raw):
                extracted_msg = PacketUtils.decode_payload(packet[Raw].load)
                hidden_msg = self.decrypt(extracted_msg)
                if hidden_msg:
                    print(f"[+] Extracted ICMP message: {hidden_msg}")

        print("[*] Listening for covert ICMP messages...")
        sniff(filter="icmp", prn=packet_callback, store=False)
