from scapy.all import IP, TCP, Raw, send, sniff
from stegnet.core.steg_base import StegNetBase
from stegnet.core.packet_utils import PacketUtils

class TCPHandler(StegNetBase):
    def __init__(self, encryption_key):
        super().__init__(encryption_key)

    def send_covert_message(self, target_ip, message):
        """Hides an encrypted message inside the TCP payload and sends it."""
        encrypted_msg = self.encrypt(message)
        packet = IP(dst=target_ip) / TCP(dport=443, flags="PA") / Raw(load=PacketUtils.encode_payload(encrypted_msg))
        send(packet, verbose=False)
        print(f"[*] Sent covert TCP message to {target_ip}")

    def receive_covert_message(self):
        """Sniffs TCP packets and extracts hidden messages."""
        def packet_callback(packet):
            if packet.haslayer(Raw):
                extracted_msg = PacketUtils.decode_payload(packet[Raw].load)
                hidden_msg = self.decrypt(extracted_msg)
                if hidden_msg:
                    print(f"[+] Extracted TCP message: {hidden_msg}")

        print("[*] Listening for covert TCP messages. Press Ctrl+C to stop.")
        try:
            sniff(filter="tcp and port 443", prn=packet_callback, store=False)
        except KeyboardInterrupt:
            print("\n[!] Sniffing stopped by user.")
