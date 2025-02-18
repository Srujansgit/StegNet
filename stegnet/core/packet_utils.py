from scapy.all import IP, TCP, ICMP, DNS, DNSQR, Raw
import struct
import base64

class PacketUtils:
    @staticmethod
    def encode_payload(data: str) -> bytes:
        """Encodes data using Base64 before embedding in packets."""
        return base64.b64encode(data.encode())

    @staticmethod
    def decode_payload(data: bytes) -> str:
        """Decodes Base64 encoded data extracted from packets."""
        try:
            return base64.b64decode(data).decode()
        except:
            return None

    @staticmethod
    def hide_in_tcp_seq(data: str) -> int:
        """Encodes data into the TCP sequence number."""
        return struct.unpack(">I", data[:4].ljust(4, b'\x00'))[0]  # Pad to 4 bytes

    @staticmethod
    def extract_from_tcp_seq(seq_num: int) -> str:
        """Decodes hidden data from the TCP sequence number."""
        return struct.pack(">I", seq_num).decode(errors="ignore")

    @staticmethod
    def hide_in_icmp(data: str):
        """Embeds data inside ICMP payload."""
        return IP(dst="192.168.1.1") / ICMP() / Raw(load=PacketUtils.encode_payload(data))

    @staticmethod
    def extract_from_icmp(packet):
        """Extracts hidden data from an ICMP payload."""
        if packet.haslayer(Raw):
            return PacketUtils.decode_payload(packet[Raw].load)
        return None

    @staticmethod
    def hide_in_dns(domain: str, data: str):
        """Encodes data into a subdomain of the given domain."""
        encoded_data = PacketUtils.encode_payload(data).decode()
        return IP(dst="8.8.8.8") / DNS(rd=1, qd=DNSQR(qname=f"{encoded_data}.{domain}"))

    @staticmethod
    def extract_from_dns(packet):
        """Extracts encoded data from a DNS query."""
        if packet.haslayer(DNS) and packet[DNS].qd:
            qname = packet[DNS].qd.qname.decode()
            encoded_data = qname.split(".")[0]
            return PacketUtils.decode_payload(encoded_data.encode())
        return None