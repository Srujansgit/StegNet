from scapy.all import sniff, TCP, ICMP, DNS, IP
import time
import statistics

class TrafficAnalyzer:
    def __init__(self):
        self.packet_timestamps = {}

    def detect_anomalous_packets(self, packet):
        """Detects packets with unusual payloads or headers."""
        if packet.haslayer(TCP):
            payload_size = len(packet[TCP].payload)
            if payload_size > 1000:  # Unusually large payloads
                print(f"[!] Suspicious TCP packet detected: {packet.summary()}")
        
        elif packet.haslayer(ICMP):
            payload_size = len(packet[ICMP].payload)
            if payload_size > 500:  # ICMP packets normally have small payloads
                print(f"[!] Suspicious ICMP packet detected: {packet.summary()}")
        
        elif packet.haslayer(DNS) and packet[DNS].qd:
            domain = packet[DNS].qd.qname.decode()
            if len(domain.split('.')[0]) > 30:  # Very long subdomains could hide data
                print(f"[!] Suspicious DNS request detected: {domain}")

    def detect_timing_anomalies(self, packet):
        """Detects suspicious timing intervals between packets."""
        src = packet[IP].src
        current_time = time.time()
        
        if src not in self.packet_timestamps:
            self.packet_timestamps[src] = []

        self.packet_timestamps[src].append(current_time)
        
        if len(self.packet_timestamps[src]) > 10:  # Analyze last 10 packets
            intervals = [self.packet_timestamps[src][i] - self.packet_timestamps[src][i-1] 
                         for i in range(1, len(self.packet_timestamps[src]))]
            
            if len(intervals) > 1:
                mean_interval = statistics.mean(intervals)
                std_dev = statistics.stdev(intervals)

                if std_dev < 0.01:  # Too regular timing can indicate covert channels
                    print(f"[!] Potential covert timing channel detected from {src}")

            self.packet_timestamps[src] = self.packet_timestamps[src][-10:]

    def analyze_traffic(self, filter_str="ip"):
        """Sniffs network traffic and applies anomaly detection."""
        print("[*] Traffic analysis started...")
        sniff(filter=filter_str, prn=self.packet_callback, store=False)

    def packet_callback(self, packet):
        """Processes each packet to check for anomalies."""
        self.detect_anomalous_packets(packet)
        if packet.haslayer(IP):
            self.detect_timing_anomalies(packet)

