from scapy.all import sniff, IP, TCP
from collections import defaultdict
import threading
import queue

#Need to cater for WLAN if doesn't work on eth0
class PacketCapture:
    def __init__(self):
        self.packet_queue = queue.Queue()
        self.stop_sniffing = threading.Event()

    #Check if IP and TCP in packet
    def packetCallback(self, packet):
        if IP in packet and TCP in packet:
            self.packet_queue.put(packet)

    def start_sniffing(self, interface="wlp4s0"): #Maybe change interface to eth0 (test)
        def captureThread():
            sniff(iface=interface, prn=self.packetCallback, store=0, stop_filter=lambda x: self.stop_sniffing.is_set())
        self.capture_thread = threading.Thread(target=captureThread)
        self.capture_thread.start()

    def stop(self):
        self.stop_sniffing.set()
        self.capture_thread.join()

class TrafficAnalysis:
    def __init__(self):
        self.connections = defaultdict(list)
        self.flowStats = defaultdict(lambda: {'packetCount': 0, 'byteCount': 0, 'startTime': None, 'endTime': None})

    def analyze_packet(self, packet):
        if IP in packet and TCP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flow_key = (src_ip, dst_ip, src_port, dst_port)

            #update flow
            stats = self.flowStats[flow_key]
            stats['packetCount'] += 1
            stats['byteCount'] += len(packet)
            currentTime = packet.time

            if not stats['startTime']:
                stats['startTime'] = currentTime
            stats['endTime'] = currentTime

            return self.getFeatures(packet, stats)

    def getFeatures(self, packet, stats):
        return {
            'packetSize': len(packet),
            'flowDuration': stats['endTime'] - stats['startTime'],
            'packetRate': stats['packetCount'] / (stats['endTime'] - stats['startTime']),
            'byteRate': stats['byteCount'] / (stats['endTime'] - stats['startTime']),
            'tcp_flags': packet[TCP].flags,
            'windowSize': packet[TCP].window
        }
