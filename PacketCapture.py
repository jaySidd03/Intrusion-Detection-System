from scapy.all import sniff, IP, TCP
from collections import defaultdict
import threading
import queue
class PacketCapture:
    def __init__(self):
        self.packet_queue = queue.Queue()
        self.stop_sniffing = threading.Event()

    def packetCallback(self, packet):
        if IP in packet and TCP in packet:
            self.packet_queue.put(packet)

    def start_sniffing(self, interface="wlp4s0"):
        def captureThread():
            sniff(iface=interface, prn=self.packetCallback, store=0, stop_filter=lambda x: self.stop_sniffing.is_set())
        self.capture_thread = threading.Thread(target=captureThread)
        self.capture_thread.start()

    def stop(self):
        self.stop_sniffing.set()
        self.capture_thread.join()
