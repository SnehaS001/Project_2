from collections import defaultdict
import time
from config import *

class AnomalyDetector:
    def __init__(self):
        self.packet_count = 0
        self.port_tracker = defaultdict(set)
        self.start_time = time.time()

    def update(self, src_ip, dst_port):
        self.packet_count += 1
        self.port_tracker[src_ip].add(dst_port)

    def check(self):
        elapsed = time.time() - self.start_time
        alerts = []

        if elapsed > MONITOR_INTERVAL:
            for ip, ports in self.port_tracker.items():
                if len(ports) > THRESHOLD_UNIQUE_PORTS:
                    alerts.append(f"Possible Port Scan from {ip}: {len(ports)} unique ports.")
            if self.packet_count > THRESHOLD_PACKET_COUNT:
                alerts.append(f"High traffic volume detected: {self.packet_count} packets in {MONITOR_INTERVAL}s.")

            self.reset()
        return alerts

    def reset(self):
        self.packet_count = 0
        self.port_tracker.clear()
        self.start_time = time.time()