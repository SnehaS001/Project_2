from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
from db_manager import init_db, log_packet
from alert_manager import send_email_alert, log_alert_to_file
from anomaly_detector import AnomalyDetector
from config import EMAIL_ALERTS

conn = init_db()
detector = AnomalyDetector()

def process(pkt):
    if IP in pkt:
        ip_layer = pkt[IP]
        proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "Other"
        src_port = pkt[TCP].sport if TCP in pkt else pkt[UDP].sport if UDP in pkt else ""
        dst_port = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport if UDP in pkt else ""

        pkt_data = {
            "timestamp": str(datetime.now()),
            "src_ip": ip_layer.src,
            "dst_ip": ip_layer.dst,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": proto,
            "length": len(pkt)
        }

        log_packet(conn, pkt_data)
        detector.update(ip_layer.src, dst_port)

        alerts = detector.check()
        for alert in alerts:
            print("ALERT:", alert)
            log_alert_to_file(alert)
            if EMAIL_ALERTS:
                send_email_alert("Network Alert", alert)

print("[*] Starting packet sniffing...")
sniff(prn=process, store=0)