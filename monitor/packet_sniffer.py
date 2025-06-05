import os
import django
import sys
from scapy.all import sniff, IP

# Set up Django environment
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "noiseguard.settings")
django.setup()

from monitor.models import Alert
from django.core.mail import send_mail

# Threshold for packet size (you can adjust this)
THRESHOLD = 1500

def send_email_alert(ip, size, status):
    subject = f"[NoiseGuard] Suspicious Activity from {ip}"
    message = f"Packet size: {size} bytes\nStatus: {status}\nCheck the dashboard for more details."
    send_mail(subject, message, 'alicerber50@gmail.com', ['admin@noise.com'])

def process_packet(packet):
    if IP in packet:
        ip_src = packet[IP].src
        packet_len = len(packet)

        status = "Suspicious" if packet_len > THRESHOLD else "Safe"

        # Create and save alert
        alert = Alert.objects.create(
            ip_address=ip_src,
            packet_size=packet_len,
            status=status
        )

        if alert.status == "Suspicious":  # You can change condition to "Blocked" if needed
            send_email_alert(alert.ip_address, alert.packet_size, alert.status)

        print(f"[+] Logged alert: {ip_src} | Size: {packet_len} | Status: {status}")

def start_sniffing():
    print("📡 Starting packet sniffing... Press Ctrl+C to stop.")
    sniff(prn=process_packet, store=False)

if __name__ == "__main__":
    start_sniffing()
