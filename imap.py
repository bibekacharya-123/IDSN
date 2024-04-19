from scapy.all import IP, ICMP, send
import time

def send_icmp_packets(source_ip, destination_ip, count):
    # Send multiple ICMP packets
    for _ in range(count):
        icmp_packet = IP(src=source_ip, dst=destination_ip) / ICMP(type=0, code=0)
        send(icmp_packet)
        time.sleep(0.1)  # Sleep for a short interval between each packet

# Replace "source_ip" and "destination_ip" with the actual IP addresses
source_ip = "192.168.1.97"
destination_ip = "192.168.1.99"
packet_count = 100  # Number of packets to send

# Send ICMP packets
send_icmp_packets(source_ip, destination_ip, packet_count)
