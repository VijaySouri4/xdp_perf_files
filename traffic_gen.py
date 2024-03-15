from scapy.all import IP, TCP, send, RandShort

# The destination IP address
dst_ip = "192.168.1.100"
# The destination port
dst_port = 9090

# Create an IP packet with the destination IP
ip_packet = IP(dst=dst_ip)

# Create a TCP segment with the destination port, and a random source port
tcp_segment = TCP(dport=dst_port, sport=RandShort())

# Combine the IP packet and TCP segment
packet = ip_packet/tcp_segment

# Optionally, you can add payload data to the TCP segment
packet.load = "Hello, port 9090!"

# Send the packet. Adjust count for the number of packets you want to send
send(packet, count=100)
