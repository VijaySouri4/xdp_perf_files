# from scapy.all import IP, TCP, send, RandShort

# # The destination IP address
# dst_ip = "192.168.1.100"
# # The destination port
# dst_port = 9090

# # Create an IP packet with the destination IP
# ip_packet = IP(dst=dst_ip)

# # Create a TCP segment with the destination port, and a random source port
# tcp_segment = TCP(dport=dst_port, sport=RandShort())

# # Combine the IP packet and TCP segment
# packet = ip_packet/tcp_segment

# # Optionally, you can add payload data to the TCP segment
# packet.load = "Hello, port 9090!"

# # Send the packet. Adjust count for the number of packets you want to send
# send(packet, count=100)


from scapy.all import *
import time

def send_traffic(src_ip, dst_ip, src_port, dst_port, dst_mac, interface, _payload_ = 'hello!'):
    packet = Ether(dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port) / Raw(load=_payload_)
    # packet.load = _payload_
    pkt_count = 0
    start_time = time.time()

    while True:
        sendp(packet, iface=interface, verbose=False)
        pkt_count += 1

        if pkt_count % 1000 == 0:
            duration = time.time() - start_time
            throughput = pkt_count / duration
            print(f"Sent {pkt_count} packets in {duration:.2f} seconds. Throughput: {throughput:.2f} packets/sec")
            break

if __name__ == '__main__':
    src_ip = '10.10.1.2'     # Source IP address
    dst_ip = '10.10.1.1'     # Destination IP address
    src_port = 12345         # Source port
    dst_port = 80            # Destination port
    dst_mac = 'a0:36:9f:2a:5c:38'  # MAC address of the target machine
    interface = 'enp3s0f0'   # Interface name on the source machine
    # _payload_ = 'Helloooooo!'

    send_traffic(src_ip, dst_ip, src_port, dst_port, dst_mac, interface)