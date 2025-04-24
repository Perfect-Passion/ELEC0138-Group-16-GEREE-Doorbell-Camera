from scapy.all import *
import time
import random

# Doorbell ip **change everytime you reestablish connection to doorbell**
target_ip = "192.168.137.63"  # Replace with actual device IP

# Common destination ports to mimic (web, IoT)
fake_ports = [80, 443, 554, 8000, 8888]

def send_noise(duration=40):
    print(f"Sending fake decoy packets to {target_ip} for {duration} seconds...")
    start = time.time()

    while time.time() - start < duration:
        # Generate a random source port and destination port
        src_port = random.randint(1024, 65535)
        dst_port = random.choice(fake_ports)

        # Create randomised TCP packets
        fake_payload = f"noise_{random.randint(1000, 9999)}"
        packet = IP(dst=target_ip)/TCP(sport=src_port, dport=dst_port)/Raw(load=fake_payload)

        # Send the packets
        send(packet, verbose=False)

        # Packet stream rate **CHANGE depending what rate is needed
        time.sleep(0.02)

    print("\nFinished sending fake noise.")

# Run it
if __name__ == "__main__":
    try:
        send_noise(duration=40)  # Runs for 40 seconds
    except KeyboardInterrupt:
        print("\n Stopped Decoy Packets")