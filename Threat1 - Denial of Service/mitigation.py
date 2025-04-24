from scapy.all import sniff, IP, TCP, UDP
import time
import subprocess
import platform

# Thresholds and time window
PACKET_THRESHOLD = 10  # Threshold for both SYN and UDP packets
TIME_WINDOW = 60       # Time window in seconds

# IP statistics dictionary
ip_stats = {}

def block_ip(ip):
    print(f"[!] Blocking IP: {ip}")
    cmd = [
        "netsh", "advfirewall", "firewall", "add",
        "rule", f"name=Block_{ip}", "dir=in",
        "action=block", f"remoteip={ip}", "protocol=ANY"
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    print(f"[+] Firewall rule added. Output:\n{result.stdout}")
    if result.stderr:
        print(f"[-] Error:\n{result.stderr}")

def packet_callback(pkt):
    if pkt.haslayer(IP):
        ip_src = pkt[IP].src
        now = time.time()

        is_suspicious = False

        # Check for TCP SYN
        if pkt.haslayer(TCP) and pkt[TCP].flags == "S":
            is_suspicious = True

        # Check for UDP
        elif pkt.haslayer(UDP):
            is_suspicious = True

        if is_suspicious:
            if ip_src not in ip_stats:
                ip_stats[ip_src] = {"count": 1, "first_seen": now}
            else:
                ip_stats[ip_src]["count"] += 1

            # Check if IP exceeds threshold within time window
            if now - ip_stats[ip_src]["first_seen"] <= TIME_WINDOW:
                if ip_stats[ip_src]["count"] > PACKET_THRESHOLD:
                    print(f"[!] DoS Attack Detected from {ip_src}")
                    block_ip(ip_src)
                    del ip_stats[ip_src]  # Clear entry after blocking
            else:
                # Reset counter after time window
                ip_stats[ip_src] = {"count": 1, "first_seen": now}

def start_sniffing():
    print("[*] Starting packet sniffing... Press Ctrl+C to stop.")
    sniff(filter="ip", prn=packet_callback, store=0)

if __name__ == "__main__":
    if platform.system() != "Windows":
        print("[-] This script is designed for Windows only.")
    else:
        start_sniffing()

