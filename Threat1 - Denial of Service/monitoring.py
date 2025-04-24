import os
import time
import logging
from datetime import datetime

logging.basicConfig(filename="device_monitor.log", level=logging.INFO, format="%(asctime)s - %(message)s")


target_ip = "127.0.0.1"


latency_threshold = 100



def ping_device(ip):
    response = os.popen(f"ping -n 1 {ip}")
    result = response.read()

    if "TTL=" in result:

        start = result.find("time=")
        end = result.find("ms", start)
        if start != -1 and end != -1:
            time_str = result[start + 5:end]
            latency = int(time_str)
            return True, latency
        return False, None
    return False, None



def monitor_device():
    while True:
        is_up, latency = ping_device(target_ip)

        if not is_up:
            logging.warning(f"{target_ip} is unresponsive or delayed. Potential attack detected!")
            print(f"[{datetime.now()}] Warning: {target_ip} is unresponsive or delayed.")
        else:
            if latency > latency_threshold:
                logging.warning(f"{target_ip} response time is high ({latency}ms). Potential DoS attack detected!")
                print(f"[{datetime.now()}] Warning: {target_ip} response time is high ({latency}ms).")
            else:
                print(f"[{datetime.now()}] {target_ip} is responsive. Latency: {latency}ms.")


        time.sleep(5)



if __name__ == "__main__":
    print(f"Monitoring {target_ip} for potential DoS attack...")
    monitor_device()
