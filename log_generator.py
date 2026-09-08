import random
import time

# List of IPs to simulate varied traffic
ips = ["192.168.1.15", "172.16.254.1", "10.0.0.55", "198.51.100.22", "45.33.22.11"]
statuses = ["[200 OK]", "[401 Unauthorized]", "[403 Forbidden]"]

def generate_log():
    # Randomly select an IP and a Status to make the graph fluctuate
    ip = random.choice(ips)
    status = random.choice(statuses)
    timestamp = time.strftime('%Y-%m-%dT%H:%M:%SZ')
    return f"{timestamp} INFO [VIGILX] - Traffic from {ip} {status}"

# The loop that "feeds" your dashboard
with open("app_logs.txt", "a") as log_file:
    print("Starting log simulation... Press Ctrl+C to stop.")
    while True:
        log_entry = generate_log()
        log_file.write(log_entry + "\n")
        log_file.flush() # Ensures data is written immediately
        time.sleep(2)    # Adds a 2-second delay between logs for a "live" feel