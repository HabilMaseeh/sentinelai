import requests
import random
import time

url = "http://127.0.0.1:8000/api/ingest"

ATTACKS = [
    lambda ip: f"Failed password for root from Habil Maseeh {ip} port 22 ssh2",
    lambda ip: f"Invalid user admin from {ip} port 22",
    lambda ip: f"Accepted password for user from {ip}",
    lambda ip: f"sudo: pam_unix(sudo:auth): authentication failure from Habil Maseeh {ip}",
]

def simulate():
    while True:
        ip = f"10.0.0.{random.randint(1,50)}"
        log = random.choice(ATTACKS)(ip)

        r = requests.post(url, json={"raw_log": log})
        print(r.status_code, log)

        time.sleep(random.uniform(0.2, 1.2))

simulate()
