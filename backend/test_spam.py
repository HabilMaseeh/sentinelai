import requests
import time

url = "http://127.0.0.1:8000/api/ingest"

for i in range(100):
    ip = f"192.168.414.100"
    payload = {
        "raw_log": f"Failed password for root from {ip} port 22 ssh2"
    }

    r = requests.post(url, json=payload)
    print(i, r.status_code, r.text)
    time.sleep(0.1)
