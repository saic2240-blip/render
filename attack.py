import requests
import time
import threading

# ─────────────────────────────────────────────
# ATTACK SIMULATION SCRIPT
# Sends rapid POST requests to /log endpoint
# to simulate a DDoS attack for demo purposes.
# ─────────────────────────────────────────────

URL = "http://localhost:5000/log"
TOTAL_REQUESTS = 200
THREADS = 10          # concurrent threads
DELAY = 0.01          # seconds between requests per thread

sent = 0
lock = threading.Lock()

def attack_worker(n):
    global sent
    for _ in range(n):
        try:
            requests.post(URL, timeout=3)
            with lock:
                sent += 1
                print(f"\r[ATTACK] Sent: {sent}/{TOTAL_REQUESTS}", end="", flush=True)
        except Exception as e:
            pass
        time.sleep(DELAY)

print(f"[*] Starting simulated DDoS attack → {URL}")
print(f"[*] Sending {TOTAL_REQUESTS} requests across {THREADS} threads...")
print()

per_thread = TOTAL_REQUESTS // THREADS
threads = []
for i in range(THREADS):
    t = threading.Thread(target=attack_worker, args=(per_thread,))
    threads.append(t)
    t.start()

for t in threads:
    t.join()

print(f"\n\n[✓] Attack simulation complete — {sent} requests sent.")
print("[*] Check your dashboard — you should see FLAGGED/BLOCKED entries.")
