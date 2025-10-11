import requests
import json
import random
import time
import subprocess
import os

# --- Configuration ---
LOG_OUTPUT_FILE = "victim_logs/unified.log" # Let's use the unified log now
ORCHESTRATOR_API_URL = "http://localhost:8000/attack/curl"

# A mix of payloads for the live demo
DEMO_PAYLOADS = [
    # Normal Traffic
    {"type": "normal", "payload": {"target": "http://victim-website/"}},
    {"type": "normal", "payload": {"target": "http://victim-website/index.html"}},
    # Malicious Traffic
    {"type": "attack", "payload": {"target": "http://victim-website/admin.php"}},
    {"type": "attack", "payload": {"target": "http://victim-website/.env"}},
    {"type": "attack", "payload": {"target": "http://victim-website/login?id=1'%20OR%20'1'='1"}},
    # More Normal Traffic
    {"type": "normal", "payload": {"target": "http://victim-website/about.html"}},
    # More Malicious Traffic
    {"type": "attack", "payload": {"target": "http://victim-website/static/../../../../etc/passwd"}},
    {"type": "attack", "payload": {"target": "http://victim-website/", "args": "-A \"Nikto/2.1.5\""}}
]

def make_request(payload):
    """Sends a single request to our Attack Orchestrator."""
    try:
        requests.post(ORCHESTRATOR_API_URL, json=payload, timeout=5)
        print(f"  Sent: {payload.get('target')}")
        return True
    except requests.exceptions.RequestException as e:
        print(f"  Error sending request: {e}")
        return False

def get_last_log_line():
    """Fetches only the most recent log line from the victim container."""
    result = subprocess.run(["docker", "logs", "victim-website", "--tail", "1"], capture_output=True, text=True)
    # The output can have both stdout and stderr, we just need the last non-empty line
    lines = (result.stdout + result.stderr).strip().splitlines()
    return lines[-1] if lines else None

def main():
    """Orchestrates a live attack, appending logs in real-time."""
    print("--- Starting Live Attack Simulation ---")

    # 1. Clear the log file on disk to start the demo fresh.
    print(f"[Step 1] Clearing local log file: {LOG_OUTPUT_FILE}")
    open(LOG_OUTPUT_FILE, 'w').close()
    
    # 2. Restart the victim container to clear its internal log buffer.
    print("[Step 2] Clearing victim container's log buffer...")
    subprocess.run(["docker", "restart", "victim-website"], capture_output=True, text=True)
    time.sleep(2) # Give nginx time to restart

    # 3. Iterate through payloads, send request, append log.
    print("\n[Step 3] Sending requests and generating live log stream...")
    for item in DEMO_PAYLOADS:
        print(f"\nSending {item['type']} request...")
        
        # Send the request
        success = make_request(item['payload'])
        
        if success:
            # Give the container a moment to write the log
            time.sleep(0.5)
            
            # Get the new log line
            last_line = get_last_log_line()
            
            if last_line:
                print(f"  Appending log: {last_line}")
                # Append the new log line to our file
                with open(LOG_OUTPUT_FILE, "a") as f:
                    f.write(last_line + "\n")
        
        # Wait a moment before the next attack
        time.sleep(1)

    print("\n--- Live attack simulation finished. ---")


if __name__ == "__main__":
    main()