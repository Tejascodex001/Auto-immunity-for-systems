# run_attack.py
import requests
import json

# This simulates the JSON payload your LLM would generate.
# Let's tell the orchestrator to scan for directories on the victim.
attack_payload = {
    "target": "http://victim-website"
    # We're targeting the victim by its container name.
    # This only works because the attacker is on the same Docker network.
}

# The API is accessible on localhost because we used "-p 8000:8000"
api_url = "http://localhost:8000/attack/gobuster"

print(f"--- Sending Attack Order to Orchestrator ---")
print(f"Endpoint: {api_url}")
print(f"Payload: {json.dumps(attack_payload, indent=2)}")

try:
    # Send the POST request to the Attack Orchestrator API
    response = requests.post(api_url, json=attack_payload, timeout=120)
    response.raise_for_status() # Raise an error for bad status codes (like 4xx or 5xx)

    print("\n--- Attack Completed. Orchestrator Response: ---")
    # The API returns the output of the tool it ran
    print(json.dumps(response.json(), indent=2))

except requests.exceptions.RequestException as e:
    print(f"\n--- ERROR ---")
    print(f"Could not execute attack. Details: {e}")
    if e.response:
        print(f"API Error Message: {e.response.text}")