import time
import re
import subprocess
import os

# --- Configuration ---
LOG_FILE_PATH = "victim_logs/unified.log"
RULES_FILE_PATH = "attack_patterns.txt"
VICTIM_CONTAINER_NAME = "victim-website"

class RAGAnalyzer:
    """
    Simplified Retrieval-Augmented Generation.
    It "retrieves" rules from a file and uses them to "generate" a verdict.
    """
    def __init__(self, rules_path):
        self.rules = []
        print(f"[Analyzer] Loading rules from {rules_path}...")
        try:
            with open(rules_path, 'r') as f:
                for line in f:
                    if line.strip() and not line.startswith('#'):
                        # Compile regex for efficiency
                        self.rules.append(re.compile(line.strip()))
            print(f"[Analyzer] Loaded {len(self.rules)} rules.")
        except FileNotFoundError:
            print(f"[Analyzer] ERROR: Rules file not found at {rules_path}. No analysis will be performed.")

    def analyze_log(self, log_line):
        """Analyzes a single log line against the loaded rules."""
        for rule in self.rules:
            if rule.search(log_line):
                # Extract the source IP address (first element in the log)
                source_ip = log_line.split()[0]
                print(f"🚨 ATTACK DETECTED! Rule: '{rule.pattern}' matched in log line.")
                return source_ip
        return None

class Executor:
    """Executes defensive actions."""
    def __init__(self, target_container):
        self.target_container = target_container
        self.blocked_ips = set()

    def block_ip(self, ip_address):
        """Blocks an IP address using iptables inside the target container."""
        if ip_address in self.blocked_ips:
            # Don't try to block an IP that is already blocked
            return

        print(f"🛡️ [Executor] DECISION: Block IP {ip_address}")
        # Construct the command to be run inside the container
        command = [
            "docker", "exec", self.target_container,
            "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"
        ]
        
        try:
            subprocess.run(command, check=True, capture_output=True, text=True)
            print(f"✅ ACTION EXECUTED: Successfully blocked {ip_address} on {self.target_container}.")
            self.blocked_ips.add(ip_address)
        except subprocess.CalledProcessError as e:
            print(f"❌ ACTION FAILED: Could not block {ip_address}.")
            print(f"   Error: {e.stderr}")

def tail_log_file(log_file):
    """A generator that yields new lines from a file."""
    if not os.path.exists(log_file):
        # Create the file if it doesn't exist to prevent errors
        open(log_file, 'a').close()

    with open(log_file, 'r') as f:
        f.seek(0, 2) # Go to the end of the file
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1) # Wait for new lines
                continue
            yield line

def main():
    """Main defense loop."""
    print("--- Defender AIS Initializing ---")
    analyzer = RAGAnalyzer(RULES_FILE_PATH)
    executor = Executor(VICTIM_CONTAINER_NAME)
    
    # This is the LogParser component
    print(f"\n[LogParser] Watching for new entries in {LOG_FILE_PATH}...")
    log_stream = tail_log_file(LOG_FILE_PATH)

    for log_line in log_stream:
        # Pass the log to the analyzer
        attacking_ip = analyzer.analyze_log(log_line.strip())
        
        # If an attack is detected, execute a defensive action
        if attacking_ip:
            executor.block_ip(attacking_ip)

if __name__ == "__main__":
    main()