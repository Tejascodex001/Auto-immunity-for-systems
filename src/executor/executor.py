import subprocess
import ipaddress
import re

class Executor:
    """
    The Executor class is responsible for taking the analysis from the LLM
    and translating it into concrete, real-world actions on the system.
    """
    def __init__(self, dry_run=True):
        """
        Initializes the Executor.

        Args:
            dry_run (bool): If True, the Executor will only print the actions it
                            would take, without actually executing them. This is a
                            critical safety feature for development and testing.
                            Defaults to True.
        """
        self.dry_run = dry_run
        if self.dry_run:
            print("Executor Initialized in Dry Run Mode. No actions will be executed.")
        else:
            print("WARNING: Executor Initialized in LIVE Mode. Actions will be executed.")

    def process_actions(self, analysis_json):
        """
        The main entry point for the Executor. It parses the analysis and dispatches
        the recommended actions to the appropriate methods.

        Args:
            analysis_json (dict): The JSON output from the RAGSecurityAnalyzer.
        """
        if not isinstance(analysis_json, dict):
            print("Executor Error: Received invalid analysis format (not a dictionary).")
            return

        # Extract the list of recommended actions and the source IP
        actions = analysis_json.get('recommended_actions', [])
        source_ip = analysis_json.get('source_ip')

        if not actions:
            print("Executor Info: No recommended actions found in the analysis.")
            return

        print(f"Executor processing {len(actions)} recommended action(s)...")
        for action in actions:
            action_lower = action.lower()

            # --- Action Dispatcher ---
            # This is where we map keywords in the action string to our methods.

            if "block source ip" in action_lower or "block the source ip" in action_lower:
                if source_ip:
                    self._block_ip(source_ip)
                else:
                    print(f"Executor Warning: 'Block IP' action found, but no 'source_ip' in analysis.")

            elif "monitor" in action_lower:
                if source_ip:
                    self._monitor_ip(source_ip, action)
                else:
                    print(f"Executor Warning: 'Monitor' action found, but no 'source_ip' in analysis.")
            
            # Add more actions here with 'elif' statements in the future
            # elif "isolate host" in action_lower:
            #     self._isolate_host(analysis_json.get('host_name'))
            
            else:
                print(f"Executor Info: No handler for action: '{action}'")

    def _validate_ip(self, ip_address):
        """A helper method to validate an IP address format."""
        try:
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            print(f"Executor Error: Invalid IP address format for '{ip_address}'. Aborting action.")
            return False

    def _block_ip(self, ip_address):
        """
        Adds a firewall rule to block an incoming IP address using iptables.
        NOTE: This requires the script to be run with sudo privileges in live mode.
        """
        if not self._validate_ip(ip_address):
            return

        # The command to insert a rule at the top of the INPUT chain to DROP packets from the source IP
        command = ["sudo", "iptables", "-I", "INPUT", "1", "-s", ip_address, "-j", "DROP"]

        print(f"Executor Action: Attempting to block IP address {ip_address}.")
        
        if self.dry_run:
            print(f"DRY RUN: Would have executed command: {' '.join(command)}")
        else:
            try:
                # Execute the command
                result = subprocess.run(command, check=True, capture_output=True, text=True)
                print(f"Executor Success: Successfully blocked IP {ip_address}.")
                # Optional: Log the stdout from the command
                # if result.stdout: print(result.stdout)
            except FileNotFoundError:
                print("Executor CRITICAL ERROR: 'sudo' or 'iptables' command not found. Is it installed and in the PATH?")
            except subprocess.CalledProcessError as e:
                print(f"Executor CRITICAL ERROR: Failed to execute iptables command for IP {ip_address}.")
                print(f"  Return Code: {e.returncode}")
                print(f"  Error Output: {e.stderr}")

    def _monitor_ip(self, ip_address, action_details):
        """
        A placeholder for a monitoring action. In a real system, this could
        add the IP to a watchlist or increase its logging verbosity.
        """
        if not self._validate_ip(ip_address):
            return

        print(f"Executor Action: Adding IP {ip_address} to monitoring watchlist.")
        print(f"  Details: {action_details}")
        if self.dry_run:
            print("DRY RUN: This is a simulated monitoring action.")
        else:
            # In a real system, you would add logic here to:
            # - Write the IP to a "watchlist.txt" file
            # - Send an alert to a chat system
            # - Integrate with a SIEM
            pass


# =====================================================================================
# --- Standalone Test Block ---
# This allows you to test the executor.py file directly.
# =====================================================================================
if __name__ == "__main__":
    print("--- Testing Executor as a standalone script ---")

    # --- Test Case 1: Brute-force attack analysis ---
    sample_analysis_1 = {
      "summary": "A failed SSH login attempt for the 'root' user was detected.",
      "threat_type": "Brute-force Attempt",
      "source_ip": "203.0.113.75",
      "risk_level": "High",
      "recommended_actions": [
          "Block the source IP at the firewall.", 
          "Monitor for further attempts from this source."
      ]
    }

    # --- Test Case 2: Benign analysis ---
    sample_analysis_2 = {
      "summary": "A successful login was detected.",
      "threat_type": "Legitimate Login",
      "source_ip": "192.168.1.100",
      "risk_level": "Low",
      "recommended_actions": [
          "No action required."
      ]
    }
    
    # --- Test Case 3: Invalid IP ---
    sample_analysis_3 = {
      "summary": "Malformed log with bad IP",
      "threat_type": "Unknown",
      "source_ip": "999.999.999.999",
      "risk_level": "Critical",
      "recommended_actions": [
          "Block source IP"
      ]
    }

    print("\n--- Test 1: High-risk event (Dry Run Mode) ---")
    executor_dry = Executor(dry_run=True)
    executor_dry.process_actions(sample_analysis_1)
    
    print("\n--- Test 2: Low-risk event (Dry Run Mode) ---")
    executor_dry.process_actions(sample_analysis_2)

    print("\n--- Test 3: Invalid IP (Dry Run Mode) ---")
    executor_dry.process_actions(sample_analysis_3)

    # --- LIVE MODE TEST (USE WITH CAUTION) ---
    # To test this for real, you would need to run the script with sudo:
    # sudo python executor.py
    # Then uncomment the lines below. It will try to block a real IP.
    # print("\n--- Test 4: High-risk event (LIVE MODE) ---")
    # print("WARNING: This will attempt to modify your system's firewall.")
    # live_executor = Executor(dry_run=False)
    # live_executor.process_actions(sample_analysis_1)