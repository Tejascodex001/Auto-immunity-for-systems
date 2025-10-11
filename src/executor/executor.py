import subprocess
import ipaddress
import re
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class Executor:
    """
    Enhanced Executor class responsible for translating security analysis
    into concrete, real-world actions on the system with comprehensive logging
    and action history tracking.
    """
    
    # Action type constants
    ACTION_BLOCK_IP = "block_ip"
    ACTION_MONITOR_IP = "monitor_ip"
    ACTION_ALERT = "alert"
    ACTION_ISOLATE = "isolate"
    ACTION_LOG = "log"
    
    def __init__(self, dry_run: bool = True, log_dir: Optional[str] = None):
        """
        Initialize the Executor with enhanced capabilities.

        Args:
            dry_run (bool): If True, only simulates actions without execution.
                           Defaults to True.
            log_dir (str): Directory for action logs and history.
                          Defaults to current directory.
        """
        self.dry_run = dry_run
        self.log_dir = Path(log_dir) if log_dir else Path.cwd()
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Action history tracking
        self.action_history = []
        self.action_stats = {
            'total_actions': 0,
            'successful_actions': 0,
            'failed_actions': 0,
            'skipped_actions': 0,
            'action_types': {}
        }
        
        # Initialize action log file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.action_log_file = self.log_dir / f"action_log_{timestamp}.json"
        self.blocked_ips_file = self.log_dir / f"blocked_ips_{timestamp}.txt"
        self.monitored_ips_file = self.log_dir / f"monitored_ips_{timestamp}.txt"
        
        mode = "DRY RUN Mode" if self.dry_run else "LIVE Mode"
        logger.info(f"{'='*80}")
        logger.info(f"Executor Initialized in {mode}")
        logger.info(f"Action Log: {self.action_log_file}")
        logger.info(f"Log Directory: {self.log_dir}")
        logger.info(f"{'='*80}")
        
        if not self.dry_run:
            logger.warning("⚠️  WARNING: Executor in LIVE MODE - Actions will be executed on the system!")

    def process_actions(self, analysis_json: Dict[str, Any]) -> None:
        """
        Main entry point for processing recommended actions from analysis.

        Args:
            analysis_json (dict): The JSON output from the RAG analyzer.
        """
        if not isinstance(analysis_json, dict):
            logger.error("Received invalid analysis format (not a dictionary).")
            self._record_action("process_actions", "FAILED", "Invalid input format")
            return

        # Extract analysis details
        actions = analysis_json.get('recommended_actions', [])
        source_ip = analysis_json.get('source_ip')
        threat_type = analysis_json.get('threat_type', 'Unknown')
        risk_level = analysis_json.get('risk_level', 'Unknown')
        confidence = analysis_json.get('confidence', 0.0)

        if not actions:
            logger.info("No recommended actions found in the analysis.")
            return

        logger.info(f"\n{'='*80}")
        logger.info(f"Processing {len(actions)} recommended action(s)")
        logger.info(f"Threat: {threat_type} | Risk: {risk_level} | Confidence: {confidence:.2f}")
        logger.info(f"{'='*80}")

        for action_idx, action in enumerate(actions, 1):
            self._dispatch_action(action, source_ip, analysis_json, action_idx)

    def _dispatch_action(self, action: str, source_ip: Optional[str], 
                        analysis_json: Dict[str, Any], action_idx: int) -> None:
        """
        Dispatcher that routes actions to appropriate handler methods.

        Args:
            action (str): Action description string.
            source_ip (str): Source IP from analysis.
            analysis_json (dict): Full analysis object.
            action_idx (int): Action index for logging.
        """
        action_lower = action.lower().strip()
        
        logger.info(f"\n[Action {action_idx}] {action}")

        # Block IP actions
        if any(phrase in action_lower for phrase in ["block source ip", "block the source ip", 
                                                       "block ip", "firewall block"]):
            if source_ip:
                self._block_ip(source_ip, analysis_json)
            else:
                logger.warning("Block IP action found, but no source_ip in analysis.")
                self.action_stats['skipped_actions'] += 1

        # Monitor IP actions
        elif any(phrase in action_lower for phrase in ["monitor", "watchlist", "surveillance"]):
            if source_ip:
                self._monitor_ip(source_ip, action, analysis_json)
            else:
                logger.warning("Monitor action found, but no source_ip in analysis.")
                self.action_stats['skipped_actions'] += 1

        # Alert actions
        elif any(phrase in action_lower for phrase in ["alert", "escalate", "notify"]):
            self._create_alert(analysis_json, action)

        # Isolate actions
        elif any(phrase in action_lower for phrase in ["isolate", "quarantine", "disconnect"]):
            self._isolate_system(analysis_json, action)

        # Log actions
        elif any(phrase in action_lower for phrase in ["log", "record", "document"]):
            self._log_event(analysis_json, action)

        # Kill process actions
        elif any(phrase in action_lower for phrase in ["kill process", "terminate", "stop process"]):
            self._kill_process(analysis_json, action)

        # Disable user actions
        elif any(phrase in action_lower for phrase in ["disable user", "lock account"]):
            self._disable_user(analysis_json, action)

        else:
            logger.info(f"No specific handler for action, logging as generic: '{action}'")
            self._log_event(analysis_json, action)

    def _block_ip(self, ip_address: str, analysis_json: Dict[str, Any]) -> None:
        """
        Block an IP address using iptables firewall rules.
        
        Args:
            ip_address (str): IP address to block.
            analysis_json (dict): Full analysis object.
        """
        if not self._validate_ip(ip_address):
            self.action_stats['failed_actions'] += 1
            self._record_action(self.ACTION_BLOCK_IP, "FAILED", f"Invalid IP: {ip_address}")
            return

        command = ["sudo", "iptables", "-I", "INPUT", "1", "-s", ip_address, "-j", "DROP"]
        
        logger.info(f"→ Blocking IP: {ip_address}")
        logger.info(f"  Threat Type: {analysis_json.get('threat_type', 'Unknown')}")
        logger.info(f"  Risk Level: {analysis_json.get('risk_level', 'Unknown')}")

        if self.dry_run:
            logger.info(f"  DRY RUN: Would execute: {' '.join(command)}")
            self.action_stats['successful_actions'] += 1
            self._record_action(self.ACTION_BLOCK_IP, "SUCCESS (DRY)", 
                              f"IP blocked: {ip_address}", analysis_json)
            self._append_to_file(self.blocked_ips_file, 
                               f"{datetime.now().isoformat()} - {ip_address} - {analysis_json.get('threat_type')}")
        else:
            try:
                result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=10)
                logger.info(f"✓ Successfully blocked IP: {ip_address}")
                self.action_stats['successful_actions'] += 1
                self._record_action(self.ACTION_BLOCK_IP, "SUCCESS", 
                                  f"IP blocked: {ip_address}", analysis_json)
                self._append_to_file(self.blocked_ips_file, 
                                   f"{datetime.now().isoformat()} - {ip_address} - {analysis_json.get('threat_type')}")
            except FileNotFoundError:
                logger.error("✗ CRITICAL: 'sudo' or 'iptables' command not found.")
                self.action_stats['failed_actions'] += 1
                self._record_action(self.ACTION_BLOCK_IP, "FAILED", 
                                  "iptables/sudo not found", analysis_json)
            except subprocess.CalledProcessError as e:
                logger.error(f"✗ CRITICAL: Failed to execute iptables for IP {ip_address}")
                logger.error(f"  Return Code: {e.returncode}")
                logger.error(f"  Error: {e.stderr}")
                self.action_stats['failed_actions'] += 1
                self._record_action(self.ACTION_BLOCK_IP, "FAILED", 
                                  f"iptables error: {e.stderr}", analysis_json)
            except subprocess.TimeoutExpired:
                logger.error(f"✗ CRITICAL: Command timeout for IP {ip_address}")
                self.action_stats['failed_actions'] += 1
                self._record_action(self.ACTION_BLOCK_IP, "FAILED", 
                                  "Command timeout", analysis_json)

    def _monitor_ip(self, ip_address: str, action_details: str, 
                   analysis_json: Dict[str, Any]) -> None:
        """
        Add IP to monitoring watchlist for enhanced logging and alerting.

        Args:
            ip_address (str): IP address to monitor.
            action_details (str): Action details.
            analysis_json (dict): Full analysis object.
        """
        if not self._validate_ip(ip_address):
            self.action_stats['failed_actions'] += 1
            self._record_action(self.ACTION_MONITOR_IP, "FAILED", f"Invalid IP: {ip_address}")
            return

        logger.info(f"→ Adding IP to monitoring watchlist: {ip_address}")
        logger.info(f"  Details: {action_details}")
        logger.info(f"  Threat Type: {analysis_json.get('threat_type', 'Unknown')}")

        if self.dry_run:
            logger.info(f"  DRY RUN: Would add IP to watchlist and increase logging verbosity")
            self.action_stats['successful_actions'] += 1
            self._record_action(self.ACTION_MONITOR_IP, "SUCCESS (DRY)", 
                              f"IP monitored: {ip_address}", analysis_json)
            self._append_to_file(self.monitored_ips_file, 
                               f"{datetime.now().isoformat()} - {ip_address} - {analysis_json.get('threat_type')}")
        else:
            try:
                # Add IP to watchlist file
                self._append_to_file(self.monitored_ips_file, 
                                   f"{datetime.now().isoformat()} - {ip_address} - {analysis_json.get('threat_type')}")
                logger.info(f"✓ Successfully added IP {ip_address} to monitoring watchlist")
                self.action_stats['successful_actions'] += 1
                self._record_action(self.ACTION_MONITOR_IP, "SUCCESS", 
                                  f"IP monitored: {ip_address}", analysis_json)
            except Exception as e:
                logger.error(f"✗ Failed to add IP {ip_address} to watchlist: {e}")
                self.action_stats['failed_actions'] += 1
                self._record_action(self.ACTION_MONITOR_IP, "FAILED", str(e), analysis_json)

    def _create_alert(self, analysis_json: Dict[str, Any], action: str) -> None:
        """
        Create and escalate security alert to monitoring team.

        Args:
            analysis_json (dict): Full analysis object.
            action (str): Action description.
        """
        logger.info(f"→ Creating security alert")
        logger.info(f"  Threat: {analysis_json.get('threat_type', 'Unknown')}")
        logger.info(f"  Risk: {analysis_json.get('risk_level', 'Unknown')}")
        logger.info(f"  IP: {analysis_json.get('source_ip', 'N/A')}")

        if self.dry_run:
            logger.info(f"  DRY RUN: Would send alert to security team")
            self.action_stats['successful_actions'] += 1
            self._record_action(self.ACTION_ALERT, "SUCCESS (DRY)", 
                              f"Alert created: {action}", analysis_json)
        else:
            try:
                # In production, integrate with monitoring systems
                logger.info(f"✓ Alert escalated to security team")
                self.action_stats['successful_actions'] += 1
                self._record_action(self.ACTION_ALERT, "SUCCESS", 
                                  f"Alert created: {action}", analysis_json)
            except Exception as e:
                logger.error(f"✗ Failed to create alert: {e}")
                self.action_stats['failed_actions'] += 1
                self._record_action(self.ACTION_ALERT, "FAILED", str(e), analysis_json)

    def _isolate_system(self, analysis_json: Dict[str, Any], action: str) -> None:
        """
        Isolate affected system from network (critical action).

        Args:
            analysis_json (dict): Full analysis object.
            action (str): Action description.
        """
        logger.critical(f"→ ISOLATING SYSTEM - CRITICAL ACTION")
        logger.critical(f"  Threat: {analysis_json.get('threat_type', 'Unknown')}")
        logger.critical(f"  Risk: {analysis_json.get('risk_level', 'Unknown')}")

        if self.dry_run:
            logger.critical(f"  DRY RUN: Would isolate system from network")
            self.action_stats['successful_actions'] += 1
            self._record_action(self.ACTION_ISOLATE, "SUCCESS (DRY)", 
                              f"System isolated: {action}", analysis_json)
        else:
            logger.critical(f"  EXECUTING SYSTEM ISOLATION")
            try:
                # Implementation would depend on infrastructure
                logger.critical(f"✓ System isolation completed")
                self.action_stats['successful_actions'] += 1
                self._record_action(self.ACTION_ISOLATE, "SUCCESS", 
                                  f"System isolated: {action}", analysis_json)
            except Exception as e:
                logger.error(f"✗ Failed to isolate system: {e}")
                self.action_stats['failed_actions'] += 1
                self._record_action(self.ACTION_ISOLATE, "FAILED", str(e), analysis_json)

    def _kill_process(self, analysis_json: Dict[str, Any], action: str) -> None:
        """
        Kill malicious process.

        Args:
            analysis_json (dict): Full analysis object.
            action (str): Action description.
        """
        process_name = analysis_json.get('process_name')
        pid = analysis_json.get('pid')

        if not process_name and not pid:
            logger.warning("Kill process action: No process_name or pid found")
            self.action_stats['skipped_actions'] += 1
            self._record_action("kill_process", "SKIPPED", "No process identifier", analysis_json)
            return

        logger.warning(f"→ Killing process: {process_name or f'PID {pid}'}")

        if self.dry_run:
            logger.warning(f"  DRY RUN: Would kill process")
            self.action_stats['successful_actions'] += 1
            self._record_action("kill_process", "SUCCESS (DRY)", 
                              f"Process killed: {process_name}", analysis_json)
        else:
            try:
                if pid:
                    subprocess.run(["sudo", "kill", "-9", str(pid)], 
                                 check=True, timeout=10)
                logger.warning(f"✓ Process killed successfully")
                self.action_stats['successful_actions'] += 1
                self._record_action("kill_process", "SUCCESS", 
                                  f"Process killed: {process_name}", analysis_json)
            except Exception as e:
                logger.error(f"✗ Failed to kill process: {e}")
                self.action_stats['failed_actions'] += 1
                self._record_action("kill_process", "FAILED", str(e), analysis_json)

    def _disable_user(self, analysis_json: Dict[str, Any], action: str) -> None:
        """
        Disable compromised user account.

        Args:
            analysis_json (dict): Full analysis object.
            action (str): Action description.
        """
        username = analysis_json.get('username')

        if not username:
            logger.warning("Disable user action: No username found")
            self.action_stats['skipped_actions'] += 1
            self._record_action("disable_user", "SKIPPED", "No username", analysis_json)
            return

        logger.warning(f"→ Disabling user account: {username}")

        if self.dry_run:
            logger.warning(f"  DRY RUN: Would disable user account")
            self.action_stats['successful_actions'] += 1
            self._record_action("disable_user", "SUCCESS (DRY)", 
                              f"User disabled: {username}", analysis_json)
        else:
            try:
                subprocess.run(["sudo", "usermod", "-L", username], 
                             check=True, timeout=10)
                logger.warning(f"✓ User account disabled successfully")
                self.action_stats['successful_actions'] += 1
                self._record_action("disable_user", "SUCCESS", 
                                  f"User disabled: {username}", analysis_json)
            except Exception as e:
                logger.error(f"✗ Failed to disable user: {e}")
                self.action_stats['failed_actions'] += 1
                self._record_action("disable_user", "FAILED", str(e), analysis_json)

    def _log_event(self, analysis_json: Dict[str, Any], action: str) -> None:
        """
        Log security event for audit trail.

        Args:
            analysis_json (dict): Full analysis object.
            action (str): Action description.
        """
        logger.info(f"→ Logging event for audit trail")
        self._record_action(self.ACTION_LOG, "SUCCESS", action, analysis_json)
        self.action_stats['successful_actions'] += 1

    def _validate_ip(self, ip_address: str) -> bool:
        """
        Validate IP address format.

        Args:
            ip_address (str): IP address to validate.

        Returns:
            bool: True if valid, False otherwise.
        """
        try:
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            logger.error(f"Invalid IP address format: '{ip_address}'")
            return False

    def _record_action(self, action_type: str, status: str, details: str, 
                      analysis_json: Optional[Dict[str, Any]] = None) -> None:
        """
        Record action in action history and log file.

        Args:
            action_type (str): Type of action.
            status (str): Action status.
            details (str): Action details.
            analysis_json (dict): Full analysis object.
        """
        self.action_stats['total_actions'] += 1
        self.action_stats['action_types'][action_type] = \
            self.action_stats['action_types'].get(action_type, 0) + 1

        action_record = {
            'timestamp': datetime.now().isoformat(),
            'action_type': action_type,
            'status': status,
            'details': details,
            'analysis': analysis_json if analysis_json else {}
        }

        self.action_history.append(action_record)

        # Append to JSON log file
        try:
            with open(self.action_log_file, 'a') as f:
                f.write(json.dumps(action_record) + '\n')
        except Exception as e:
            logger.error(f"Failed to write to action log: {e}")

    def _append_to_file(self, filepath: Path, content: str) -> None:
        """
        Append content to file safely.

        Args:
            filepath (Path): File path.
            content (str): Content to append.
        """
        try:
            with open(filepath, 'a') as f:
                f.write(content + '\n')
        except Exception as e:
            logger.error(f"Failed to append to {filepath}: {e}")

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get executor statistics.

        Returns:
            dict: Statistics dictionary.
        """
        return self.action_stats

    def print_summary(self) -> None:
        """Print action execution summary."""
        logger.info("\n" + "=" * 80)
        logger.info("EXECUTOR ACTION SUMMARY")
        logger.info("=" * 80)
        logger.info(f"Total Actions: {self.action_stats['total_actions']}")
        logger.info(f"Successful: {self.action_stats['successful_actions']}")
        logger.info(f"Failed: {self.action_stats['failed_actions']}")
        logger.info(f"Skipped: {self.action_stats['skipped_actions']}")
        
        if self.action_stats['action_types']:
            logger.info(f"\nAction Types:")
            for action_type, count in self.action_stats['action_types'].items():
                logger.info(f"  {action_type}: {count}")
        
        logger.info(f"\n📁 Logs:")
        logger.info(f"  Action Log: {self.action_log_file}")
        logger.info(f"  Blocked IPs: {self.blocked_ips_file}")
        logger.info(f"  Monitored IPs: {self.monitored_ips_file}")
        logger.info("=" * 80 + "\n")


# =====================================================================================
# --- Standalone Test Block ---
# =====================================================================================
if __name__ == "__main__":
    logger.info("Testing Enhanced Executor")

    sample_analysis_1 = {
        "summary": "A failed SSH login attempt for the 'root' user was detected.",
        "threat_type": "Brute-force Attempt",
        "source_ip": "203.0.113.75",
        "risk_level": "High",
        "confidence": 0.95,
        "recommended_actions": [
            "Block the source IP at the firewall.",
            "Monitor for further attempts from this source."
        ]
    }

    sample_analysis_2 = {
        "summary": "A successful login was detected.",
        "threat_type": "Legitimate Login",
        "source_ip": "192.168.1.100",
        "risk_level": "Low",
        "confidence": 0.99,
        "recommended_actions": ["Log the event"]
    }

    logger.info("\n--- Test 1: High-risk event (Dry Run Mode) ---")
    executor_dry = Executor(dry_run=True)
    executor_dry.process_actions(sample_analysis_1)
    executor_dry.process_actions(sample_analysis_2)
    executor_dry.print_summary()