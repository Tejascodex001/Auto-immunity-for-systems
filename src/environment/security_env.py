import gymnasium as gym
from gymnasium import spaces
import numpy as np
from typing import Dict, Any, Tuple, Optional
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SecurityEnv(gym.Env):
    """
    Enhanced Gymnasium environment for comprehensive cybersecurity threat detection.
    Supports detection and response for 20+ threat types including:
    - Authentication attacks (Brute Force, Credential Stuffing)
    - Injection attacks (SQL, Command, XML)
    - Network attacks (DDoS, Port Scanning, Reconnaissance)
    - Malware/code attacks (Shellcode, Exploit, Backdoor, Malware, Worms)
    - Application attacks (XXE, CSRF, LFI, RFI)
    - Fuzzing and Reconnaissance
    """
    
    # Class-level constants for better maintainability
    ACTION_DO_NOTHING = 0
    ACTION_MONITOR = 1
    ACTION_BLOCK_IP = 2
    ACTION_ALERT = 3
    ACTION_ISOLATE = 4
    
    ACTION_NAMES = {
        ACTION_DO_NOTHING: "Do Nothing",
        ACTION_MONITOR: "Monitor",
        ACTION_BLOCK_IP: "Block IP",
        ACTION_ALERT: "Alert",
        ACTION_ISOLATE: "Isolate"
    }
    
    # Reward values as constants
    REWARD_CRITICAL_ATTACK_ISOLATED = 200
    REWARD_CRITICAL_ATTACK_BLOCKED = 150
    REWARD_HIGH_ATTACK_BLOCKED = 100
    REWARD_ATTACK_ISOLATED = 100
    REWARD_SEVERE_ALERT = 75
    REWARD_MEDIUM_ATTACK_BLOCKED = 50
    REWARD_NORMAL_DO_NOTHING = 30
    REWARD_LOW_ALERT = 20
    REWARD_LOW_MONITOR = 10
    
    PENALTY_UNNECESSARY_MONITOR = -10
    PENALTY_CRITICAL_NO_ACTION = -150
    PENALTY_CRITICAL_MONITOR = -50
    PENALTY_FALSE_ALERT = -50
    PENALTY_FALSE_BLOCK = -300
    PENALTY_FALSE_ISOLATE = -500

    def __init__(self):
        super(SecurityEnv, self).__init__()
        
        # --- 1. Action Space ---
        # 0: Do Nothing, 1: Monitor, 2: Block IP, 3: Alert, 4: Isolate
        self.action_space = spaces.Discrete(5)

        # --- 2. Observation Space ---
        # Format: [threat_type_id, risk_level_id, threat_severity]
        self.observation_space = spaces.Box(
            low=0, 
            high=10, 
            shape=(3,), 
            dtype=np.float32
        )

        # --- 3. Comprehensive Threat Mappings ---
        self.threat_map = self._initialize_threat_map()
        self.risk_map = self._initialize_risk_map()
        
        # Reverse mappings for debugging
        self.threat_id_to_name = {v: k for k, v in self.threat_map.items() 
                                  if isinstance(v, int)}
        self.risk_id_to_name = {v: k for k, v in self.risk_map.items() 
                                if isinstance(v, int)}
        
        self.current_analysis: Optional[Dict[str, Any]] = None
        self.episode_count = 0
        
        logger.info("SecurityEnv: Enhanced environment initialized with %d threat categories.", 
                   len(set(self.threat_map.values())))

    def _initialize_threat_map(self) -> Dict[str, int]:
        """Initialize comprehensive threat type mappings."""
        return {
            # ID 0: Benign / Normal
            "Normal": 0, 
            "Legitimate Activity": 0, 
            "Informational": 0, 
            "N/A": 0, 
            "Legitimate Login": 0,
            
            # ID 1: Low-level reconnaissance
            "Reconnaissance": 1, 
            "Port Scanning": 1, 
            "Network Enumeration": 1, 
            "Probing": 1,
            
            # ID 2: Authentication attacks
            "Brute Force Attack": 2, 
            "Credential Stuffing": 2, 
            "Password Attack": 2, 
            "Failed Login": 2,
            
            # ID 3: Injection attacks
            "SQL Injection": 3, 
            "Command Injection": 3, 
            "XML Injection": 3, 
            "LDAP Injection": 3,
            "Template Injection": 3, 
            "Code Injection": 3,
            
            # ID 4: Fuzzing and bypass attempts
            "Fuzzing": 4, 
            "Web Fuzzing": 4, 
            "Protocol Fuzzing": 4, 
            "Buffer Overflow": 4,
            "Payload Injection": 4, 
            "Input Fuzzing": 4,
            
            # ID 5: Application layer attacks
            "Cross-Site Scripting": 5, 
            "XSS": 5,
            "XXE": 5, 
            "CSRF": 5, 
            "Path Traversal": 5,
            "LFI": 5, 
            "RFI": 5, 
            "Directory Traversal": 5,
            
            # ID 6: Malware and backdoors
            "Malware": 6, 
            "Backdoors": 6, 
            "Trojan": 6, 
            "Backdoor Installation": 6,
            "Persistence": 6, 
            "Rootkit": 6,
            
            # ID 7: Exploits
            "Exploit": 7, 
            "Zero-Day": 7, 
            "Vulnerability Exploitation": 7,
            "Remote Code Execution": 7, 
            "RCE": 7,
            "Arbitrary Code Execution": 7,
            
            # ID 8: Worms and self-propagating malware
            "Worms": 8, 
            "Self-Propagating Malware": 8, 
            "Network Worm": 8,
            
            # ID 9: Shellcode and direct execution attacks
            "Shellcode": 9, 
            "Payload Execution": 9, 
            "Direct Code Execution": 9,
            "Memory Corruption": 9,
            
            # ID 10: Denial of Service attacks
            "DoS": 10, 
            "DDoS": 10, 
            "Distributed Denial of Service": 10, 
            "Application DDoS": 10,
            "Network DDoS": 10, 
            "DNS DDoS": 10, 
            "Slowloris": 10,
            
            # ID 11: Suspicious host/process activity
            "Suspicious Host Activity": 11, 
            "Suspicious Process Creation": 11,
            "Unauthorized Access": 11, 
            "Privilege Escalation": 11,
            
            # ID 12: Data exfiltration and lateral movement
            "Data Exfiltration": 12, 
            "Lateral Movement": 12,
            "Account Takeover": 12, 
            "Credential Theft": 12,
        }
    
    def _initialize_risk_map(self) -> Dict[str, int]:
        """Initialize risk level mappings."""
        return {
            "N/A": 0, 
            "Informational": 0, 
            "Low": 0,
            "Medium": 1,
            "High": 2,
            "Critical": 3,
        }

    def get_obs_from_analysis(self, analysis_json: Dict[str, Any]) -> np.ndarray:
        """
        Converts JSON analysis into a numerical observation array.
        
        Args:
            analysis_json: Dictionary containing threat analysis
            
        Returns:
            np.ndarray: [threat_type_id, risk_level_id, threat_severity]
        """
        threat_type = analysis_json.get('threat_type', 'Normal')
        risk_level = analysis_json.get('risk_level', 'Low')
        
        # Get threat ID (0-12)
        threat_id = self.threat_map.get(threat_type, 0)
        
        # Get risk ID (0-3)
        risk_id = self.risk_map.get(risk_level, 0)
        
        # Compute severity as normalized combination of threat type and risk
        # Avoid division by zero
        max_threat_id = max(self.threat_map.values())
        max_risk_id = max(self.risk_map.values())
        
        if max_threat_id > 0 and max_risk_id > 0:
            threat_severity = (threat_id / max_threat_id) * (risk_id / max_risk_id)
        else:
            threat_severity = 0.0
        
        return np.array([threat_id, risk_id, threat_severity], dtype=np.float32)

    def set_current_analysis(self, analysis_json: Dict[str, Any]) -> None:
        """
        Load current event into environment state.
        
        Args:
            analysis_json: Dictionary containing threat analysis
        """
        if not isinstance(analysis_json, dict):
            raise TypeError("analysis_json must be a dictionary")
        
        self.current_analysis = analysis_json
        logger.debug("Analysis loaded: threat=%s, risk=%s", 
                    analysis_json.get('threat_type'), 
                    analysis_json.get('risk_level'))

    def reset(self, *, seed: Optional[int] = None, 
              options: Optional[Dict[str, Any]] = None) -> Tuple[np.ndarray, Dict[str, Any]]:
        """
        Reset environment for new episode.
        
        Args:
            seed: Random seed for reproducibility
            options: Additional options
            
        Returns:
            Tuple of (observation, info_dict)
        """
        super().reset(seed=seed)
        self.episode_count += 1
        
        if self.current_analysis is None:
            obs = np.array([0, 0, 0], dtype=np.float32)
        else:
            obs = self.get_obs_from_analysis(self.current_analysis)
        
        info = {
            'episode': self.episode_count,
            'threat_type': self.current_analysis.get('threat_type') if self.current_analysis else None
        }
        
        return obs, info

    def _calculate_reward(self, action: int, is_attack: bool, 
                         risk_level: str) -> float:
        """
        Calculate reward based on action, attack status, and risk level.
        
        Args:
            action: Action taken (0-4)
            is_attack: Whether event is an attack
            risk_level: Risk level string
            
        Returns:
            float: Calculated reward value
        """
        risk_lower = risk_level.lower()
        
        if is_attack:
            # Real attack detected - reward appropriate responses
            if action == self.ACTION_DO_NOTHING:
                return self.PENALTY_CRITICAL_NO_ACTION
            
            elif action == self.ACTION_MONITOR:
                return (self.PENALTY_CRITICAL_MONITOR if risk_lower == 'critical' 
                       else self.REWARD_LOW_MONITOR)
            
            elif action == self.ACTION_BLOCK_IP:
                if risk_lower == 'critical':
                    return self.REWARD_CRITICAL_ATTACK_BLOCKED
                elif risk_lower == 'high':
                    return self.REWARD_HIGH_ATTACK_BLOCKED
                else:
                    return self.REWARD_MEDIUM_ATTACK_BLOCKED
            
            elif action == self.ACTION_ALERT:
                return (self.REWARD_SEVERE_ALERT if risk_lower in ['critical', 'high'] 
                       else self.REWARD_LOW_ALERT)
            
            elif action == self.ACTION_ISOLATE:
                return (self.REWARD_CRITICAL_ATTACK_ISOLATED if risk_lower == 'critical' 
                       else self.REWARD_ATTACK_ISOLATED)
        
        else:
            # Normal/benign event - penalize aggressive actions
            if action == self.ACTION_DO_NOTHING:
                return self.REWARD_NORMAL_DO_NOTHING
            
            elif action == self.ACTION_MONITOR:
                return self.PENALTY_UNNECESSARY_MONITOR
            
            elif action == self.ACTION_BLOCK_IP:
                return self.PENALTY_FALSE_BLOCK
            
            elif action == self.ACTION_ALERT:
                return self.PENALTY_FALSE_ALERT
            
            elif action == self.ACTION_ISOLATE:
                return self.PENALTY_FALSE_ISOLATE
        
        return 0.0

    def step(self, action: int) -> Tuple[np.ndarray, float, bool, bool, Dict[str, Any]]:
        """
        Execute action and calculate reward.
        
        Args:
            action: Action to take (0-4)
            
        Returns:
            Tuple of (observation, reward, terminated, truncated, info)
        """
        if self.current_analysis is None:
            raise ValueError("No analysis loaded. Call set_current_analysis() first.")
        
        if not 0 <= action < self.action_space.n:
            raise ValueError(f"Invalid action: {action}. Must be in range [0, {self.action_space.n-1}]")

        is_attack = self.current_analysis.get('is_attack', False)
        risk_level = str(self.current_analysis.get('risk_level', 'Low'))
        threat_type = self.current_analysis.get('threat_type', 'Normal')
        
        # Calculate reward
        reward = self._calculate_reward(action, is_attack, risk_level)
        
        # Get next observation
        next_observation = self.get_obs_from_analysis(self.current_analysis)
        
        # Episode always terminates after one step
        terminated = True
        truncated = False
        
        # Build info dictionary
        info = {
            'action_name': self.ACTION_NAMES[action],
            'is_attack': is_attack,
            'threat_type': threat_type,
            'risk_level': risk_level,
            'reward': reward,
            'source_ip': self.current_analysis.get('source_ip', 'unknown')
        }
        
        logger.debug("Step completed: action=%s, reward=%.2f, threat=%s", 
                    self.ACTION_NAMES[action], reward, threat_type)
        
        return next_observation, reward, terminated, truncated, info
    
    def render(self, mode: str = 'human') -> None:
        """
        Render the environment state.
        
        Args:
            mode: Rendering mode
        """
        if self.current_analysis:
            print(f"\n=== Security Environment State ===")
            print(f"Threat: {self.current_analysis.get('threat_type', 'Unknown')}")
            print(f"Risk: {self.current_analysis.get('risk_level', 'Unknown')}")
            print(f"Attack: {self.current_analysis.get('is_attack', False)}")
            print(f"Source IP: {self.current_analysis.get('source_ip', 'Unknown')}")
            print("=" * 35)
    
    def close(self) -> None:
        """Clean up environment resources."""
        self.current_analysis = None
        logger.info("Environment closed after %d episodes", self.episode_count)