import gymnasium as gym
from gymnasium import spaces
import numpy as np

class SecurityEnv(gym.Env):
    """
    A custom Gymnasium environment to simulate making a cybersecurity decision.
    The agent learns the best mitigation action for a given threat analysis by
    receiving rewards based on the "ground truth" from a historical dataset.
    """
    def __init__(self):
        super(SecurityEnv, self).__init__()
        
        # --- 1. Action Space ---
        # Defines the discrete set of actions the agent can choose.
        # 0: Do Nothing, 1: Monitor, 2: Block IP
        self.action_space = spaces.Discrete(3)

        # --- 2. Observation Space ---
        # Defines the information the agent receives.
        # Format: [ threat_type_id, risk_level_id ]
        self.observation_space = spaces.Box(low=0, high=10, shape=(2,), dtype=np.float32)

        # --- 3. Mappings for converting text to numerical observations ---
        # These maps are crucial for converting the RAG system's JSON output
        # into a format the RL agent can understand.
        self.threat_map = {
            # ID 0: Benign / Not a threat (with aliases)
            "Legitimate Activity": 0, "Normal": 0, "Informational": 0, "N/A": 0, None: 0,
            
            # ID 1: Low-level suspicious activity
            "Reconnaissance": 1,
            
            # ID 2: Clear attack patterns (with aliases)
            "Brute Force": 2, "Brute Force Attack": 2, "Failed Login": 2,
            
            # ID 3: More severe attacks
            "SQL Injection": 3, "Command Injection": 3,
            
            # ID 4: Host-based threats
            "Suspicious Host Activity": 4, "Suspicious Process Creation": 4,
            
            # ID 5: High-impact attacks
            "DoS": 5, "Exploit": 5, "Worms": 5, "Shellcode": 5, "Backdoors": 5,
        }
        self.risk_map = {
            # ID 0: Low / No risk (with aliases)
            "N/A": 0, "Informational": 0, "Low": 0, None: 0,
            
            # ID 1: Medium risk
            "Medium": 1,
            
            # ID 2: High risk
            "High": 2,
            
            # ID 3: Critical risk
            "Critical": 3,
        }
        
        # --- 4. Initialize the internal state ---
        self.current_analysis = None
        print("SecurityEnv: Initialized.")

    def get_obs_from_analysis(self, analysis_json):
        """
        Converts a JSON analysis from the RAG system into a numerical observation array.
        This version is robust to None values and variations in string casing.
        """
        threat_type = analysis_json.get('threat_type')
        risk_level = analysis_json.get('risk_level')

        # Look up the threat_id, defaulting to 0 if not found or if the type is unknown.
        threat_id = self.threat_map.get(threat_type)
        if threat_id is None and isinstance(threat_type, str):
            threat_id = self.threat_map.get(threat_type.title(), 0)
        elif threat_id is None:
            threat_id = 0

        # Look up the risk_id, defaulting to 0.
        risk_id = self.risk_map.get(risk_level)
        if risk_id is None and isinstance(risk_level, str):
            risk_id = self.risk_map.get(risk_level.title(), 0)
        elif risk_id is None:
            risk_id = 0

        return np.array([threat_id, risk_id], dtype=np.float32)

    def set_current_analysis(self, analysis_json):
        """
        An external method used by the training callback (or the live pipeline)
        to load the current event into the environment's state.
        """
        self.current_analysis = analysis_json

    def reset(self, *, seed=None, options=None):
        """
        Resets the environment for a new episode. In our case, it generates an
        observation based on the currently loaded event.
        """
        if self.current_analysis is None:
            # If no event is loaded (e.g., at the very start of training),
            # return a default, neutral observation.
            obs = np.array([0, 0], dtype=np.float32)
        else:
            obs = self.get_obs_from_analysis(self.current_analysis)
        
        info = {}
        return obs, info

    def step(self, action):
        """
        Executes the agent's chosen action and calculates the reward.
        This is the core of the learning process.
        
        Reward function logic:
        - For ACTUAL ATTACKS:
          - Do Nothing: -100 (heavy penalty)
          - Monitor: +5 (small reward)
          - Block IP: +50 to +100 (high reward, higher for critical)
        
        - For NORMAL traffic:
          - Do Nothing: +20 (high reward)
          - Monitor: -5 (small penalty)
          - Block IP: -200 (massive penalty for false positive)
        """
        if self.current_analysis is None:
            raise ValueError("`step()` was called before an event was loaded with `set_current_analysis()`.")

        reward = 0
        is_attack = self.current_analysis.get('is_attack', False)
        risk_level = str(self.current_analysis.get('risk_level', 'Low')).lower()

        # --- The Aggressive Reward Function ---
        if is_attack:
            # The event IS A REAL ATTACK
            if action == 0:    # Do Nothing
                reward = -100   # Heavy penalty for ignoring a threat
            elif action == 1:  # Monitor
                reward = 5     # Small reward, better than nothing
            elif action == 2:  # Block IP
                if risk_level == 'critical':
                    reward = 100
                elif risk_level == 'high':
                    reward = 50
                else:
                    reward = 25
        else:
            # The event IS NOT an attack
            if action == 0:    # Do Nothing
                reward = 20    # High reward for correctly ignoring normal traffic
            elif action == 1:  # Monitor
                reward = -5    # Small penalty for being overly cautious
            elif action == 2:  # Block IP
                reward = -200  # Massive penalty for blocking a legitimate user

        terminated = True  # Each event is its own self-contained episode
        truncated = False
        info = {}
        next_observation = self.get_obs_from_analysis(self.current_analysis)

        return next_observation, reward, terminated, truncated, info