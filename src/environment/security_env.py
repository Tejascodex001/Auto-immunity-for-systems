# src/environment/security_env.py

import gymnasium as gym
from gymnasium import spaces
import numpy as np

class SecurityEnv(gym.Env):
    def __init__(self):
        super(SecurityEnv, self).__init__()
        print("SecurityEnv: Initialized")
        
        self.action_space = spaces.Discrete(3)
        self.observation_space = spaces.Box(low=0, high=10, shape=(2,), dtype=np.float32)

        # Your threat_map and risk_map are correct...
        self.threat_map = {
            "Legitimate Activity": 0, "Normal": 0, "Reconnaissance": 1, 
            "Brute Force": 2, "Brute Force Attack": 2, "Failed Login": 2,
            # ... etc
        }
        self.risk_map = {
            "N/A": 0, "Informational": 0, "Low": 0, None: 0,
            "Medium": 1, "High": 2, "Critical": 3,
        }
        
        # --- THIS IS THE FIX ---
        # We must initialize the attribute when the object is created.
        # We set it to None to indicate that no event has been loaded yet.
        self.current_analysis = None

    def get_obs_from_analysis(self, analysis_json):
        """
        A more robust helper function to convert a JSON analysis into a numerical observation.
        It now handles None values and different string casings.
        """
        # Get the values, which could be None
        threat_type = analysis_json.get('threat_type')
        risk_level = analysis_json.get('risk_level')

        # Handle variations in string casing by checking for the capitalized version
        # This is a simple but effective way to normalize the LLM's output.
        threat_id = self.threat_map.get(threat_type)
        if threat_id is None and isinstance(threat_type, str):
            threat_id = self.threat_map.get(threat_type.title(), 0) # Default to 0 if still not found
        elif threat_id is None:
            threat_id = 0

        risk_id = self.risk_map.get(risk_level)
        if risk_id is None and isinstance(risk_level, str):
            risk_id = self.risk_map.get(risk_level.title(), 0)
        elif risk_id is None:
            risk_id = 0

        return np.array([threat_id, risk_id], dtype=np.float32)

    def set_current_analysis(self, analysis_json):
        """A new method to load the next event into the environment."""
        self.current_analysis = analysis_json

    def reset(self, *, seed=None, options=None):
        """Resets the environment. Now returns an observation from the current analysis."""
        if self.current_analysis is None:
            # Provide a default observation if no analysis is set
            obs = np.array([0, 0], dtype=np.float32)
        else:
            obs = self.get_obs_from_analysis(self.current_analysis)
        info = {}
        return obs, info

    # --- THIS IS THE CORRECTED STEP METHOD ---
    # It no longer takes 'analysis_json' as an argument.
    # In the SecurityEnv class...

    def step(self, action):
        if self.current_analysis is None:
            raise ValueError("`step()` called before `set_current_analysis()`")

        reward = 0
        is_attack = self.current_analysis.get('is_attack', False)
        risk_level = self.current_analysis.get('risk_level', 'Low').lower()

        # --- NEW, MORE AGGRESSIVE REWARD FUNCTION ---

        if is_attack:
            # --- The event IS A REAL ATTACK ---
            if action == 0: # Do Nothing
                # HEAVY penalty for ignoring a real threat.
                reward = -40
            elif action == 1: # Monitor
                # Small positive reward. It's better than nothing.
                reward = 5
            elif action == 2: # Block IP
                # HIGH reward for taking the correct, decisive action.
                # We can even scale it by risk.
                if risk_level == 'critical':
                    reward = 100
                else: # high or medium
                    reward = 50
        else:
            # --- The event IS NOT an attack (legitimate) ---
            if action == 0: # Do Nothing
                # HIGH reward for correctly identifying and ignoring normal traffic.
                reward = 20
            elif action == 1: # Monitor
                # Small penalty for being overly cautious.
                reward = -5
            elif action == 2: # Block IP
                # MASSIVE penalty for blocking a legitimate user. This is the worst mistake.
                reward = -100
        
        terminated = True
        truncated = False
        info = {}
        next_observation = self.get_obs_from_analysis(self.current_analysis)

        return next_observation, reward, terminated, truncated, info