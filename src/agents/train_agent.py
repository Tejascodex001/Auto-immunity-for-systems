# src/agents/train_agent.py

import sys
import os
import json
import pandas as pd
from stable_baselines3 import PPO
from stable_baselines3.common.callbacks import BaseCallback

# --- Import our corrected custom environment ---
try:
    current_dir = os.path.dirname(os.path.abspath(__file__))
    src_dir = os.path.dirname(current_dir)
    sys.path.append(src_dir)
    from environment.security_env import SecurityEnv
except ImportError as e:
    print(f"Error: Could not import SecurityEnv. Details: {e}")
    sys.exit(1)

# --- NEW: A custom callback to feed our offline data ---
class SimulationCallback(BaseCallback):
    """
    A custom callback that resets the environment with a new event
    from our simulation data at the start of each rollout.
    """
    def __init__(self, simulation_df, verbose=0):
        super(SimulationCallback, self).__init__(verbose)
        self.simulation_df = simulation_df

    def _on_rollout_start(self) -> None:
        """This is called before collecting new experiences."""
        # Sample a random event from our dataset
        sample_event = self.simulation_df.sample(1).iloc[0].to_dict()
        # Set this event as the "current analysis" in our environment
        self.training_env.env_method("set_current_analysis", sample_event)

    def _on_step(self) -> bool:
        return True # Continue training

# --- Configuration ---
TRAINING_DATA_PATH = "/home/tejas/Projects/AIS/data/mordor_finetuning.jsonl"
MODEL_SAVE_PATH = "./ais_rl_agent_ppo.zip"
TOTAL_TRAINING_STEPS = 25000

# --- Main Training Script ---
if __name__ == "__main__":
    print("--- Starting Offline RL Agent Training ---")

    # 1. Load the simulation data
    print(f"Loading simulation data from: {TRAINING_DATA_PATH}")
    if not os.path.exists(TRAINING_DATA_PATH):
        print(f"ERROR: Training data not found.")
        sys.exit(1)
        
    all_events = [json.loads(json.loads(line)['messages'][2]['content']) for line in open(TRAINING_DATA_PATH, 'r')]
    simulation_df = pd.DataFrame(all_events)
    print(f"Loaded {len(simulation_df)} events for training simulation.")

    # 2. Initialize the environment and the callback
    env = SecurityEnv()
    simulation_callback = SimulationCallback(simulation_df)

    # 3. Initialize the PPO Agent, now using the CPU as recommended
    agent = PPO("MlpPolicy", env, verbose=1, device="cpu")

    # 4. The NEW, Simplified Training Call
    # We've removed the manual loop and now pass our custom callback to the learn() method.
    # The callback will inject our offline data into the standard training process.
    print(f"Starting training for {TOTAL_TRAINING_STEPS} steps...")
    agent.learn(total_timesteps=TOTAL_TRAINING_STEPS, callback=simulation_callback)

    # 5. Save the trained agent
    agent.save(MODEL_SAVE_PATH)
    print(f"\n✅ Training complete. Agent saved to '{MODEL_SAVE_PATH}'")