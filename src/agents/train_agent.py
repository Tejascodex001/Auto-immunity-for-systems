# src/agents/train_agent.py

import sys
import os
import json
import pandas as pd
from stable_baselines3 import PPO
from stable_baselines3.common.callbacks import BaseCallback

# --- Import our custom environment from the 'environment' directory ---
try:
    # This allows the script to find the 'environment' module
    current_dir = os.path.dirname(os.path.abspath(__file__))
    src_dir = os.path.dirname(current_dir)
    sys.path.append(src_dir)
    from environment.security_env import SecurityEnv
except ImportError as e:
    print(f"CRITICAL ERROR: Could not import the SecurityEnv class. Details: {e}")
    print("Please ensure your project structure is correct and you have __init__.py files.")
    sys.exit(1)

# --- The custom callback to feed our offline data into the training loop ---
class SimulationCallback(BaseCallback):
    """
    A stable-baselines3 callback that hooks into the training process.
    Before the agent collects a new batch of experiences (a "rollout"),
    this callback will randomly select an event from our historical data
    and set it as the current state of the environment.
    """
    def __init__(self, simulation_df, verbose=0):
        super(SimulationCallback, self).__init__(verbose)
        self.simulation_df = simulation_df

    def _on_rollout_start(self) -> None:
        """
        This method is called automatically by the `agent.learn()` process
        at the beginning of each new rollout.
        """
        # 1. Sample a random event from our historical dataset
        sample_event = self.simulation_df.sample(1).iloc[0].to_dict()
        
        # 2. Use the environment's `set_current_analysis` method to inject
        #    this event as the current situation the agent must face.
        # `env_method` is a tool from stable-baselines3 to call methods on the underlying env.
        self.training_env.env_method("set_current_analysis", sample_event)

    def _on_step(self) -> bool:
        """
        This method is called after each step in the environment.
        Returning True ensures that training continues.
        """
        return True

# --- Configuration ---
# Point this to the .jsonl file you want to use for training the agent.
# Using a large, diverse file like UNSW is a good starting point.
TRAINING_DATA_PATH = "/home/tejas/Projects/AIS/data/UNSW_finetuning.jsonl"
MODEL_SAVE_PATH = "./ais_rl_agent_ppo.zip"
TOTAL_TRAINING_STEPS = 25000 # Increase this for a more thoroughly trained agent (e.g., 50000)

# --- Main Training Script ---
if __name__ == "__main__":
    print("--- Starting Offline RL Agent Training ---")

    # 1. Load the simulation data from our knowledge base
    print(f"Loading simulation data from: {TRAINING_DATA_PATH}")
    if not os.path.exists(TRAINING_DATA_PATH):
        print(f"CRITICAL ERROR: Training data not found at '{TRAINING_DATA_PATH}'.")
        sys.exit(1)
        
    all_events = []
    with open(TRAINING_DATA_PATH, 'r') as f:
        for line in f:
            try:
                # The 'assistant' message contains the structured JSON with our labels
                data = json.loads(line)
                json_analysis_str = data['messages'][2]['content']
                all_events.append(json.loads(json_analysis_str))
            except (json.JSONDecodeError, IndexError, KeyError):
                # Safely skip any malformed lines in the knowledge base
                continue
    
    simulation_df = pd.DataFrame(all_events)
    print(f"Loaded {len(simulation_df)} events for training simulation.")

    # 2. Initialize the environment and our custom callback
    env = SecurityEnv()
    simulation_callback = SimulationCallback(simulation_df)

    # 3. Initialize the PPO Agent
    # We explicitly set `device='cpu'` as it's more efficient for this simple MLP model.
    agent = PPO(
        "MlpPolicy",
        env,
        verbose=1, # Set to 1 to see training progress
        device="cpu",
        n_steps=2048, # The number of steps to run for each environment before updating the policy
    )

    # 4. Start the training process
    # The `agent.learn()` method will now run its standard training loop,
    # and our `SimulationCallback` will ensure it's learning from our specific dataset.
    print(f"\nStarting training for {TOTAL_TRAINING_STEPS} steps...")
    agent.learn(
        total_timesteps=TOTAL_TRAINING_STEPS,
        callback=simulation_callback
    )

    # 5. Save the final, trained agent
    agent.save(MODEL_SAVE_PATH)
    print(f"\nTraining complete. Agent saved to '{MODEL_SAVE_PATH}'")