#!/usr/bin/env python3
"""
CRITICAL: Retrain the RL agent with CORRECTED threat types.
The old agent was trained with misclassified threats. This script fixes that.
"""

import sys
import os
import json
import pandas as pd
from stable_baselines3 import PPO
from stable_baselines3.common.callbacks import BaseCallback
import numpy as np
import traceback

try:
    current_dir = os.path.dirname(os.path.abspath(__file__))
    src_dir = os.path.dirname(current_dir)
    sys.path.append(src_dir)
    from environment.security_env import SecurityEnv
except ImportError as e:
    print(f"CRITICAL ERROR: Could not import SecurityEnv. {e}")
    traceback.print_exc()
    sys.exit(1)


def normalize_threat_type(threat_description):
    """
    Converts threat descriptions to standardized types.
    MATCHES the normalization in threat_analyzer.py exactly.
    """
    threat_lower = str(threat_description or '').lower()
    
    # Map raw threat types from training data to standardized types
    if any(word in threat_lower for word in ['legitimate', 'benign', 'normal', 'standard', 'accepted', 'allowed']):
        return "Normal"
    elif any(word in threat_lower for word in ['informational', 'info', 'notification']):
        return "Normal"
    elif any(word in threat_lower for word in ['brute', 'force', 'password', 'credential', 'repeated', 'attempt']):
        return "Brute Force Attack"
    elif any(word in threat_lower for word in ['sql', 'injection']):
        return "SQL Injection"
    elif any(word in threat_lower for word in ['command', 'injection', 'shell']):
        return "Command Injection"
    elif any(word in threat_lower for word in ['dos', 'ddos', 'flood']):
        return "DoS"
    elif any(word in threat_lower for word in ['exploit', 'cve']):
        return "Exploit"
    elif any(word in threat_lower for word in ['scan', 'reconnaissance', 'probe']):
        return "Reconnaissance"
    elif any(word in threat_lower for word in ['worm', 'malware']):
        return "Worms"
    elif any(word in threat_lower for word in ['backdoor']):
        return "Backdoors"
    elif any(word in threat_lower for word in ['shellcode', 'payload']):
        return "Shellcode"
    elif any(word in threat_lower for word in ['suspicious', 'process']):
        return "Suspicious Process Creation"
    else:
        return "Normal"


def normalize_risk_level(risk_description):
    """Converts risk descriptions to standardized levels."""
    risk_lower = str(risk_description or '').lower()
    
    if any(word in risk_lower for word in ['critical', 'severe']):
        return "Critical"
    elif any(word in risk_lower for word in ['high', 'significant']):
        return "High"
    elif any(word in risk_lower for word in ['medium', 'moderate']):
        return "Medium"
    elif any(word in risk_lower for word in ['low', 'minor', 'negligible', 'informational']):
        return "Low"
    else:
        return "N/A"


def compute_is_attack(threat_type):
    """Determines if an event is an attack."""
    benign_threats = ['Normal', 'Legitimate Activity', 'Informational', 'N/A', None]
    return threat_type not in benign_threats


class SimulationCallback(BaseCallback):
    """Feeds training data into the learning loop."""
    def __init__(self, simulation_df, verbose=0):
        super(SimulationCallback, self).__init__(verbose)
        self.simulation_df = simulation_df
        self.rollout_count = 0

    def _on_rollout_start(self) -> None:
        sample_event = self.simulation_df.sample(1).iloc[0].to_dict()
        self.rollout_count += 1
        
        if self.rollout_count % 500 == 0:
            threat = sample_event.get('threat_type', 'Unknown')
            risk = sample_event.get('risk_level', 'Unknown')
            is_attack = sample_event.get('is_attack', False)
            print(f"[ROLLOUT {self.rollout_count}] Threat: {threat}, Risk: {risk}, Attack: {is_attack}")
        
        self.training_env.env_method("set_current_analysis", sample_event)

    def _on_step(self) -> bool:
        return True


if __name__ == "__main__":
    print("=" * 80)
    print("RETRAINING RL AGENT WITH CORRECTED THREAT CLASSIFICATION")
    print("=" * 80)

    TRAINING_DATA_PATH = "/home/tejas/Projects/AIS/data/UNSW_finetuning.jsonl"
    MODEL_SAVE_PATH = "/home/tejas/Projects/AIS/ais_rl_agent_ppo.zip"
    TOTAL_TRAINING_STEPS = 200000  # Increased for better training

    print(f"\n[STEP 1] Loading training data from: {TRAINING_DATA_PATH}")
    if not os.path.exists(TRAINING_DATA_PATH):
        print(f"ERROR: Training data not found.")
        sys.exit(1)
        
    all_events = []
    malformed_count = 0
    
    with open(TRAINING_DATA_PATH, 'r') as f:
        for line_num, line in enumerate(f, 1):
            try:
                data = json.loads(line)
                json_analysis_str = data['messages'][2]['content']
                analysis = json.loads(json_analysis_str)
                
                # --- CRITICAL: Normalize threat types ---
                raw_threat = analysis.get('threat_type', 'Normal')
                raw_risk = analysis.get('risk_level', 'Low')
                
                analysis['threat_type'] = normalize_threat_type(raw_threat)
                analysis['risk_level'] = normalize_risk_level(raw_risk)
                analysis['is_attack'] = compute_is_attack(analysis['threat_type'])
                
                all_events.append(analysis)
            except (json.JSONDecodeError, IndexError, KeyError, TypeError):
                malformed_count += 1
                continue
    
    simulation_df = pd.DataFrame(all_events)
    print(f"  ✓ Loaded {len(simulation_df)} events")
    print(f"  ✓ Skipped {malformed_count} malformed lines")
    
    print("\n[STEP 2] Corrected Threat Distribution")
    print(f"  Total events: {len(simulation_df)}")
    
    attacks = simulation_df['is_attack'].sum()
    normal = len(simulation_df) - attacks
    print(f"  Attack events: {attacks} ({100*attacks/len(simulation_df):.1f}%)")
    print(f"  Normal events: {normal} ({100*normal/len(simulation_df):.1f}%)")
    
    print("\n  Threat Type Distribution (Top 10):")
    for threat, count in simulation_df['threat_type'].value_counts().head(10).items():
        attack_pct = 100 * simulation_df[simulation_df['threat_type'] == threat]['is_attack'].sum() / count
        print(f"    {threat}: {count} ({attack_pct:.1f}% attacks)")
    
    print("\n  Risk Level Distribution:")
    for risk, count in simulation_df['risk_level'].value_counts().items():
        print(f"    {risk}: {count}")

    print("\n[STEP 3] Initializing Environment & Agent")
    env = SecurityEnv()
    callback = SimulationCallback(simulation_df)
    
    agent = PPO(
        "MlpPolicy",
        env,
        verbose=1,
        device="cpu",
        n_steps=2048,
        learning_rate=3e-4,
        n_epochs=20,
        batch_size=64,
        ent_coef=0.01,
    )

    print("\n" + "=" * 80)
    print(f"[STEP 4] Training for {TOTAL_TRAINING_STEPS} steps...")
    print("=" * 80 + "\n")
    
    try:
        agent.learn(
            total_timesteps=TOTAL_TRAINING_STEPS,
            callback=callback,
            progress_bar=True
        )
    except KeyboardInterrupt:
        print("\nTraining interrupted.")
    except Exception as e:
        print(f"Error: {e}")
        traceback.print_exc()

    print("\n" + "=" * 80)
    agent.save(MODEL_SAVE_PATH)
    print(f"✓ Agent saved to: {MODEL_SAVE_PATH}")
    print("=" * 80)
    
    # Validation tests
    print("\n[STEP 5] Validation Tests")
    print("-" * 80)
    
    test_cases = [
        {
            "name": "Legitimate Activity (Normal)",
            "analysis": {"threat_type": "Normal", "risk_level": "N/A", "is_attack": False},
            "expected": 0,  # Do Nothing
        },
        {
            "name": "Brute Force Attack (High Risk)",
            "analysis": {"threat_type": "Brute Force Attack", "risk_level": "High", "is_attack": True},
            "expected": 2,  # Block IP
        },
        {
            "name": "Critical SQL Injection",
            "analysis": {"threat_type": "SQL Injection", "risk_level": "Critical", "is_attack": True},
            "expected": 2,  # Block IP
        },
    ]
    
    action_names = {0: "Do Nothing", 1: "Monitor", 2: "Block IP"}
    passed = 0
    
    for test in test_cases:
        env.set_current_analysis(test['analysis'])
        obs, _ = env.reset()
        action, _ = agent.predict(obs, deterministic=True)
        action_int = int(action)
        expected_name = action_names[test['expected']]
        actual_name = action_names[action_int]
        
        status = "✓" if action_int == test['expected'] else "✗"
        print(f"{status} {test['name']}")
        print(f"  Expected: {expected_name}, Got: {actual_name}")
        
        if action_int == test['expected']:
            passed += 1
    
    print("-" * 80)
    print(f"Validation: {passed}/3 passed")
    print("\n✓ Retrain complete! The agent should now correctly classify threats.")
    print("  Run threat_analyzer.py to test the full pipeline.")