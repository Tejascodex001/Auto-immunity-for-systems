"""
Debug script to understand why reward function tests are failing.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from environment.security_env import SecurityEnv

env = SecurityEnv()
action_names = {0: "Do Nothing", 1: "Monitor", 2: "Block IP"}

# Test Case 1: CRITICAL BRUTE FORCE - Should prefer action 2 (Block IP)
print("\n" + "=" * 80)
print("TEST CASE 1: CRITICAL BRUTE FORCE ATTACK")
print("=" * 80)

analysis = {
    "threat_type": "Brute Force Attack",
    "risk_level": "Critical",
    "is_attack": True,
}

env.set_current_analysis(analysis)
obs, _ = env.reset()

print(f"\nAnalysis: {analysis}")
print(f"Observation: {obs}")
print(f"Threat map lookup for 'Brute Force Attack': {env.threat_map.get('Brute Force Attack', 'NOT FOUND')}")
print(f"Risk map lookup for 'Critical': {env.risk_map.get('Critical', 'NOT FOUND')}")

print("\nExpected rewards (is_attack=True, risk_level='critical'):")
print("  Action 0 (Do Nothing): -100")
print("  Action 1 (Monitor): +5")
print("  Action 2 (Block IP): +100 (because risk_level == 'critical')")

print("\nActual rewards:")
rewards = {}
for action in [0, 1, 2]:
    _, reward, _, _, _ = env.step(action)
    rewards[action] = reward
    print(f"  Action {action} ({action_names[action]}): {reward:+6.0f}")

best_action = max(rewards, key=rewards.get)
print(f"\nBest action: {best_action} ({action_names[best_action]}) with reward {rewards[best_action]}")
print(f"Expected best action: 2 (Block IP)")
print(f"RESULT: {'✓ PASS' if best_action == 2 else '✗ FAIL'}")

# Test Case 2: NORMAL LOGIN - Should prefer action 0 (Do Nothing)
print("\n" + "=" * 80)
print("TEST CASE 2: LEGITIMATE USER LOGIN")
print("=" * 80)

analysis = {
    "threat_type": "Normal",
    "risk_level": "N/A",
    "is_attack": False,
}

env.set_current_analysis(analysis)
obs, _ = env.reset()

print(f"\nAnalysis: {analysis}")
print(f"Observation: {obs}")

print("\nExpected rewards (is_attack=False):")
print("  Action 0 (Do Nothing): +20")
print("  Action 1 (Monitor): -5")
print("  Action 2 (Block IP): -200")

print("\nActual rewards:")
rewards = {}
for action in [0, 1, 2]:
    _, reward, _, _, _ = env.step(action)
    rewards[action] = reward
    print(f"  Action {action} ({action_names[action]}): {reward:+6.0f}")

best_action = max(rewards, key=rewards.get)
print(f"\nBest action: {best_action} ({action_names[best_action]}) with reward {rewards[best_action]}")
print(f"Expected best action: 0 (Do Nothing)")
print(f"RESULT: {'✓ PASS' if best_action == 0 else '✗ FAIL'}")

# Check the env.step code
print("\n" + "=" * 80)
print("DEBUGGING: SecurityEnv.step() logic")
print("=" * 80)

print("\nLet's trace through the step function for Critical Brute Force:")
analysis = {
    "threat_type": "Brute Force Attack",
    "risk_level": "Critical",
    "is_attack": True,
}

env.set_current_analysis(analysis)
env.reset()

is_attack = env.current_analysis.get('is_attack', False)
risk_level = str(env.current_analysis.get('risk_level', 'Low')).lower()

print(f"  is_attack = {is_attack}")
print(f"  risk_level = '{risk_level}'")
print(f"  is_attack is True: {is_attack is True}")
print(f"  risk_level == 'critical': {risk_level == 'critical'}")

print("\nStep through logic:")
if is_attack:
    print("  if is_attack: [TRUE]")
    action = 2
    if action == 0:
        print("    if action == 0: [FALSE]")
    elif action == 1:
        print("    elif action == 1: [FALSE]")
    elif action == 2:
        print("    elif action == 2: [TRUE]")
        if risk_level == 'critical':
            print(f"      if risk_level == 'critical': [TRUE] → reward = 100")
        elif risk_level == 'high':
            print(f"      elif risk_level == 'high': [FALSE]")
        else:
            print(f"      else: [FALSE]")