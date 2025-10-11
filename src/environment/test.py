"""
Complete testing and debugging script for the RL Security Environment.
Run this BEFORE training to verify everything is working correctly.
"""

import sys
import os
import json
import numpy as np
import traceback

try:
    current_dir = os.path.dirname(os.path.abspath(__file__))
    src_dir = os.path.dirname(current_dir)
    sys.path.append(src_dir)
    from environment.security_env import SecurityEnv
except ImportError as e:
    print(f"ERROR: Could not import SecurityEnv. {e}")
    traceback.print_exc()
    sys.exit(1)


def test_reward_function():
    """Test the reward function with various realistic scenarios."""
    print("\n" + "=" * 80)
    print("TEST 1: REWARD FUNCTION VALIDATION")
    print("=" * 80)
    
    env = SecurityEnv()
    action_names = {0: "Do Nothing", 1: "Monitor", 2: "Block IP"}
    
    test_cases = [
        {
            "name": "CRITICAL BRUTE FORCE ATTACK",
            "analysis": {
                "threat_type": "Brute Force Attack",
                "risk_level": "Critical",
                "is_attack": True,
            },
            "best_action": 2,
            "reasoning": "Critical attacks should be blocked"
        },
        {
            "name": "HIGH RISK SQL INJECTION",
            "analysis": {
                "threat_type": "SQL Injection",
                "risk_level": "High",
                "is_attack": True,
            },
            "best_action": 2,
            "reasoning": "High-risk attacks should be blocked"
        },
        {
            "name": "MEDIUM RISK RECONNAISSANCE",
            "analysis": {
                "threat_type": "Reconnaissance",
                "risk_level": "Medium",
                "is_attack": True,
            },
            "best_action": 1,
            "reasoning": "Medium-risk should be monitored or blocked (both better than do nothing)"
        },
        {
            "name": "LEGITIMATE USER LOGIN",
            "analysis": {
                "threat_type": "Normal",
                "risk_level": "N/A",
                "is_attack": False,
            },
            "best_action": 0,
            "reasoning": "Normal login should do nothing"
        },
        {
            "name": "SYSTEM INFORMATIONAL EVENT",
            "analysis": {
                "threat_type": "Informational",
                "risk_level": "Low",
                "is_attack": False,
            },
            "best_action": 0,
            "reasoning": "Informational events should do nothing"
        },
    ]
    
    passed = 0
    failed = 0
    
    for i, test in enumerate(test_cases, 1):
        print(f"\n[Test {i}] {test['name']}")
        print(f"  Threat: {test['analysis']['threat_type']}")
        print(f"  Risk: {test['analysis']['risk_level']}")
        print(f"  Is Attack: {test['analysis']['is_attack']}")
        print(f"  Reasoning: {test['reasoning']}")
        
        # Create a fresh environment for each test
        env = SecurityEnv()
        env.set_current_analysis(test['analysis'])
        obs, _ = env.reset()
        
        print(f"  Observation: {obs}")
        
        # Test all three actions
        rewards = {}
        best_action = None
        best_reward = -float('inf')
        
        print("  Action Rewards:")
        for action in [0, 1, 2]:
            # CRITICAL: Reset the environment before each action test
            obs_before_step, _ = env.reset()
            next_obs, reward, terminated, truncated, info = env.step(action)
            rewards[action] = reward
            marker = "→" if action == test['best_action'] else " "
            print(f"    {marker} Action {action} ({action_names[action]:12s}): {reward:+6.0f}")
            
            if reward > best_reward:
                best_reward = reward
                best_action = action
        
        expected_best = test['best_action']
        
        # For medium risk attacks, either monitor (1) or block (2) is acceptable
        if test['name'] == "MEDIUM RISK RECONNAISSANCE":
            if best_action in [1, 2]:
                print(f"  ✓ PASS - Chose {action_names[best_action]} (acceptable for medium risk)")
                passed += 1
            else:
                print(f"  ✗ FAIL - Chose {action_names[best_action]}, expected Monitor or Block")
                failed += 1
        else:
            if best_action == expected_best:
                print(f"  ✓ PASS - Correctly chose {action_names[best_action]}")
                passed += 1
            else:
                print(f"  ✗ FAIL - Chose {action_names[best_action]}, expected {action_names[expected_best]}")
                print(f"    Reward breakdown: {rewards}")
                failed += 1
    
    print("\n" + "-" * 80)
    print(f"RESULT: {passed} passed, {failed} failed")
    return failed == 0


def test_observation_mapping():
    """Test that threat and risk levels map correctly to observation vectors."""
    print("\n" + "=" * 80)
    print("TEST 2: OBSERVATION SPACE MAPPING")
    print("=" * 80)
    
    env = SecurityEnv()
    
    test_mappings = [
        {
            "threat_type": "Normal",
            "risk_level": "N/A",
            "expected_threat_id": 0,
            "expected_risk_id": 0,
        },
        {
            "threat_type": "Brute Force Attack",
            "risk_level": "High",
            "expected_threat_id": 2,
            "expected_risk_id": 2,
        },
        {
            "threat_type": "SQL Injection",
            "risk_level": "Critical",
            "expected_threat_id": 3,
            "expected_risk_id": 3,
        },
        {
            "threat_type": "Reconnaissance",
            "risk_level": "Medium",
            "expected_threat_id": 1,
            "expected_risk_id": 1,
        },
        {
            "threat_type": "DoS",
            "risk_level": "High",
            "expected_threat_id": 5,
            "expected_risk_id": 2,
        },
    ]
    
    passed = 0
    failed = 0
    
    for i, mapping in enumerate(test_mappings, 1):
        analysis = {
            "threat_type": mapping["threat_type"],
            "risk_level": mapping["risk_level"],
            "is_attack": True
        }
        obs = env.get_obs_from_analysis(analysis)
        
        expected = np.array([mapping["expected_threat_id"], mapping["expected_risk_id"]], dtype=np.float32)
        match = np.allclose(obs, expected)
        
        status = "✓" if match else "✗"
        print(f"{status} {mapping['threat_type']:25s} / {mapping['risk_level']:10s} → {obs}")
        
        if match:
            passed += 1
        else:
            print(f"  Expected: {expected}, Got: {obs}")
            failed += 1
    
    print(f"\nRESULT: {passed} passed, {failed} failed")
    return failed == 0


def test_environment_consistency():
    """Test that the environment behaves consistently."""
    print("\n" + "=" * 80)
    print("TEST 3: ENVIRONMENT CONSISTENCY")
    print("=" * 80)
    
    env = SecurityEnv()
    
    # Test 1: Multiple resets with same analysis should give same observation
    print("\n[Consistency Test 1] Multiple resets with same analysis")
    analysis = {
        "threat_type": "Brute Force Attack",
        "risk_level": "High",
        "is_attack": True,
    }
    env.set_current_analysis(analysis)
    
    obs_list = []
    for i in range(5):
        obs, _ = env.reset()
        obs_list.append(obs)
    
    all_same = all(np.allclose(obs_list[0], obs) for obs in obs_list)
    print(f"  Observations: {[list(o) for o in obs_list]}")
    if all_same:
        print(f"  ✓ PASS - All observations identical")
    else:
        print(f"  ✗ FAIL - Observations differ")
        return False
    
    # Test 2: Step should work without errors
    print("\n[Consistency Test 2] Step function works for all actions")
    try:
        for action in [0, 1, 2]:
            obs, reward, terminated, truncated, info = env.step(action)
            print(f"  Action {action}: reward={reward:+6.0f}, terminated={terminated}")
        print(f"  ✓ PASS - All steps executed successfully")
    except Exception as e:
        print(f"  ✗ FAIL - Error during step: {e}")
        traceback.print_exc()
        return False
    
    return True


def test_is_attack_field():
    """Test that is_attack field is properly recognized."""
    print("\n" + "=" * 80)
    print("TEST 4: IS_ATTACK FIELD RECOGNITION")
    print("=" * 80)
    
    env = SecurityEnv()
    
    test_cases = [
        {
            "analysis": {"threat_type": "Normal", "risk_level": "N/A", "is_attack": False},
            "expected_is_attack": False,
        },
        {
            "analysis": {"threat_type": "Brute Force Attack", "risk_level": "High", "is_attack": True},
            "expected_is_attack": True,
        },
    ]
    
    passed = 0
    failed = 0
    
    for test in test_cases:
        analysis = test["analysis"]
        env.set_current_analysis(analysis)
        
        retrieved_is_attack = env.current_analysis.get('is_attack', False)
        expected = test["expected_is_attack"]
        
        if retrieved_is_attack == expected:
            print(f"  ✓ {analysis['threat_type']}: is_attack={retrieved_is_attack}")
            passed += 1
        else:
            print(f"  ✗ {analysis['threat_type']}: got is_attack={retrieved_is_attack}, expected {expected}")
            failed += 1
    
    print(f"\nRESULT: {passed} passed, {failed} failed")
    return failed == 0


def main():
    """Run all tests."""
    print("\n" + "=" * 80)
    print("SECURITY ENVIRONMENT TEST SUITE")
    print("=" * 80)
    
    results = {
        "Is_Attack Field": test_is_attack_field(),
        "Observation Mapping": test_observation_mapping(),
        "Environment Consistency": test_environment_consistency(),
        "Reward Function": test_reward_function(),
    }
    
    print("\n" + "=" * 80)
    print("FINAL TEST SUMMARY")
    print("=" * 80)
    for test_name, passed in results.items():
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"{status} - {test_name}")
    
    all_passed = all(results.values())
    print("\n" + "=" * 80)
    if all_passed:
        print("✓ ALL TESTS PASSED - Environment is ready for training!")
        print("\nNext steps:")
        print("  1. Run: python scripts/train_rl_agent.py")
        print("  2. Wait for training to complete (~5-10 minutes)")
        print("  3. Run: python scripts/main.py")
    else:
        print("✗ SOME TESTS FAILED - Fix issues before training")
    print("=" * 80 + "\n")
    
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())