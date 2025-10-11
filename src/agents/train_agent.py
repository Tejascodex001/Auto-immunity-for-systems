#!/usr/bin/env python3
"""
Enhanced RL Agent Retraining Script with Improved Threat Classification
- Better error handling and validation
- Comprehensive logging and metrics
- Normalized threat types matching SecurityEnv
- Data quality checks
- Training progress monitoring
"""

import sys
import os
import json
import pandas as pd
import numpy as np
import traceback
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from pathlib import Path

from stable_baselines3 import PPO
from stable_baselines3.common.callbacks import BaseCallback, CallbackList
from stable_baselines3.common.vec_env import DummyVecEnv
from stable_baselines3.common.evaluation import evaluate_policy

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

try:
    current_dir = os.path.dirname(os.path.abspath(__file__))
    src_dir = os.path.dirname(current_dir)
    sys.path.append(src_dir)
    from environment.security_env import SecurityEnv
except ImportError as e:
    logger.critical(f"Could not import SecurityEnv: {e}")
    traceback.print_exc()
    sys.exit(1)


class ThreatNormalizer:
    """Handles threat type and risk level normalization."""
    
    # Benign threat types
    BENIGN_THREATS = {'Normal', 'Legitimate Activity', 'Informational', 
                     'N/A', 'Legitimate Login'}
    
    # Threat type mappings
    THREAT_PATTERNS = {
        'Normal': ['legitimate', 'benign', 'normal', 'standard', 'accepted', 
                  'allowed', 'informational', 'info', 'notification'],
        'Brute Force Attack': ['brute', 'force', 'password', 'credential', 
                              'repeated', 'attempt', 'failed login'],
        'SQL Injection': ['sql', 'injection', 'query'],
        'Command Injection': ['command', 'injection', 'shell', 'os command'],
        'DoS': ['dos', 'ddos', 'flood', 'denial'],
        'Exploit': ['exploit', 'cve', 'vulnerability', 'zero-day'],
        'Reconnaissance': ['scan', 'reconnaissance', 'probe', 'enum', 'port scan'],
        'Worms': ['worm', 'malware', 'virus', 'self-propagating'],
        'Backdoors': ['backdoor', 'persistence', 'rootkit'],
        'Shellcode': ['shellcode', 'payload', 'code execution'],
        'Suspicious Process Creation': ['suspicious', 'process', 'execution', 
                                        'unauthorized'],
    }
    
    # Risk level mappings
    RISK_PATTERNS = {
        'Critical': ['critical', 'severe'],
        'High': ['high', 'significant'],
        'Medium': ['medium', 'moderate', 'mid'],
        'Low': ['low', 'minor', 'negligible', 'informational'],
    }
    
    @classmethod
    def normalize_threat_type(cls, threat_description: str, 
                              log_entry: str = "") -> str:
        """
        Normalize threat type to standardized categories.
        
        Args:
            threat_description: Raw threat description
            log_entry: Log entry for additional context
            
        Returns:
            Normalized threat type
        """
        threat_lower = str(threat_description or '').lower()
        log_lower = str(log_entry or '').lower()
        
        # Check for success indicators in log
        if 'successfully' in log_lower or 'login success' in log_lower:
            if not any(word in log_lower for word in ['failed', 'fail', 'incorrect']):
                return 'Normal'
        
        # Match against threat patterns
        for threat_type, patterns in cls.THREAT_PATTERNS.items():
            if any(pattern in threat_lower for pattern in patterns):
                return threat_type
        
        return 'Normal'
    
    @classmethod
    def normalize_risk_level(cls, risk_description: str) -> str:
        """
        Normalize risk level to standardized categories.
        
        Args:
            risk_description: Raw risk description
            
        Returns:
            Normalized risk level
        """
        risk_lower = str(risk_description or '').lower()
        
        for risk_level, patterns in cls.RISK_PATTERNS.items():
            if any(pattern in risk_lower for pattern in patterns):
                return risk_level
        
        return 'N/A'
    
    @classmethod
    def compute_is_attack(cls, threat_type: str) -> bool:
        """
        Determine if event is an attack.
        
        Args:
            threat_type: Normalized threat type
            
        Returns:
            True if attack, False otherwise
        """
        return threat_type not in cls.BENIGN_THREATS


class DataValidator:
    """Validates training data quality."""
    
    @staticmethod
    def validate_event(event: Dict) -> Tuple[bool, Optional[str]]:
        """
        Validate a single event.
        
        Args:
            event: Event dictionary
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        required_fields = ['threat_type', 'risk_level', 'is_attack']
        
        for field in required_fields:
            if field not in event:
                return False, f"Missing required field: {field}"
        
        if not isinstance(event['is_attack'], bool):
            return False, "is_attack must be boolean"
        
        return True, None
    
    @staticmethod
    def analyze_dataset(df: pd.DataFrame) -> Dict:
        """
        Analyze dataset quality and distribution.
        
        Args:
            df: Training dataset
            
        Returns:
            Dictionary with analysis metrics
        """
        total = len(df)
        attacks = df['is_attack'].sum()
        normal = total - attacks
        
        analysis = {
            'total_events': total,
            'attack_events': int(attacks),
            'normal_events': int(normal),
            'attack_ratio': float(attacks / total) if total > 0 else 0,
            'threat_distribution': df['threat_type'].value_counts().to_dict(),
            'risk_distribution': df['risk_level'].value_counts().to_dict(),
        }
        
        return analysis


class TrainingCallback(BaseCallback):
    """Enhanced callback with better logging and metrics."""
    
    def __init__(self, simulation_df: pd.DataFrame, log_frequency: int = 500, 
                 verbose: int = 0):
        super(TrainingCallback, self).__init__(verbose)
        self.simulation_df = simulation_df
        self.log_frequency = log_frequency
        self.rollout_count = 0
        self.episode_rewards = []
        self.action_counts = {i: 0 for i in range(5)}
    
    def _on_rollout_start(self) -> None:
        """Sample event for training episode."""
        sample_event = self.simulation_df.sample(1).iloc[0].to_dict()
        self.rollout_count += 1
        
        if self.rollout_count % self.log_frequency == 0:
            threat = sample_event.get('threat_type', 'Unknown')
            risk = sample_event.get('risk_level', 'Unknown')
            is_attack = sample_event.get('is_attack', False)
            
            logger.info(f"Rollout {self.rollout_count}: Threat={threat}, "
                       f"Risk={risk}, Attack={is_attack}")
            
            # Log action distribution
            total_actions = sum(self.action_counts.values())
            if total_actions > 0:
                logger.info("Action distribution:")
                for action, count in self.action_counts.items():
                    pct = 100 * count / total_actions
                    logger.info(f"  Action {action}: {count} ({pct:.1f}%)")
        
        self.training_env.env_method("set_current_analysis", sample_event)
    
    def _on_step(self) -> bool:
        """Track actions taken."""
        if len(self.locals.get('actions', [])) > 0:
            action = int(self.locals['actions'][0])
            self.action_counts[action] += 1
        
        return True


class ModelTrainer:
    """Handles model training and evaluation."""
    
    def __init__(self, training_data_path: str, model_save_path: str,
                 total_steps: int = 200000):
        self.training_data_path = Path(training_data_path)
        self.model_save_path = Path(model_save_path)
        self.total_steps = total_steps
        self.env = None
        self.agent = None
        self.training_df = None
    
    def load_and_prepare_data(self) -> pd.DataFrame:
        """Load and prepare training data."""
        logger.info(f"Loading training data from: {self.training_data_path}")
        
        if not self.training_data_path.exists():
            raise FileNotFoundError(f"Training data not found: {self.training_data_path}")
        
        all_events = []
        malformed_count = 0
        
        with open(self.training_data_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                try:
                    data = json.loads(line)
                    json_analysis_str = data['messages'][2]['content']
                    analysis = json.loads(json_analysis_str)
                    
                    # Normalize threat types
                    raw_threat = analysis.get('threat_type', 'Normal')
                    raw_risk = analysis.get('risk_level', 'Low')
                    
                    analysis['threat_type'] = ThreatNormalizer.normalize_threat_type(
                        raw_threat
                    )
                    analysis['risk_level'] = ThreatNormalizer.normalize_risk_level(
                        raw_risk
                    )
                    analysis['is_attack'] = ThreatNormalizer.compute_is_attack(
                        analysis['threat_type']
                    )
                    
                    # Validate event
                    is_valid, error = DataValidator.validate_event(analysis)
                    if is_valid:
                        all_events.append(analysis)
                    else:
                        logger.warning(f"Line {line_num}: {error}")
                        malformed_count += 1
                        
                except (json.JSONDecodeError, IndexError, KeyError, TypeError) as e:
                    malformed_count += 1
                    if line_num % 1000 == 0:
                        logger.warning(f"Parsing error at line {line_num}: {e}")
                    continue
        
        df = pd.DataFrame(all_events)
        logger.info(f"Loaded {len(df)} valid events")
        logger.info(f"Skipped {malformed_count} malformed lines")
        
        return df
    
    def print_data_analysis(self, df: pd.DataFrame) -> None:
        """Print comprehensive data analysis."""
        analysis = DataValidator.analyze_dataset(df)
        
        logger.info("\n" + "=" * 80)
        logger.info("TRAINING DATA ANALYSIS")
        logger.info("=" * 80)
        logger.info(f"Total events: {analysis['total_events']}")
        logger.info(f"Attack events: {analysis['attack_events']} "
                   f"({100*analysis['attack_ratio']:.1f}%)")
        logger.info(f"Normal events: {analysis['normal_events']} "
                   f"({100*(1-analysis['attack_ratio']):.1f}%)")
        
        logger.info("\nThreat Type Distribution (Top 10):")
        threat_dist = sorted(analysis['threat_distribution'].items(), 
                            key=lambda x: x[1], reverse=True)[:10]
        for threat, count in threat_dist:
            threat_df = df[df['threat_type'] == threat]
            attack_pct = 100 * threat_df['is_attack'].sum() / len(threat_df)
            logger.info(f"  {threat}: {count} ({attack_pct:.1f}% attacks)")
        
        logger.info("\nRisk Level Distribution:")
        for risk, count in sorted(analysis['risk_distribution'].items(), 
                                  key=lambda x: x[1], reverse=True):
            logger.info(f"  {risk}: {count}")
        
        logger.info("=" * 80 + "\n")
    
    def initialize_environment(self) -> SecurityEnv:
        """Initialize training environment."""
        logger.info("Initializing SecurityEnv...")
        return SecurityEnv()
    
    def create_agent(self, env: SecurityEnv) -> PPO:
        """Create PPO agent with optimized hyperparameters."""
        logger.info("Creating PPO agent...")
        
        agent = PPO(
            policy="MlpPolicy",
            env=env,
            verbose=1,
            device="cpu",
            n_steps=2048,
            learning_rate=3e-4,
            n_epochs=20,
            batch_size=64,
            ent_coef=0.01,
            gamma=0.99,
            gae_lambda=0.95,
            clip_range=0.2,
        )
        
        return agent
    
    def train(self) -> None:
        """Execute full training pipeline."""
        try:
            # Load and prepare data
            self.training_df = self.load_and_prepare_data()
            self.print_data_analysis(self.training_df)
            
            # Initialize environment and agent
            self.env = self.initialize_environment()
            callback = TrainingCallback(self.training_df, log_frequency=500)
            self.agent = self.create_agent(self.env)
            
            # Train
            logger.info("\n" + "=" * 80)
            logger.info(f"STARTING TRAINING: {self.total_steps} steps")
            logger.info("=" * 80 + "\n")
            
            start_time = datetime.now()
            
            self.agent.learn(
                total_timesteps=self.total_steps,
                callback=callback,
                progress_bar=True
            )
            
            training_time = (datetime.now() - start_time).total_seconds()
            logger.info(f"\nTraining completed in {training_time:.2f} seconds")
            
            # Save model
            self.agent.save(str(self.model_save_path))
            logger.info(f"Model saved to: {self.model_save_path}")
            
        except KeyboardInterrupt:
            logger.warning("Training interrupted by user")
        except Exception as e:
            logger.error(f"Training error: {e}")
            traceback.print_exc()
            raise
    
    def validate(self) -> None:
        """Run validation tests on trained model."""
        if self.agent is None or self.env is None:
            logger.error("Cannot validate: agent or environment not initialized")
            return
        
        logger.info("\n" + "=" * 80)
        logger.info("VALIDATION TESTS")
        logger.info("=" * 80)
        
        test_cases = [
            {
                "name": "Normal Traffic (Legitimate Login)",
                "analysis": {
                    "threat_type": "Normal",
                    "risk_level": "N/A",
                    "is_attack": False,
                    "source_ip": "192.168.1.100"
                },
                "expected": SecurityEnv.ACTION_DO_NOTHING,
            },
            {
                "name": "Brute Force Attack (High Risk)",
                "analysis": {
                    "threat_type": "Brute Force Attack",
                    "risk_level": "High",
                    "is_attack": True,
                    "source_ip": "10.0.0.50"
                },
                "expected": SecurityEnv.ACTION_BLOCK_IP,
            },
            {
                "name": "Critical SQL Injection",
                "analysis": {
                    "threat_type": "SQL Injection",
                    "risk_level": "Critical",
                    "is_attack": True,
                    "source_ip": "203.0.113.42"
                },
                "expected": SecurityEnv.ACTION_BLOCK_IP,
            },
            {
                "name": "Low Risk Reconnaissance",
                "analysis": {
                    "threat_type": "Reconnaissance",
                    "risk_level": "Low",
                    "is_attack": True,
                    "source_ip": "172.16.0.5"
                },
                "expected": SecurityEnv.ACTION_MONITOR,
            },
            {
                "name": "Critical DDoS Attack",
                "analysis": {
                    "threat_type": "DoS",
                    "risk_level": "Critical",
                    "is_attack": True,
                    "source_ip": "198.51.100.25"
                },
                "expected": SecurityEnv.ACTION_ISOLATE,
            },
        ]
        
        passed = 0
        total = len(test_cases)
        
        for test in test_cases:
            self.env.set_current_analysis(test['analysis'])
            obs, _ = self.env.reset()
            action, _ = self.agent.predict(obs, deterministic=True)
            action_int = int(action)
            
            expected_name = SecurityEnv.ACTION_NAMES[test['expected']]
            actual_name = SecurityEnv.ACTION_NAMES[action_int]
            
            status = "✓" if action_int == test['expected'] else "✗"
            logger.info(f"{status} {test['name']}")
            logger.info(f"  Expected: {expected_name}, Got: {actual_name}")
            
            if action_int == test['expected']:
                passed += 1
        
        logger.info("=" * 80)
        logger.info(f"Validation Results: {passed}/{total} tests passed "
                   f"({100*passed/total:.1f}%)")
        logger.info("=" * 80 + "\n")


def main():
    """Main execution function."""
    print("=" * 80)
    print("ENHANCED RL AGENT RETRAINING")
    print("=" * 80)
    
    # Configuration
    TRAINING_DATA_PATH = "/home/tejas/Projects/AIS/data/UNSW_finetuning.jsonl"
    MODEL_SAVE_PATH = "/home/tejas/Projects/AIS/ais_rl_agent_ppo.zip"
    TOTAL_TRAINING_STEPS = 200000
    
    try:
        trainer = ModelTrainer(
            training_data_path=TRAINING_DATA_PATH,
            model_save_path=MODEL_SAVE_PATH,
            total_steps=TOTAL_TRAINING_STEPS
        )
        
        # Execute training
        trainer.train()
        
        # Run validation
        trainer.validate()
        
        logger.info("\n✓ Training pipeline completed successfully!")
        logger.info("  The agent is now ready for deployment.")
        logger.info("  Run threat_analyzer.py to test the full pipeline.\n")
        
    except Exception as e:
        logger.critical(f"Fatal error: {e}")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

