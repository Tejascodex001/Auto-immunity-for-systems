#!/usr/bin/env python3
"""
Complete AI-Driven Security Analysis Pipeline
Integrates: Log Parser → Advanced RAG → RL Agent → Executor
Auto-generates clean summaries after analysis
"""

import json
import os
import sys
import traceback
import logging
import csv
from typing import Dict, Any, List
from pathlib import Path
from datetime import datetime

from stable_baselines3 import PPO

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Import custom modules
try:
    current_dir = os.path.dirname(os.path.abspath(__file__))
    src_dir = os.path.dirname(current_dir)
    
    if not os.path.exists(os.path.join(src_dir, '__init__.py')):
        logger.info(f"Creating missing __init__.py in {src_dir}")
        open(os.path.join(src_dir, '__init__.py'), 'w').close()
    
    sys.path.append(src_dir)
    
    from executor.executor import Executor
    from log_parser.log_parser import LogParser
    from environment.security_env import SecurityEnv
    
    # Import the AdvancedRAGAnalyzer
    from LLM.advanced_rag_analyzer import AdvancedRAGAnalyzer
    
except ImportError as e:
    logger.critical(f"Could not import required module: {e}")
    traceback.print_exc()
    sys.exit(1)


class SummaryGenerator:
    """Generates clean summaries from analysis results."""
    
    def __init__(self, analysis_file: str, output_dir: str = None):
        """
        Initialize summary generator.
        
        Args:
            analysis_file: Path to analysis results JSONL file
            output_dir: Directory for output files
        """
        self.analysis_file = Path(analysis_file)
        self.output_dir = Path(output_dir) if output_dir else self.analysis_file.parent
        
        # Generate timestamped output filenames
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.csv_summary = self.output_dir / f"summary_{timestamp}.csv"
        self.attacks_csv = self.output_dir / f"attacks_{timestamp}.csv"
        self.json_summary = self.output_dir / f"summary_{timestamp}.json"
    
    def load_records(self) -> List[Dict[str, Any]]:
        """Load analysis records from JSONL file."""
        records = []
        with open(self.analysis_file, 'r') as f:
            for line in f:
                if line.strip():
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return records
    
    def extract_summary(self, record: Dict[str, Any]) -> Dict[str, str]:
        """Extract key fields for summary."""
        timestamp = record.get('timestamp', '')
        try:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            formatted_time = dt.strftime("%Y-%m-%d %H:%M:%S")
        except:
            formatted_time = timestamp[:19] if len(timestamp) >= 19 else timestamp
        
        return {
            'time': formatted_time,
            'ip': record.get('source_ip', 'Unknown'),
            'attack_type': record.get('threat_type', 'Unknown'),
            'risk': record.get('risk_level', 'N/A'),
            'is_attack': 'Yes' if record.get('is_attack', False) else 'No',
            'confidence': f"{record.get('confidence', 0.0):.2f}"
        }
    
    def generate_csv(self, records: List[Dict[str, Any]]) -> None:
        """Generate CSV summary (all events)."""
        with open(self.csv_summary, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['time', 'ip', 'attack_type', 'risk', 'is_attack', 'confidence'])
            writer.writeheader()
            
            for record in records:
                summary = self.extract_summary(record)
                writer.writerow(summary)
        
        logger.info(f"✓ CSV summary: {self.csv_summary.name}")
    
    def generate_attacks_csv(self, records: List[Dict[str, Any]]) -> None:
        """Generate CSV with attacks only."""
        attacks = [r for r in records if r.get('is_attack', False)]
        
        with open(self.attacks_csv, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['time', 'ip', 'attack_type', 'risk', 'confidence', 'action'])
            writer.writeheader()
            
            for record in attacks:
                summary = self.extract_summary(record)
                actions = record.get('recommended_actions', [])
                
                row = {
                    'time': summary['time'],
                    'ip': summary['ip'],
                    'attack_type': summary['attack_type'],
                    'risk': summary['risk'],
                    'confidence': summary['confidence'],
                    'action': actions[0] if actions else 'No action'
                }
                writer.writerow(row)
        
        logger.info(f"✓ Attacks CSV: {self.attacks_csv.name} ({len(attacks)} attacks)")
    
    def generate_json(self, records: List[Dict[str, Any]]) -> None:
        """Generate JSON summary."""
        summaries = [self.extract_summary(record) for record in records]
        attacks = sum(1 for s in summaries if s['is_attack'] == 'Yes')
        
        output = {
            'generated_at': datetime.now().isoformat(),
            'total_events': len(summaries),
            'attacks_detected': attacks,
            'normal_events': len(summaries) - attacks,
            'events': summaries
        }
        
        with open(self.json_summary, 'w') as f:
            json.dump(output, f, indent=2)
        
        logger.info(f"✓ JSON summary: {self.json_summary.name}")
    
    def generate_all(self) -> None:
        """Generate all summary files."""
        logger.info("\n" + "=" * 80)
        logger.info("GENERATING CLEAN SUMMARIES")
        logger.info("=" * 80)
        
        records = self.load_records()
        
        if not records:
            logger.warning("No records to summarize")
            return
        
        self.generate_csv(records)
        self.generate_attacks_csv(records)
        self.generate_json(records)
        
        # Print quick stats
        attacks = sum(1 for r in records if r.get('is_attack', False))
        logger.info(f"\n📊 Summary: {len(records)} events, {attacks} attacks ({100*attacks/len(records):.1f}%)")
        logger.info("=" * 80 + "\n")


class SecurityPipeline:
    """Main security analysis pipeline with advanced RAG."""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize security pipeline.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.metrics = {
            'total_events': 0,
            'attacks_detected': 0,
            'normal_events': 0,
            'actions_taken': {},
            'errors': 0,
            'threat_type_distribution': {},
            'risk_level_distribution': {},
            'confidence_scores': []
        }
        
        self._initialize_components()
    
    def _initialize_components(self) -> None:
        """Initialize all pipeline components."""
        logger.info("\n" + "=" * 80)
        logger.info("INITIALIZING ADVANCED SECURITY PIPELINE")
        logger.info("=" * 80)
        
        # Initialize log parser
        logger.info("[INIT] Loading Log Parser...")
        self.log_parser = LogParser(
            keywords=self.config['interesting_keywords']
        )
        
        # Initialize Advanced RAG analyzer
        logger.info("[INIT] Loading Advanced RAG Analyzer...")
        self.rag_analyzer = AdvancedRAGAnalyzer(
            knowledge_base_dir=self.config['knowledge_base_dir'],
            llm_model=self.config.get('llm_model', 'phi3:mini'),
            n_neighbors=self.config.get('n_neighbors', 5),
            use_multi_query=self.config.get('use_multi_query', True),
            use_reranking=self.config.get('use_reranking', True)
        )
        
        # Initialize executor
        logger.info("[INIT] Loading Executor...")
        self.executor = Executor(
            dry_run=self.config.get('dry_run', True)
        )
        
        # Initialize RL agent
        logger.info("[INIT] Loading RL Agent...")
        if not os.path.exists(self.config['rl_agent_path']):
            raise FileNotFoundError(
                f"Trained RL Agent not found at: {self.config['rl_agent_path']}"
            )
        
        self.rl_env = SecurityEnv()
        self.rl_agent = PPO.load(
            self.config['rl_agent_path'], 
            env=self.rl_env, 
            device='cpu'
        )
        logger.info("  ✓ RL Agent loaded successfully")
        
        logger.info("=" * 80 + "\n")
    
    def process_event(self, event: str, event_num: int, 
                     total_events: int, output_log) -> None:
        """
        Process a single security event.
        
        Args:
            event: Log entry to process
            event_num: Event number
            total_events: Total number of events
            output_log: Output file handle
        """
        logger.info(f"\n{'='*80}")
        logger.info(f"EVENT {event_num}/{total_events}")
        logger.info(f"{'='*80}")
        logger.info(f"Log: {event[:150]}...")
        
        self.metrics['total_events'] += 1
        
        try:
            # Step 1: Advanced RAG Analysis
            logger.info("\n[STEP 1] RAG Analysis")
            final_analysis = self.rag_analyzer.analyze(event)
            
            if final_analysis is None:
                logger.warning("  ✗ Skipping - analysis failed")
                self.metrics['errors'] += 1
                return
            
            # Save analysis
            output_log.write(json.dumps(final_analysis) + '\n')
            output_log.flush()
            
            # Update metrics
            threat_type = final_analysis.get('threat_type', 'Unknown')
            risk_level = final_analysis.get('risk_level', 'Unknown')
            confidence = final_analysis.get('confidence', 0.0)
            
            self.metrics['threat_type_distribution'][threat_type] = \
                self.metrics['threat_type_distribution'].get(threat_type, 0) + 1
            
            self.metrics['risk_level_distribution'][risk_level] = \
                self.metrics['risk_level_distribution'].get(risk_level, 0) + 1
            
            self.metrics['confidence_scores'].append(confidence)
            
            if final_analysis.get('is_attack', False):
                self.metrics['attacks_detected'] += 1
            else:
                self.metrics['normal_events'] += 1
            
            # Step 2: RL Agent Decision
            logger.info("\n[STEP 2] RL Agent Decision Making")
            self.rl_env.set_current_analysis(final_analysis)
            observation, _ = self.rl_env.reset()
            
            logger.info(f"  Observation: {observation}")
            
            action, _ = self.rl_agent.predict(observation, deterministic=True)
            action_int = int(action)
            chosen_action = SecurityEnv.ACTION_NAMES.get(action_int, "Unknown")
            
            logger.info(f"  → Decision: {chosen_action}")
            
            # Track actions
            self.metrics['actions_taken'][chosen_action] = \
                self.metrics['actions_taken'].get(chosen_action, 0) + 1
            
            # Step 3: Execute action
            logger.info("\n[STEP 3] Action Execution")
            
            if action_int == SecurityEnv.ACTION_BLOCK_IP:
                logger.warning(f"  🚫 BLOCKING IP: {final_analysis.get('source_ip')}")
                final_analysis['recommended_actions'] = ["Block the source IP"]
                self.executor.process_actions(final_analysis)
            
            elif action_int == SecurityEnv.ACTION_MONITOR:
                logger.info(f"  👁️  MONITORING: {final_analysis.get('source_ip')}")
                final_analysis['recommended_actions'] = ["Monitor activity"]
                self.executor.process_actions(final_analysis)
            
            elif action_int == SecurityEnv.ACTION_ALERT:
                logger.warning(f"  📢 ALERT: Escalating to security team")
                final_analysis['recommended_actions'] = ["Alert security team"]
                self.executor.process_actions(final_analysis)
            
            elif action_int == SecurityEnv.ACTION_ISOLATE:
                logger.critical(f"  🔒 ISOLATING SYSTEM")
                final_analysis['recommended_actions'] = ["Isolate system immediately"]
                self.executor.process_actions(final_analysis)
            
            else:
                logger.info(f"  ✓ NO ACTION REQUIRED")
            
            # Print summary
            logger.info("\n" + "-" * 80)
            logger.info(f"Summary:")
            logger.info(f"  Threat: {threat_type}")
            logger.info(f"  Risk: {risk_level}")
            logger.info(f"  Confidence: {confidence:.2f}")
            logger.info(f"  Action: {chosen_action}")
            logger.info(f"  Source IP: {final_analysis.get('source_ip', 'Unknown')}")
            logger.info("-" * 80)
            
        except Exception as e:
            logger.error(f"  ✗ Error processing event: {e}")
            traceback.print_exc()
            self.metrics['errors'] += 1
    
    def run(self) -> None:
        """Execute the security pipeline."""
        logger.info("\n" + "=" * 80)
        logger.info("STARTING ANALYSIS PIPELINE")
        logger.info("=" * 80)
        
        start_time = datetime.now()
        output_file = self.config['analysis_output_file']
        
        try:
            with open(output_file, 'w') as output_log:  # 'w' to overwrite
                # Parse log file
                logger.info(f"\n[PARSING] Reading logs from: {self.config['raw_log_file']}")
                
                important_events = list(
                    self.log_parser.parse_log_file(
                        self.config['raw_log_file']
                    )
                )
                
                if not important_events:
                    logger.warning("No important events found in log file.")
                    return
                
                logger.info(f"✓ Found {len(important_events)} events to analyze\n")
                
                # Process each event
                for event_num, event in enumerate(important_events, 1):
                    self.process_event(
                        event, event_num, len(important_events), output_log
                    )
                    
                    # Print progress every 10 events
                    if event_num % 10 == 0:
                        logger.info(f"\n{'='*80}")
                        logger.info(f"PROGRESS: {event_num}/{len(important_events)} events processed")
                        logger.info(f"{'='*80}\n")
            
            # Calculate elapsed time
            elapsed_time = (datetime.now() - start_time).total_seconds()
            
            # Print final summary
            self._print_summary(elapsed_time)
            
            # Generate clean summaries
            if self.config.get('generate_summaries', True):
                summary_gen = SummaryGenerator(output_file)
                summary_gen.generate_all()
            
        except Exception as e:
            logger.critical(f"Pipeline error: {e}")
            traceback.print_exc()
            raise
    
    def _print_summary(self, elapsed_time: float) -> None:
        """Print comprehensive pipeline execution summary."""
        logger.info("\n" + "=" * 80)
        logger.info("PIPELINE EXECUTION SUMMARY")
        logger.info("=" * 80)
        
        # Basic stats
        logger.info(f"\n📊 Processing Statistics:")
        logger.info(f"  Total events processed: {self.metrics['total_events']}")
        logger.info(f"  Attacks detected: {self.metrics['attacks_detected']}")
        logger.info(f"  Normal events: {self.metrics['normal_events']}")
        logger.info(f"  Errors: {self.metrics['errors']}")
        logger.info(f"  Processing time: {elapsed_time:.2f} seconds")
        logger.info(f"  Average time/event: {elapsed_time/self.metrics['total_events']:.2f}s")
        
        # Attack rate
        if self.metrics['total_events'] > 0:
            attack_rate = 100 * self.metrics['attacks_detected'] / self.metrics['total_events']
            logger.info(f"  Attack rate: {attack_rate:.1f}%")
        
        # Confidence scores
        if self.metrics['confidence_scores']:
            avg_confidence = sum(self.metrics['confidence_scores']) / len(self.metrics['confidence_scores'])
            min_confidence = min(self.metrics['confidence_scores'])
            max_confidence = max(self.metrics['confidence_scores'])
            
            logger.info(f"\n🎯 Confidence Metrics:")
            logger.info(f"  Average: {avg_confidence:.3f}")
            logger.info(f"  Min: {min_confidence:.3f}")
            logger.info(f"  Max: {max_confidence:.3f}")
        
        # Actions taken
        if self.metrics['actions_taken']:
            logger.info(f"\n⚡ Actions Taken:")
            total_actions = sum(self.metrics['actions_taken'].values())
            for action, count in sorted(self.metrics['actions_taken'].items(), 
                                       key=lambda x: x[1], reverse=True):
                percentage = 100 * count / total_actions
                logger.info(f"  {action}: {count} ({percentage:.1f}%)")
        
        # Threat distribution
        if self.metrics['threat_type_distribution']:
            logger.info(f"\n🎭 Threat Type Distribution:")
            sorted_threats = sorted(self.metrics['threat_type_distribution'].items(), 
                                   key=lambda x: x[1], reverse=True)
            for threat, count in sorted_threats[:10]:  # Top 10
                percentage = 100 * count / self.metrics['total_events']
                logger.info(f"  {threat}: {count} ({percentage:.1f}%)")
        
        # Risk distribution
        if self.metrics['risk_level_distribution']:
            logger.info(f"\n⚠️  Risk Level Distribution:")
            risk_order = ['Critical', 'High', 'Medium', 'Low', 'N/A']
            for risk in risk_order:
                count = self.metrics['risk_level_distribution'].get(risk, 0)
                if count > 0:
                    percentage = 100 * count / self.metrics['total_events']
                    logger.info(f"  {risk}: {count} ({percentage:.1f}%)")
        
        # RAG statistics
        logger.info(f"\n🔍 RAG Analyzer Statistics:")
        rag_stats = self.rag_analyzer.get_statistics()
        logger.info(f"  Knowledge base size: {rag_stats['knowledge_base_size']:,}")
        logger.info(f"  Cache hits: {rag_stats['cache_size']}")
        logger.info(f"  Multi-query: {rag_stats['multi_query_enabled']}")
        logger.info(f"  Re-ranking: {rag_stats['reranking_enabled']}")
        
        logger.info(f"\n📁 Output:")
        logger.info(f"  Analysis results: {self.config['analysis_output_file']}")
        
        logger.info("\n" + "=" * 80)
        logger.info("✓ PIPELINE COMPLETED SUCCESSFULLY")
        logger.info("=" * 80 + "\n")


def main():
    """Main execution function."""
    logger.info("=" * 80)
    logger.info("AI-DRIVEN SECURITY ANALYSIS PIPELINE")
    logger.info("Advanced RAG + RL Agent Integration")
    logger.info("=" * 80)
    
    # Configuration
    config = {
        # Data paths
        'knowledge_base_dir': "/home/tejas/Projects/AIS/data/",
        'raw_log_file': "/home/tejas/Projects/AIS/test_web/logs/app.log",
        'analysis_output_file': "/home/tejas/Projects/AIS/analysis_results.jsonl",
        'rl_agent_path': "/home/tejas/Projects/AIS/ais_rl_agent_ppo.zip",
        
        # Log parser settings
        'interesting_keywords': [
            "Login failed", "User logged in", "Failed password", 
            "session opened", "authentication failure", "attack",
            "injection", "exploit", "malware", "suspicious",
            "unauthorized", "blocked", "denied", "critical",
            "error", "warning"
        ],
        
        # RAG settings
        'llm_model': 'phi3:mini',
        'n_neighbors': 5,
        'use_multi_query': True,
        'use_reranking': True,
        
        # Execution settings
        'dry_run': True,  # Set to False for production
        'generate_summaries': True,  # Auto-generate clean summaries
    }
    
    try:
        # Initialize and run pipeline
        pipeline = SecurityPipeline(config)
        pipeline.run()
        
        logger.info("\n✓ All operations completed successfully!\n")
        
    except KeyboardInterrupt:
        logger.warning("\n\n⚠️  Pipeline interrupted by user\n")
        sys.exit(0)
    except Exception as e:
        logger.critical(f"\n\n✗ FATAL ERROR: {e}\n")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()