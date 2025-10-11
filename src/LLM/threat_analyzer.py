#!/usr/bin/env python3
"""
Complete AI-Driven Security Analysis Pipeline
Integrates: Log Parser → Advanced RAG → RL Agent → Executor
Auto-generates clean summaries after analysis with organized folder structure
"""

import json
import time
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
    
    # Import the HybridThreatDetector
    from LLM.advanced_rag_analyzer import HybridThreatDetector
    
except ImportError as e:
    logger.critical(f"Could not import required module: {e}")
    traceback.print_exc()
    sys.exit(1)

# In main_defender.py

# ... (all imports remain the same) ...

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time # Make sure to import time

class LogChangeHandler(FileSystemEventHandler):
    """A watchdog event handler that processes new lines appended to a log file."""
    def __init__(self, pipeline_instance, filepath_to_watch):
        self.pipeline = pipeline_instance
        self.filepath = os.path.abspath(filepath_to_watch)
        self.last_known_position = self._get_file_size()
        logger.info(f"LogChangeHandler initialized for '{self.filepath}'. Starting at position {self.last_known_position}.")

    def _get_file_size(self):
        try:
            return os.path.getsize(self.filepath)
        except FileNotFoundError:
            return 0

    def on_modified(self, event):
        """Called by watchdog when a file or directory is modified."""
        # We only care about modifications to our specific log file.
        if os.path.abspath(event.src_path) == self.filepath:
            self._process_new_lines()

    def _process_new_lines(self):
        """Reads and processes only the new content added to the log file."""
        current_size = self._get_file_size()
        if current_size > self.last_known_position:
            with open(self.filepath, 'r') as f:
                f.seek(self.last_known_position)
                new_lines = f.readlines()
                self.last_known_position = f.tell()

            if new_lines:
                logger.info(f"Detected {len(new_lines)} new log line(s). Processing...")
                for line in new_lines:
                    # Use the pipeline's parser to see if the line is interesting
                    # This now assumes your parser has a method for single lines
                    event_generator = self.pipeline.log_parser.parse_log_file_line(line)
                    for event in event_generator:
                        # If the parser yields an event, process it through the full pipeline
                        self.pipeline.process_event(event)


class SecurityPipeline:
    # ... (Your __init__ and _initialize_components methods are correct) ...
    # ... (Your process_event and _print_summary methods are correct) ...

    def run(self):
        """
        Executes the security pipeline in continuous, real-time monitoring mode using watchdog.
        """
        logger.info("--- Starting Real-Time Analysis Pipeline ---")
        
        log_path_str = self.config['raw_log_file']
        log_file_path = os.path.abspath(log_path_str)
        log_directory = os.path.dirname(log_file_path)

        # Ensure the log file and its directory exist before we start monitoring
        if not os.path.exists(log_directory):
            os.makedirs(log_directory)
            logger.info(f"Created log directory: {log_directory}")
        if not os.path.exists(log_file_path):
            open(log_file_path, 'a').close()
            logger.info(f"Created empty log file: {log_file_path}")

        # Initialize our custom event handler
        event_handler = LogChangeHandler(self, log_file_path)
        
        # Initialize the watchdog Observer
        observer = Observer()
        # Monitor the DIRECTORY, not the file, as this is more reliable
        observer.schedule(event_handler, log_directory, recursive=False)
        
        # Start the observer in a background thread
        observer.start()
        logger.info(f"Now monitoring for changes in: {log_file_path}")
        print("AIS Defender is live. Press Ctrl+C to stop.")

        try:
            # Keep the main thread alive, waiting for events
            while True:
                time.sleep(5)
        except KeyboardInterrupt:
            logger.info("Shutdown signal received. Stopping AIS Defender.")
            observer.stop()
        
        observer.join()
        self._print_summary()


class SummaryGenerator:
    """Generates clean summaries from analysis results with organized folder structure."""
    
    def __init__(self, analysis_file: str, output_dir: str = None):
        """
        Initialize summary generator with organized folder structure.
        
        Args:
            analysis_file: Path to analysis results JSONL file
            output_dir: Base directory for output files
        """
        self.analysis_file = Path(analysis_file)
        self.base_output_dir = Path(output_dir) if output_dir else self.analysis_file.parent
        
        # Create main summary folder
        self.summary_dir = self.base_output_dir / "summary"
        self.summary_dir.mkdir(parents=True, exist_ok=True)
        
        # Create subdirectories
        self.json_dir = self.summary_dir / "json"
        self.summary_csv_dir = self.summary_dir / "summary"
        self.attacks_dir = self.summary_dir / "attacks"
        
        self.json_dir.mkdir(parents=True, exist_ok=True)
        self.summary_csv_dir.mkdir(parents=True, exist_ok=True)
        self.attacks_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate timestamped output filenames
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.csv_summary = self.summary_csv_dir / f"summary_{timestamp}.csv"
        self.attacks_csv = self.attacks_dir / f"attacks_{timestamp}.csv"
        self.json_summary = self.json_dir / f"summary_{timestamp}.json"
    
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
        """Generate CSV summary (all events) in summary subfolder."""
        with open(self.csv_summary, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['time', 'ip', 'attack_type', 'risk', 'is_attack', 'confidence'])
            writer.writeheader()
            
            for record in records:
                summary = self.extract_summary(record)
                writer.writerow(summary)
        
        logger.info(f"✓ CSV summary: summary/{self.csv_summary.name}")
    
    def generate_attacks_csv(self, records: List[Dict[str, Any]]) -> None:
        """Generate CSV with attacks only in attacks subfolder."""
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
        
        logger.info(f"Attacks CSV: attacks/{self.attacks_csv.name} ({len(attacks)} attacks)")
    
    def generate_json(self, records: List[Dict[str, Any]]) -> None:
        """Generate JSON summary in json subfolder."""
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
        
        logger.info(f"JSON summary: json/{self.json_summary.name}")
    
    def generate_all(self) -> None:
        """Generate all summary files in organized structure."""
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
        logger.info(f"\nSummary: {len(records)} events, {attacks} attacks ({100*attacks/len(records):.1f}%)")
        logger.info(f"Output folder structure: {self.summary_dir}/")
        logger.info(f"  ├── json/")
        logger.info(f"  ├── summary/")
        logger.info(f"  └── attacks/")
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
        self.rag_analyzer = HybridThreatDetector(
            knowledge_base_dir=self.config['knowledge_base_dir'],
            llm_model=self.config.get('llm_model', 'phi3:mini'),
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
    

    def process_event(self, event: str):
        """
        Processes a single security event. Now takes only the event string.
        """
        self.metrics['total_events'] += 1
        logger.info(f"--- Processing Event #{self.metrics['total_events']}: '{event[:100]}...' ---")
        
        # Open the output file in append mode for each event
        with open(self.config['analysis_output_file'], 'a') as output_log:
            try:
                # Stage 1: RAG Analysis
                final_analysis = self.rag_analyzer.analyze(event)
                
                if not final_analysis:
                    logger.warning("  > Skipping - RAG analysis failed.")
                    self.metrics['errors'] += 1
                    return

                # Write full analysis to the structured log
                output_log.write(json.dumps(final_analysis) + '\n')

                # Stage 2: RL Agent Decision
                observation = self.rl_env.get_obs_from_analysis(final_analysis)
                action, _ = self.rl_agent.predict(observation, deterministic=True)
                chosen_action_name = self.rl_env.ACTION_NAMES.get(int(action), "Unknown")
                
                logger.info(f"  > RAG: Threat=[{final_analysis.get('threat_type', 'N/A')}], Risk=[{final_analysis.get('risk_level', 'N/A')}]")
                logger.info(f"  > RL Agent Decision: Chose action '{chosen_action_name}'")
                
                # ... (rest of the action execution and metrics logic) ...
            
            except Exception as e:
                logger.error(f"  > Error processing event: {e}")
                traceback.print_exc()
                self.metrics['errors'] += 1


    def run(self):
        """
        Executes the security pipeline in continuous, real-time monitoring mode.
        """
        logger.info("--- Starting Real-Time Analysis Pipeline ---")
        
        log_path = self.config['raw_log_file']
        log_dir = os.path.dirname(log_path)

        # Ensure the log file exists before we start monitoring
        if not os.path.exists(log_path):
            logger.info(f"Log file not found at {log_path}, creating it.")
            open(log_path, 'a').close()

        # Initialize our custom event handler
        event_handler = LogChangeHandler(self, log_path)
        
        # Initialize the watchdog Observer
        observer = Observer()
        observer.schedule(event_handler, log_dir, recursive=False)
        
        # Start the observer in a background thread
        observer.start()
        logger.info(f"Now monitoring for changes in: {log_path}")
        print("AIS is live. Press Ctrl+C to stop.")

        try:
            # Keep the main thread alive, waiting for events
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Shutdown signal received. Stopping AIS.")
            observer.stop()
        
        observer.join()
        self._print_summary() # Print summary on shutdown
    
    def _print_summary(self, elapsed_time: float) -> None:
        """Print comprehensive pipeline execution summary."""
        logger.info("\n" + "=" * 80)
        logger.info("PIPELINE EXECUTION SUMMARY")
        logger.info("=" * 80)
        
        # Basic stats
        logger.info(f"\nProcessing Statistics:")
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
            
            logger.info(f"\nConfidence Metrics:")
            logger.info(f"  Average: {avg_confidence:.3f}")
            logger.info(f"  Min: {min_confidence:.3f}")
            logger.info(f"  Max: {max_confidence:.3f}")
        
        # Actions taken
        if self.metrics['actions_taken']:
            logger.info(f"\nActions Taken:")
            total_actions = sum(self.metrics['actions_taken'].values())
            for action, count in sorted(self.metrics['actions_taken'].items(), 
                                       key=lambda x: x[1], reverse=True):
                percentage = 100 * count / total_actions
                logger.info(f"  {action}: {count} ({percentage:.1f}%)")
        
        # Threat distribution
        if self.metrics['threat_type_distribution']:
            logger.info(f"\nThreat Type Distribution:")
            sorted_threats = sorted(self.metrics['threat_type_distribution'].items(), 
                                   key=lambda x: x[1], reverse=True)
            for threat, count in sorted_threats[:10]:  # Top 10
                percentage = 100 * count / self.metrics['total_events']
                logger.info(f"  {threat}: {count} ({percentage:.1f}%)")
        
        # Risk distribution
        if self.metrics['risk_level_distribution']:
            logger.info(f"\nRisk Level Distribution:")
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
        logger.info(f"  Summaries folder: {Path(self.config['analysis_output_file']).parent}/summary/")
        
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
        logger.warning("\n\nPipeline interrupted by user\n")
        sys.exit(0)
    except Exception as e:
        logger.critical(f"\n\n✗ FATAL ERROR: {e}\n")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()