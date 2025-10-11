#!/usr/bin/env python3
"""
Generate clean summary from analysis results.
Creates a simplified CSV/JSON file with key information only.
"""

import json
import csv
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AnalysisSummaryGenerator:
    """Generate clean summaries from detailed analysis results."""
    
    def __init__(self, input_file: str, output_dir: str = None):
        """
        Initialize the summary generator.
        
        Args:
            input_file: Path to analysis_results.jsonl
            output_dir: Directory for output files (defaults to same as input)
        """
        self.input_file = Path(input_file)
        
        if output_dir:
            self.output_dir = Path(output_dir)
        else:
            self.output_dir = self.input_file.parent
        
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate output filenames
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.csv_output = self.output_dir / f"analysis_summary_{timestamp}.csv"
        self.json_output = self.output_dir / f"analysis_summary_{timestamp}.json"
        self.attacks_only_output = self.output_dir / f"attacks_only_{timestamp}.csv"
    
    def load_analysis_data(self) -> List[Dict[str, Any]]:
        """
        Load analysis data from JSONL file.
        
        Returns:
            List of analysis records
        """
        logger.info(f"Loading analysis data from: {self.input_file}")
        
        records = []
        with open(self.input_file, 'r') as f:
            for line_num, line in enumerate(f, 1):
                try:
                    record = json.loads(line.strip())
                    records.append(record)
                except json.JSONDecodeError as e:
                    logger.warning(f"Line {line_num}: Invalid JSON - {e}")
                    continue
        
        logger.info(f"Loaded {len(records)} records")
        return records
    
    def extract_summary_fields(self, record: Dict[str, Any]) -> Dict[str, str]:
        """
        Extract key fields for summary.
        
        Args:
            record: Full analysis record
            
        Returns:
            Dictionary with summary fields
        """
        # Parse timestamp
        timestamp = record.get('timestamp', '')
        try:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            formatted_time = dt.strftime("%Y-%m-%d %H:%M:%S")
        except:
            formatted_time = timestamp[:19] if len(timestamp) >= 19 else timestamp
        
        return {
            'timestamp': formatted_time,
            'source_ip': record.get('source_ip', 'Unknown'),
            'threat_type': record.get('threat_type', 'Unknown'),
            'risk_level': record.get('risk_level', 'N/A'),
            'is_attack': 'Yes' if record.get('is_attack', False) else 'No',
            'confidence': f"{record.get('confidence', 0.0):.2f}",
        }
    
    def generate_csv_summary(self, records: List[Dict[str, Any]]) -> None:
        """
        Generate CSV summary file.
        
        Args:
            records: List of analysis records
        """
        logger.info(f"Generating CSV summary: {self.csv_output}")
        
        with open(self.csv_output, 'w', newline='') as f:
            fieldnames = ['timestamp', 'source_ip', 'threat_type', 
                         'risk_level', 'is_attack', 'confidence']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            
            writer.writeheader()
            
            for record in records:
                summary = self.extract_summary_fields(record)
                writer.writerow(summary)
        
        logger.info(f"✓ CSV summary saved: {self.csv_output}")
    
    def generate_json_summary(self, records: List[Dict[str, Any]]) -> None:
        """
        Generate JSON summary file.
        
        Args:
            records: List of analysis records
        """
        logger.info(f"Generating JSON summary: {self.json_output}")
        
        summaries = [self.extract_summary_fields(record) for record in records]
        
        output_data = {
            'generated_at': datetime.now().isoformat(),
            'total_events': len(summaries),
            'attacks_detected': sum(1 for s in summaries if s['is_attack'] == 'Yes'),
            'events': summaries
        }
        
        with open(self.json_output, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        logger.info(f"✓ JSON summary saved: {self.json_output}")
    
    def generate_attacks_only_csv(self, records: List[Dict[str, Any]]) -> None:
        """
        Generate CSV with attacks only.
        
        Args:
            records: List of analysis records
        """
        logger.info(f"Generating attacks-only CSV: {self.attacks_only_output}")
        
        attack_records = [r for r in records if r.get('is_attack', False)]
        
        with open(self.attacks_only_output, 'w', newline='') as f:
            fieldnames = ['timestamp', 'source_ip', 'threat_type', 
                         'risk_level', 'confidence', 'recommended_action']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            
            writer.writeheader()
            
            for record in attack_records:
                summary = self.extract_summary_fields(record)
                
                # Get first recommended action
                actions = record.get('recommended_actions', [])
                first_action = actions[0] if actions else 'No action specified'
                
                row = {
                    'timestamp': summary['timestamp'],
                    'source_ip': summary['source_ip'],
                    'threat_type': summary['threat_type'],
                    'risk_level': summary['risk_level'],
                    'confidence': summary['confidence'],
                    'recommended_action': first_action
                }
                writer.writerow(row)
        
        logger.info(f"✓ Attacks-only CSV saved: {self.attacks_only_output}")
        logger.info(f"  Total attacks: {len(attack_records)}")
    
    def print_statistics(self, records: List[Dict[str, Any]]) -> None:
        """
        Print summary statistics.
        
        Args:
            records: List of analysis records
        """
        total = len(records)
        attacks = sum(1 for r in records if r.get('is_attack', False))
        normal = total - attacks
        
        # Count by risk level
        risk_counts = {}
        for record in records:
            if record.get('is_attack', False):
                risk = record.get('risk_level', 'Unknown')
                risk_counts[risk] = risk_counts.get(risk, 0) + 1
        
        # Count by threat type
        threat_counts = {}
        for record in records:
            if record.get('is_attack', False):
                threat = record.get('threat_type', 'Unknown')
                threat_counts[threat] = threat_counts.get(threat, 0) + 1
        
        # Top attacking IPs
        ip_counts = {}
        for record in records:
            if record.get('is_attack', False):
                ip = record.get('source_ip', 'Unknown')
                if ip != 'Unknown':
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1
        
        print("\n" + "=" * 80)
        print("ANALYSIS SUMMARY STATISTICS")
        print("=" * 80)
        print(f"\n📊 Overview:")
        print(f"  Total events: {total}")
        print(f"  Attacks detected: {attacks} ({100*attacks/total:.1f}%)")
        print(f"  Normal events: {normal} ({100*normal/total:.1f}%)")
        
        if risk_counts:
            print(f"\n⚠️  Risk Level Distribution (Attacks Only):")
            for risk in ['Critical', 'High', 'Medium', 'Low']:
                count = risk_counts.get(risk, 0)
                if count > 0:
                    print(f"  {risk}: {count}")
        
        if threat_counts:
            print(f"\n🎭 Top 10 Threat Types:")
            sorted_threats = sorted(threat_counts.items(), 
                                   key=lambda x: x[1], reverse=True)[:10]
            for threat, count in sorted_threats:
                print(f"  {threat}: {count}")
        
        if ip_counts:
            print(f"\n🚨 Top 10 Attacking IPs:")
            sorted_ips = sorted(ip_counts.items(), 
                               key=lambda x: x[1], reverse=True)[:10]
            for ip, count in sorted_ips:
                print(f"  {ip}: {count} attacks")
        
        print("\n" + "=" * 80)
        print("OUTPUT FILES GENERATED:")
        print("=" * 80)
        print(f"  All events (CSV):     {self.csv_output.name}")
        print(f"  All events (JSON):    {self.json_output.name}")
        print(f"  Attacks only (CSV):   {self.attacks_only_output.name}")
        print("=" * 80 + "\n")
    
    def generate_all_summaries(self) -> None:
        """Generate all summary files and statistics."""
        try:
            # Load data
            records = self.load_analysis_data()
            
            if not records:
                logger.error("No records found in input file")
                return
            
            # Generate summaries
            self.generate_csv_summary(records)
            self.generate_json_summary(records)
            self.generate_attacks_only_csv(records)
            
            # Print statistics
            self.print_statistics(records)
            
            logger.info("✓ All summaries generated successfully!")
            
        except FileNotFoundError:
            logger.error(f"Input file not found: {self.input_file}")
        except Exception as e:
            logger.error(f"Error generating summaries: {e}")
            raise


def main():
    """Main execution function."""
    import sys
    
    print("=" * 80)
    print("ANALYSIS SUMMARY GENERATOR")
    print("=" * 80)
    print()
    
    # Configuration
    if len(sys.argv) > 1:
        INPUT_FILE = sys.argv[1]
    else:
        INPUT_FILE = "/home/tejas/Projects/AIS/analysis_results.jsonl"
    
    OUTPUT_DIR = Path(INPUT_FILE).parent
    
    # Generate summaries
    generator = AnalysisSummaryGenerator(INPUT_FILE, OUTPUT_DIR)
    generator.generate_all_summaries()


if __name__ == "__main__":
    main()