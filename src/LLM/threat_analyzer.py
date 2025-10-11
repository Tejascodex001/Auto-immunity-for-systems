import ollama
import json
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.neighbors import NearestNeighbors
import os
import sys
import glob
import traceback

from stable_baselines3 import PPO

# --- Import custom modules ---
try:
    current_dir = os.path.dirname(os.path.abspath(__file__))
    src_dir = os.path.dirname(current_dir)
    
    if not os.path.exists(os.path.join(src_dir, '__init__.py')):
        print(f"Creating missing __init__.py in {src_dir}")
        open(os.path.join(src_dir, '__init__.py'), 'w').close()
    
    sys.path.append(src_dir)
    from executor.executor import Executor
    from log_parser.log_parser import LogParser
    from environment.security_env import SecurityEnv
except ImportError as e:
    print(f"CRITICAL ERROR: Could not import module. Error: {e}")
    traceback.print_exc()
    sys.exit(1)


def extract_json_from_string(text):
    """Finds and parses the first valid JSON object within a string."""
    start_index = text.find('{')
    end_index = text.rfind('}')
    if start_index != -1 and end_index != -1 and end_index > start_index:
        json_str = text[start_index:end_index+1]
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            return None
    return None


def compute_is_attack(threat_type):
    """Determines if an event is an attack based on threat type."""
    benign_threats = ['Legitimate Activity', 'Normal', 'Informational', 'N/A', None, 'Legitimate Login']
    if threat_type in benign_threats:
        return False
    return True


# =====================================================================================
# --- RAG Security Analyzer Class ---
# =====================================================================================
class RAGSecurityAnalyzer:
    def __init__(self, knowledge_base_dir, llm_model='phi3:mini', n_neighbors=3):
        self.model = llm_model
        self.n_neighbors = n_neighbors
        print("Initializing RAG Security Analyzer...")
        knowledge_base_paths = glob.glob(os.path.join(knowledge_base_dir, '*.jsonl'))
        if not knowledge_base_paths:
            raise ValueError(f"No .jsonl files found in: {knowledge_base_dir}")
        self.knowledge_df = self._load_knowledge_base(knowledge_base_paths)
        if self.knowledge_df.empty:
            raise ValueError("Knowledge base is empty after loading.")
        self.retriever = self._build_retriever()
        print(f"✓ Analyzer ready. Loaded {len(self.knowledge_df)} examples from {len(knowledge_base_paths)} files.")

    def _load_knowledge_base(self, file_paths):
        all_records = []
        print(f"Loading knowledge from {len(file_paths)} file(s)...")
        for path in file_paths:
            print(f"  - Loading {os.path.basename(path)}")
            with open(path, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        all_records.append({
                            'log_entry': data['messages'][1]['content'],
                            'json_analysis': data['messages'][2]['content']
                        })
                    except (json.JSONDecodeError, IndexError, KeyError):
                        continue
        return pd.DataFrame(all_records)

    def _build_retriever(self):
        print("Building retriever...")
        self.vectorizer = TfidfVectorizer(min_df=5, stop_words='english')
        tfidf_matrix = self.vectorizer.fit_transform(self.knowledge_df['log_entry'])
        retriever = NearestNeighbors(n_neighbors=self.n_neighbors, algorithm='brute', metric='cosine')
        retriever.fit(tfidf_matrix)
        return retriever

    def _find_similar_examples(self, new_log_entry):
        query_vector = self.vectorizer.transform([new_log_entry])
        _, indices = self.retriever.kneighbors(query_vector)
        return self.knowledge_df.iloc[indices[0]]

    def _normalize_threat_type(self, threat_description, log_entry):
        """
        Converts long threat descriptions into standardized threat types.
        Maps various descriptions to the threat_map keys in SecurityEnv.
        Uses both the threat description AND the log entry for better classification.
        """
        threat_lower = str(threat_description or '').lower()
        log_lower = str(log_entry or '').lower()
        
        # First, check for explicit success/normal indicators in the log
        if any(word in log_lower for word in ['successfully', 'login success', 'logged in successfully', 'accepted', 'allowed']):
            if any(word in log_lower for word in ['failed', 'fail', 'incorrect', 'not found', 'denied', 'refused']):
                # Contains both success and failure keywords - favor failure for failed attempts
                pass
            else:
                # Clear success indicator with no failure keywords
                return "Normal"
        
        # Check for failed/attack indicators
        if any(word in threat_lower for word in ['failed', 'attempt', 'fail', 'incorrect']):
            if any(word in threat_lower for word in ['multiple', 'repeated', 'brute', 'force']):
                return "Brute Force Attack"
            # Single failed attempt might still be brute force related
            return "Brute Force Attack"
        
        # Standard threat mappings
        if any(word in threat_lower for word in ['brute', 'force', 'password', 'credential', 'repeated attempt']):
            return "Brute Force Attack"
        elif any(word in threat_lower for word in ['sql', 'injection', 'query']):
            return "SQL Injection"
        elif any(word in threat_lower for word in ['command', 'injection', 'shell', 'os command']):
            return "Command Injection"
        elif any(word in threat_lower for word in ['dos', 'ddos', 'flood', 'denial']):
            return "DoS"
        elif any(word in threat_lower for word in ['exploit', 'cve', 'vulnerability']):
            return "Exploit"
        elif any(word in threat_lower for word in ['scan', 'reconnaissance', 'probe', 'enum', 'port scan']):
            return "Reconnaissance"
        elif any(word in threat_lower for word in ['worm', 'malware', 'virus']):
            return "Worms"
        elif any(word in threat_lower for word in ['backdoor', 'persistence', 'persistence mechanism']):
            return "Backdoors"
        elif any(word in threat_lower for word in ['shellcode', 'payload', 'code execution']):
            return "Shellcode"
        elif any(word in threat_lower for word in ['suspicious', 'process', 'execution', 'unauthorized']):
            return "Suspicious Process Creation"
        elif any(word in threat_lower for word in ['normal', 'legitimate', 'info', 'informational', 'standard']):
            return "Normal"
        else:
            # Default to Normal for truly unknown threats
            return "Normal"

    def _normalize_risk_level(self, risk_description):
        """
        Converts risk descriptions into standardized risk levels.
        """
        risk_lower = str(risk_description or '').lower()
        
        if any(word in risk_lower for word in ['critical', 'severe', 'critical risk']):
            return "Critical"
        elif any(word in risk_lower for word in ['high', 'significant', 'high risk']):
            return "High"
        elif any(word in risk_lower for word in ['medium', 'moderate', 'mid']):
            return "Medium"
        elif any(word in risk_lower for word in ['low', 'minor', 'negligible', 'informational']):
            return "Low"
        else:
            return "N/A"

    def analyze(self, new_log_entry):
        """Performs RAG analysis on a log entry."""
        print(f"\n→ Analyzing: '{new_log_entry}'")
        try:
            similar_examples = self._find_similar_examples(new_log_entry)
            print(f"  Found {len(similar_examples)} similar examples")
            
            prompt_parts = []
            for _, row in similar_examples.iterrows():
                prompt_parts.append(f"Log: {row['log_entry']}\nAnalysis:\n{row['json_analysis']}")
            
            prompt_parts.append(f"Log: {new_log_entry}\nAnalysis:")
            final_prompt = "\n---\n".join(prompt_parts)

            response = ollama.generate(
                model=self.model,
                prompt=final_prompt,
                format='json'
            )
            
            raw_response_text = response['response']
            parsed_json = extract_json_from_string(raw_response_text)
            
            if parsed_json is None:
                print(f"  ✗ Could not parse JSON from LLM response")
                print(f"    Raw: {raw_response_text[:200]}")
                return None
            
            # --- CRITICAL FIX: Normalize threat type and risk level ---
            raw_threat = parsed_json.get('threat_type', 'Normal')
            raw_risk = parsed_json.get('risk_level', 'Low')
            
            # Pass log entry as additional context for better threat classification
            parsed_json['threat_type'] = self._normalize_threat_type(raw_threat, new_log_entry)
            parsed_json['risk_level'] = self._normalize_risk_level(raw_risk)
            
            # Add is_attack field based on normalized threat type
            threat_type = parsed_json.get('threat_type', 'Normal')
            parsed_json['is_attack'] = compute_is_attack(threat_type)
            
            # Ensure source_ip exists (extract from log entry if possible)
            if 'source_ip' not in parsed_json or not parsed_json['source_ip']:
                # Try to extract IP from log entry using regex
                import re
                ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                ip_match = re.search(ip_pattern, new_log_entry)
                parsed_json['source_ip'] = ip_match.group(0) if ip_match else "0.0.0.0"
            
            print(f"  ✓ Threat={parsed_json['threat_type']}, Risk={parsed_json['risk_level']}, IsAttack={parsed_json['is_attack']}, SourceIP={parsed_json.get('source_ip', 'N/A')}")
            
            return parsed_json
            
        except Exception as e:
            print(f"  ✗ Analysis error: {e}")
            traceback.print_exc()
            return None


# =====================================================================================
# --- Main Execution Block ---
# =====================================================================================
if __name__ == "__main__":
    print("=" * 80)
    print("AI-DRIVEN SECURITY ANALYSIS PIPELINE")
    print("=" * 80)
    
    # Configuration
    KNOWLEDGE_BASE_DIRECTORY = "/home/tejas/Projects/AIS/data/"
    INTERESTING_KEYWORDS = ["Login failed", "User logged in", "Failed password", "session opened"]
    RAW_LOG_FILE_TO_ANALYZE = "/home/tejas/Projects/AIS/app.log"
    ANALYSIS_OUTPUT_FILE = "analysis_results.jsonl"
    RL_AGENT_PATH = "/home/tejas/Projects/AIS/ais_rl_agent_ppo.zip"

    try:
        # Initialize components
        print("\n[INIT] Loading Log Parser...")
        log_parser = LogParser(keywords=INTERESTING_KEYWORDS)
        
        print("[INIT] Loading RAG Analyzer...")
        rag_analyzer = RAGSecurityAnalyzer(knowledge_base_dir=KNOWLEDGE_BASE_DIRECTORY)
        
        print("[INIT] Loading Executor...")
        executor = Executor(dry_run=True)

        print("[INIT] Loading RL Agent...")
        if not os.path.exists(RL_AGENT_PATH):
            raise FileNotFoundError(f"Trained RL Agent not found at: {RL_AGENT_PATH}")
        rl_env = SecurityEnv()
        rl_agent = PPO.load(RL_AGENT_PATH, env=rl_env, device='cpu')
        print("  ✓ RL Agent loaded successfully")
        
        # Main pipeline loop
        print("\n" + "=" * 80)
        print("STARTING ANALYSIS PIPELINE")
        print("=" * 80)
        
        with open(ANALYSIS_OUTPUT_FILE, 'a') as output_log:
            important_events = list(log_parser.parse_log_file(RAW_LOG_FILE_TO_ANALYZE))
            
            if not important_events:
                print("No important events found in log file.")
            else:
                print(f"Found {len(important_events)} important events to analyze.\n")
                
                for event_num, event in enumerate(important_events, 1):
                    print(f"\n[EVENT {event_num}/{len(important_events)}]")
                    print("-" * 80)
                    
                    # Step 1: RAG Analysis
                    final_analysis = rag_analyzer.analyze(event)
                    
                    if final_analysis is None:
                        print("  Skipping this event due to analysis failure.")
                        continue
                    
                    # Save analysis to output
                    output_log.write(json.dumps(final_analysis) + '\n')
                    
                    # Step 2: RL Agent Decision
                    rl_env.set_current_analysis(final_analysis)
                    observation, _ = rl_env.reset()
                    
                    print(f"  Observation vector: {observation}")
                    
                    action, confidence = rl_agent.predict(observation, deterministic=True)
                    action_map = {0: "Do Nothing", 1: "Monitor", 2: "Block IP"}
                    chosen_action = action_map.get(int(action), "Unknown")
                    
                    print(f"  RL Agent Decision: '{chosen_action}' (action={int(action)})")
                    
                    # Step 3: Execute action
                    if chosen_action == "Block IP":
                        print(f"  ⚠ HIGH-RISK ACTION - Executing Block IP")
                        # Add source_ip to recommended_actions for executor
                        final_analysis['recommended_actions'] = ["Block the source IP"]
                        executor.process_actions(final_analysis)
                    elif chosen_action == "Monitor":
                        print(f"  ℹ Monitoring enabled for this event")
                        final_analysis['recommended_actions'] = ["Monitor"]
                        executor.process_actions(final_analysis)
                    else:
                        print(f"  ✓ No action needed")
                    
                    print("-" * 80)
        
        print("\n" + "=" * 80)
        print("PIPELINE COMPLETE")
        print(f"Analysis results saved to: {ANALYSIS_OUTPUT_FILE}")
        print("=" * 80)

    except Exception as e:
        print(f"\n✗ FATAL ERROR: {e}")
        traceback.print_exc()
        sys.exit(1)