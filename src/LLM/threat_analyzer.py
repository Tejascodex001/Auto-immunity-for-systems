# rag_analyzer.py (Final, Complete Version)

import ollama
import json
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.neighbors import NearestNeighbors
import os
import sys
import glob
import traceback # For detailed error logging

# --- Stable Baselines for loading the trained agent ---
from stable_baselines3 import PPO

# --- Import all our custom modules ---
try:
    current_dir = os.path.dirname(os.path.abspath(__file__))
    src_dir = os.path.dirname(current_dir)
    # Check for __init__.py to validate the structure
    if not os.path.exists(os.path.join(src_dir, '__init__.py')):
        print(f"Warning: Missing __init__.py in {src_dir}. Imports may fail.")
    sys.path.append(src_dir)
    from executor.executor import Executor
    from log_parser.log_parser import LogParser
    from environment.security_env import SecurityEnv
except ImportError as e:
    print(f"CRITICAL ERROR: Could not import a required module. Error: {e}")
    print("Please ensure your project has the correct structure with __init__.py files.")
    sys.exit(1)

def extract_json_from_string(text):
    """Finds and parses the first valid JSON object within a string."""
    # Find the first '{' and the last '}'
    start_index = text.find('{')
    end_index = text.rfind('}')
    if start_index != -1 and end_index != -1 and end_index > start_index:
        json_str = text[start_index:end_index+1]
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            return None
    return None

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
            raise ValueError(f"No .jsonl files found in the directory: {knowledge_base_dir}")
        self.knowledge_df = self._load_knowledge_base(knowledge_base_paths)
        if self.knowledge_df.empty:
            raise ValueError("Knowledge base is empty after loading files.")
        self.retriever = self._build_retriever()
        print(f"Analyzer is ready. Loaded {len(self.knowledge_df)} examples from {len(knowledge_base_paths)} files.")

    def _load_knowledge_base(self, file_paths):
        all_records = []
        print(f"Loading knowledge from {len(file_paths)} file(s)...")
        for path in file_paths:
            print(f"  - Loading {os.path.basename(path)}")
            with open(path, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        all_records.append({'log_entry': data['messages'][1]['content'], 'json_analysis': data['messages'][2]['content']})
                    except (json.JSONDecodeError, IndexError, KeyError):
                        continue
        return pd.DataFrame(all_records)

    def _build_retriever(self):
        print("Building the retriever...")
        self.vectorizer = TfidfVectorizer(min_df=5, stop_words='english')
        tfidf_matrix = self.vectorizer.fit_transform(self.knowledge_df['log_entry'])
        retriever = NearestNeighbors(n_neighbors=self.n_neighbors, algorithm='brute', metric='cosine')
        retriever.fit(tfidf_matrix)
        return retriever

    def _find_similar_examples(self, new_log_entry):
        query_vector = self.vectorizer.transform([new_log_entry])
        _, indices = self.retriever.kneighbors(query_vector)
        return self.knowledge_df.iloc[indices[0]]

    # In your RAGSecurityAnalyzer class...

    def analyze(self, new_log_entry):
        """
        Performs the full RAG process with a simplified, direct prompt.
        """
        print(f"\nAnalyzing new log entry: '{new_log_entry}'")
        try:
            # --- THIS IS THE MISSING LOGIC ---
            # 1. Retrieve similar examples
            similar_examples = self._find_similar_examples(new_log_entry)
            print(f"Found {len(similar_examples)} similar examples from knowledge base.")
            
            # 2. Build the prompt as a list of parts
            prompt_parts = []
            for index, row in similar_examples.iterrows():
                prompt_parts.append(f"Log: {row['log_entry']}\nAnalysis:\n{row['json_analysis']}")
            
            # Add the new log entry to complete the pattern
            prompt_parts.append(f"Log: {new_log_entry}\nAnalysis:")
            
            # Join the parts into the final prompt string
            final_prompt = "\n---\n".join(prompt_parts)
            # --- END OF MISSING LOGIC ---

            print("Querying LLM with simplified, direct prompt...")
            response = ollama.generate(
                model=self.model,
                prompt=final_prompt, # This variable now exists
                format='json'
            )
            
            raw_response_text = response['response']
            parsed_json = extract_json_from_string(raw_response_text)
            
            if parsed_json is None:
                print(f"An error occurred in RAGSecurityAnalyzer.analyze: Could not find valid JSON in the model's response.")
                print(f"Raw Response: {raw_response_text}")
                return None
            
            return parsed_json
            
        except Exception as e:
            print(f"An error occurred in RAGSecurityAnalyzer.analyze: {e}")
            traceback.print_exc()
            return None


# =====================================================================================
# --- Main Execution Block ---
# =====================================================================================
if __name__ == "__main__":
    # --- Configuration ---
    KNOWLEDGE_BASE_DIRECTORY = "/home/tejas/Projects/AIS/data/"
    INTERESTING_KEYWORDS = [
        "Login failed", 
        "User logged in",
        # You can keep old keywords to support multiple log types
        "Failed password", 
        "session opened",
    ]
    RAW_LOG_FILE_TO_ANALYZE = "/home/tejas/Projects/AIS/app.log"
    ANALYSIS_OUTPUT_FILE = "analysis_results.jsonl"
    RL_AGENT_PATH = "/home/tejas/Projects/AIS/ais_rl_agent_ppo.zip"
    # ----------------------------------------------------

    # Create a dummy log file
    # with open(RAW_LOG_FILE_TO_ANALYZE, "w") as f:
    #     f.write("Oct 10 14:35:10 my-server sshd: Failed password for invalid user 'admin' from 103.207.39.21\n")
    #     f.write("Oct 10 14:35:14 my-server sshd: session opened for user tejas\n")

    # --- Pipeline Execution ---
    try:
        log_parser = LogParser(keywords=INTERESTING_KEYWORDS)
        rag_analyzer = RAGSecurityAnalyzer(knowledge_base_dir=KNOWLEDGE_BASE_DIRECTORY)
        executor = Executor(dry_run=True)

        if not os.path.exists(RL_AGENT_PATH):
            raise FileNotFoundError(f"Trained RL Agent not found at: {RL_AGENT_PATH}")
        print(f"Loading trained RL agent from: {RL_AGENT_PATH}")
        rl_env = SecurityEnv()
        rl_agent = PPO.load(RL_AGENT_PATH, env=rl_env)
        print("RL Agent loaded successfully.")
        
        with open(ANALYSIS_OUTPUT_FILE, 'a') as output_log:
            important_events = log_parser.parse_log_file(RAW_LOG_FILE_TO_ANALYZE)
            print("\nStarting AI-driven analysis pipeline...")
            print("------------------------------------------------------")
            for event in important_events:
                final_analysis = rag_analyzer.analyze(event)
                if final_analysis:
                    output_log.write(json.dumps(final_analysis) + '\n')
                    observation = rl_env.get_obs_from_analysis(final_analysis)
                    action, _ = rl_agent.predict(observation, deterministic=True)
                    action_map = {0: "Do Nothing", 1: "Monitor", 2: "Block IP"}
                    chosen_action = action_map.get(int(action), "Unknown")
                    
                    print(f"Analyzed Event: '{event}'")
                    print(f"  - RAG Analysis: Risk=[{final_analysis.get('risk_level', 'N/A')}], Threat=[{final_analysis.get('threat_type', 'N/A')}]")
                    print(f"  - RL Agent Decision: Chose action '{chosen_action}'")
                    
                    if chosen_action == "Block IP":
                        print("  - Action: High-risk decision. Passing to Executor.")
                        executor.process_actions(final_analysis)
                    elif chosen_action == "Monitor":
                        print("  - Action: Monitoring.")
                else:
                    print(f"Analysis failed for event: '{event}'")
                print("---")

    except Exception as e:
        print(f"\nAn unexpected error occurred during pipeline execution: {e}")
        traceback.print_exc()