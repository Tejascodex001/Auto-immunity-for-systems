# rag_analyzer.py (Final Version)

import ollama
import json
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.neighbors import NearestNeighbors
import os
import sys
import glob

# --- This section handles importing from your structured 'src/' directory ---
try:
    current_dir = os.path.dirname(os.path.abspath(__file__))
    # Go up one level from '/llm/' to '/src/'
    src_dir = os.path.dirname(current_dir)
    sys.path.append(src_dir)
    from executor.executor import Executor
    from log_parser.log_parser import LogParser
except (ImportError, ValueError):
    # This is a fallback in case the file structure is different
    print("Warning: Could not perform relative imports. Assuming all modules are in the same directory.")
    from executor import Executor
    from log_parser import LogParser


# =====================================================================================
# --- RAG Security Analyzer Class ---
# =====================================================================================
class RAGSecurityAnalyzer:
    def __init__(self, knowledge_base_dir, llm_model='phi3:mini', n_neighbors=3):
        """
        Initializes the RAG analyzer by automatically loading all .jsonl files
        from a specified directory.
        """
        self.model = llm_model
        self.n_neighbors = n_neighbors
        print("Initializing RAG Security Analyzer...")

        # Automatically find all files ending with .jsonl in the provided directory
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

    def analyze(self, new_log_entry):
        print(f"\nAnalyzing new log entry: '{new_log_entry}'")
        similar_examples = self._find_similar_examples(new_log_entry)
        print(f"Found {len(similar_examples)} similar examples from knowledge base.")
        prompt_parts = []
        for index, row in similar_examples.iterrows():
            prompt_parts.append(f"Log: {row['log_entry']}\nAnalysis:\n{row['json_analysis']}")
        prompt_parts.append(f"Log: {new_log_entry}\nAnalysis:")
        final_prompt = "\n---\n".join(prompt_parts)
        print("Querying LLM with simplified, direct prompt...")
        try:
            response = ollama.generate(model=self.model, prompt=final_prompt, format='json')
            return json.loads(response['response'])
        except Exception as e:
            print(f"An error occurred while querying Ollama: {e}")
            return None

# =====================================================================================
# --- Main Execution Block ---
# =====================================================================================
if __name__ == "__main__":
    # --- Configuration ---
    # Point to the single directory containing all your .jsonl knowledge base files.
    KNOWLEDGE_BASE_DIRECTORY = "/home/tejas/Projects/AIS/data/"
    INTERESTING_KEYWORDS = ["Failed password", "invalid user", "session opened", "command="]
    RAW_LOG_FILE_TO_ANALYZE = "auth.log"
    ANALYSIS_OUTPUT_FILE = "analysis_results.jsonl"
    # ----------------------------------------------------

    # Create a dummy log file for the example
    with open(RAW_LOG_FILE_TO_ANALYZE, "w") as f:
        f.write("Oct 10 14:35:10 my-server sshd: Failed password for invalid user 'admin' from 103.207.39.21\n")
        f.write("Oct 10 14:35:14 my-server sshd: session opened for user tejas\n")

    # --- Pipeline Execution ---
    try:
        # 1. Initialize all components
        log_parser = LogParser(keywords=INTERESTING_KEYWORDS)
        # Pass the directory to the analyzer
        rag_analyzer = RAGSecurityAnalyzer(knowledge_base_dir=KNOWLEDGE_BASE_DIRECTORY, llm_model='phi3:mini')
        executor = Executor(dry_run=True)

        # 2. Open the output file in "append" mode
        with open(ANALYSIS_OUTPUT_FILE, 'a') as output_log:
            # Get the stream of important events
            important_events = log_parser.parse_log_file(RAW_LOG_FILE_TO_ANALYZE)

            print("\nStarting automated analysis pipeline...")
            print(f"Full analysis results will be saved to '{ANALYSIS_OUTPUT_FILE}'")
            print("------------------------------------------------------")

            # 3. Process each event
            for event in important_events:
                final_analysis = rag_analyzer.analyze(event)
                
                if final_analysis:
                    # Concise logging to the terminal
                    summary = final_analysis.get('summary', 'No summary.')
                    risk = final_analysis.get('risk_level', 'UNKNOWN')
                    threat = final_analysis.get('threat_type', 'N/A')
                    print(f"Analyzed Event: Risk=[{risk}] Threat=[{threat}] Summary=[{summary}]")
                    
                    # Save full JSON to the output file
                    output_log.write(json.dumps(final_analysis) + '\n')
                    
                    # Pass to executor if high-risk
                    if risk.lower() in ['high', 'critical']:
                        print("High-Risk Event Detected. Passing to Executor.")
                        executor.process_actions(final_analysis)
                else:
                    print(f"Analysis failed for event: '{event}'")
                
                print("---") # Separator

    except Exception as e:
        print(f"\nAn unexpected error occurred during pipeline execution: {e}")