import ollama
import json
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.neighbors import NearestNeighbors
import os

class RAGSecurityAnalyzer:
    def __init__(self, knowledge_base_paths, llm_model='phi3:mini', n_neighbors=3):
        """
        Initializes the RAG analyzer.
        Args:
            knowledge_base_paths (list): A list of file paths to the .jsonl knowledge base files.
            llm_model (str): The name of the Ollama model to use.
            n_neighbors (int): The number of similar examples to retrieve.
        """
        self.model = llm_model
        self.n_neighbors = n_neighbors
        print("--- Initializing RAG Security Analyzer ---")

        # 1. Load the knowledge base from all provided files
        self.knowledge_df = self._load_knowledge_base(knowledge_base_paths)
        if self.knowledge_df.empty:
            raise ValueError("Knowledge base is empty. Please check your file paths.")

        # 2. Build the retriever
        self.retriever = self._build_retriever()
        print(f"Analyzer is ready. Using '{self.model}' with a knowledge base of {len(self.knowledge_df)} examples.")

    def _load_knowledge_base(self, file_paths):
        """Loads and parses the .jsonl files into a pandas DataFrame."""
        all_records = []
        print(f"Loading knowledge from: {file_paths}")
        for path in file_paths:
            if not os.path.exists(path):
                print(f"WARNING: File not found at '{path}'. Skipping.")
                continue
            with open(path, 'r') as f:
                for line in f:
                    data = json.loads(line)
                    # We need the user's log entry for searching, and the assistant's JSON for the example
                    log_entry = data['messages'][1]['content']
                    json_analysis = data['messages'][2]['content']
                    all_records.append({'log_entry': log_entry, 'json_analysis': json_analysis})
        return pd.DataFrame(all_records)

    def _build_retriever(self):
        """
        Builds a TF-IDF vectorizer and a NearestNeighbors model to act as our search engine.
        TF-IDF is great for this because it finds documents with similar keywords (like srcip, protocol, etc.).
        """
        print("Building the retriever...")
        # The vectorizer turns text into numerical vectors
        self.vectorizer = TfidfVectorizer(min_df=5, stop_words='english')
        tfidf_matrix = self.vectorizer.fit_transform(self.knowledge_df['log_entry'])
        
        # The model finds the nearest neighbors in that vector space
        retriever = NearestNeighbors(n_neighbors=self.n_neighbors, algorithm='brute', metric='cosine')
        retriever.fit(tfidf_matrix)
        return retriever

    def _find_similar_examples(self, new_log_entry):
        """Finds the most similar log entries from the knowledge base."""
        # Convert the new log into a TF-IDF vector
        query_vector = self.vectorizer.transform([new_log_entry])
        # Find the nearest neighbors
        distances, indices = self.retriever.kneighbors(query_vector)
        # Return the corresponding rows from our DataFrame
        return self.knowledge_df.iloc[indices[0]]

    def analyze(self, new_log_entry):
        """
        Performs the full RAG process: retrieve, build prompt, and query the LLM.
        """
        print(f"\n--- Analyzing new log entry: ---\n{new_log_entry}\n")

        # 1. Retrieve similar examples
        similar_examples = self._find_similar_examples(new_log_entry)
        print(f"--- Found {len(similar_examples)} similar examples from knowledge base ---")

        # 2. Build the detailed "mega-prompt"
        prompt_template = """You are a precise cybersecurity analyst. Your task is to analyze a log entry and respond ONLY with a structured JSON object. Use the following examples as a guide for format and content.

---
### Similar Examples
{examples}
---
### New Log for Analysis
**Log:** "{new_log}"
**Analysis:**
```json
"""
        example_prompts = []
        for index, row in similar_examples.iterrows():
            example_prompts.append(f"**Log:** \"{row['log_entry']}\"\n**Analysis:**\n```json\n{row['json_analysis']}\n```")
        
        final_prompt = prompt_template.format(
            examples="\n---\n".join(example_prompts),
            new_log=new_log_entry
        )

        # 3. Query the LLM with the rich prompt
        print("--- Querying LLM with augmented prompt... ---")
        try:
            response = ollama.chat(
                model=self.model,
                messages=[{'role': 'user', 'content': final_prompt}],
                format='json' # Ask Ollama to ensure the output is valid JSON
            )
            return json.loads(response['message']['content'])
        except Exception as e:
            print(f"An error occurred while querying Ollama: {e}")
            return None

# =====================================================================================
# --- EXAMPLE USAGE ---
# =====================================================================================
if __name__ == "__main__":

    KNOWLEDGE_BASE_FILES = [
        '/home/tejas/Projects/AIS/data/UNSW_finetuning.jsonl',
        '/home/tejas/Projects/AIS/data/dtst.jsonl',
        '/home/tejas/Projects/AIS/data/mordor_finetuning.jsonl'
    ]
    # ----------------------------------------------------

    # Check if any files exist before initializing
    existing_files = [f for f in KNOWLEDGE_BASE_FILES if os.path.exists(f)]
    if not existing_files:
        print("CRITICAL ERROR: No knowledge base files found. Please check the KNOWLEDGE_BASE_FILES list.")
    else:
        # Initialize the analyzer
        analyzer = RAGSecurityAnalyzer(knowledge_base_paths=existing_files, llm_model='phi3:mini')

        # --- Test Cases ---
        log1 = input('Enter your first problem of the system')
        analysis1 = analyzer.analyze(log1)
        if analysis1:
            print("\n--- Final Analysis (Log 1) ---")
            print(json.dumps(analysis1, indent=2))

        log2 = input('Enter your problem in the system')
        analysis2 = analyzer.analyze(log2)
        if analysis2:
            print("\n--- Final Analysis (Log 2) ---")
            print(json.dumps(analysis2, indent=2))