import ollama
import json
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.neighbors import NearestNeighbors
import os
import glob
import traceback

class LLMRAGAnalyzer:
    """
    A powerful security log analyzer that uses a true Retrieval-Augmented
    Generation (RAG) pipeline with an LLM.
    """
    def __init__(self, knowledge_base_dir: str, llm_model: str = 'phi3:mini', n_neighbors: int = 3):
        self.model = llm_model
        self.n_neighbors = n_neighbors
        print("Initializing LLM-based RAG Security Analyzer...")
        
        knowledge_base_paths = glob.glob(os.path.join(knowledge_base_dir, '*.jsonl'))
        if not knowledge_base_paths:
            raise ValueError(f"No .jsonl files found in directory: {knowledge_base_dir}")
            
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

    def analyze(self, log_entry: str):
        print(f"\nAnalyzing log entry with LLM-RAG: '{log_entry}'")
        try:
            similar_examples = self._find_similar_examples(log_entry)
            prompt_parts = []
            for _, row in similar_examples.iterrows():
                prompt_parts.append(f"Log: {row['log_entry']}\nAnalysis:\n{row['json_analysis']}")
            prompt_parts.append(f"Log: {log_entry}\nAnalysis:")
            final_prompt = "\n---\n".join(prompt_parts)
            
            print("Querying LLM with simplified, direct prompt...")
            response = ollama.generate(model=self.model, prompt=final_prompt, format='json')
            
            # Use a helper to safely extract JSON
            return self._extract_json_from_string(response['response'])
            
        except Exception as e:
            print(f"An error occurred in LLMRAGAnalyzer.analyze: {e}")
            traceback.print_exc()
            return None

    def _extract_json_from_string(self, text):
        start_index = text.find('{')
        end_index = text.rfind('}')
        if start_index != -1 and end_index != -1 and end_index > start_index:
            json_str = text[start_index:end_index+1]
            try:
                return json.loads(json_str)
            except json.JSONDecodeError:
                print(f"Could not decode JSON from response fragment: {json_str}")
                return None
        print(f"No JSON object found in response: {text}")
        return None