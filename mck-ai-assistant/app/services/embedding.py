import os
import random
import math
import hashlib
import google.generativeai as genai
from typing import List

class EmbeddingService:
    """
    Generates semantic vector embeddings.
    Supports:
    - Gemini API ('text-embedding-004') - 768 dimensions.
    - Fallback stable pseudo-random vector hashing for dry runs and testing in pure Python.
    """
    
    def __init__(self):
        self.api_key = os.getenv("GEMINI_API_KEY", "")
        if self.api_key:
            genai.configure(api_key=self.api_key)
            self.use_api = True
        else:
            self.use_api = False
            print("GEMINI_API_KEY not configured. Falling back to local pseudo-embeddings.")

    def get_embedding(self, text: str) -> List[float]:
        """
        Generates embedding for a single string.
        """
        if self.use_api:
            try:
                response = genai.embed_content(
                    model="models/text-embedding-004",
                    content=text,
                    task_type="retrieval_document"
                )
                return response['embedding']
            except Exception as e:
                print(f"Gemini embedding API call failed: {e}. Falling back to pseudo-embedding.")
                
        # Robust pseudo-random hash embedding fallback (768 dimensions)
        # Seeded by the text content to make it deterministic (same text = same vector)
        return self._generate_pseudo_embedding(text)

    def get_embeddings(self, texts: List[str]) -> List[List[float]]:
        """
        Generates embeddings for a batch of strings.
        """
        if self.use_api and len(texts) > 0:
            try:
                response = genai.embed_content(
                    model="models/text-embedding-004",
                    content=texts,
                    task_type="retrieval_document"
                )
                return response['embeddings']
            except Exception as e:
                print(f"Gemini batch embedding API call failed: {e}. Falling back to pseudo-embeddings.")

        return [self._generate_pseudo_embedding(t) for t in texts]

    def _generate_pseudo_embedding(self, text: str, dimensions: int = 768) -> List[float]:
        """
        Deterministic pseudo-embedding for testing and offline fallback in pure Python.
        Ensures exact same text returns exact same vector.
        """
        # Create a stable seed using MD5 to be consistent across different processes
        seed = int(hashlib.md5(text.encode('utf-8')).hexdigest(), 16) & 0xffffffff
        rng = random.Random(seed)
        vec = [rng.gauss(0.0, 1.0) for _ in range(dimensions)]
        
        # Normalize the vector to unit length
        norm = math.sqrt(sum(x * x for x in vec))
        if norm > 0:
            vec = [x / norm for x in vec]
        return vec
