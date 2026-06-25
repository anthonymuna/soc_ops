import os
import time
import math
import google.generativeai as genai
from sqlalchemy.orm import Session
from typing import List, Dict, Any, Tuple
from app.database.models import DocumentChunk, AuditLog, Hymn
from app.services.embedding import EmbeddingService

class MethodistRAGEngine:
    """
    Core RAG Engine for the Methodist Church Kenya.
    Coordinates embedding search, context retrieval, API calls,
    and enforces strict citation rules and hallucination safety blocks.
    """
    
    def __init__(self, db_session: Session):
        self.db = db_session
        self.embedding_service = EmbeddingService()
        
        # Configure Gemini API
        api_key = os.getenv("GEMINI_API_KEY", "")
        if api_key:
            genai.configure(api_key=api_key)
            self.model = genai.GenerativeModel('gemini-1.5-flash')
            self.has_llm = True
        else:
            self.model = None
            self.has_llm = False
            print("GEMINI_API_KEY not configured. Running RAG in dry-run mode.")

    def retrieve_context(self, query: str, top_k: int = 4) -> List[Tuple[DocumentChunk, float]]:
        """
        Retrieves the most semantically relevant chunks from the database.
        Detects if database dialect is SQLite or PostgreSQL and acts accordingly.
        """
        query_embedding = self.embedding_service.get_embedding(query)
        
        # Determine database dialect
        dialect_name = self.db.bind.dialect.name
        
        if dialect_name == "postgresql":
            # Direct pgvector HNSW similarity query
            sql = """
                SELECT id, document_id, chunk_index, content, citation_tag, embedding, metadata_json,
                       (embedding <=> :query_vector::vector) as distance
                FROM document_chunks
                ORDER BY distance ASC
                LIMIT :top_k
            """
            result = self.db.execute(sql, {"query_vector": query_embedding, "top_k": top_k}).fetchall()
            
            retrieved = []
            for row in result:
                # Reconstruct chunk model
                chunk = DocumentChunk(
                    id=row[0],
                    document_id=row[1],
                    chunk_index=row[2],
                    content=row[3],
                    citation_tag=row[4],
                    metadata_json=row[6]
                )
                # Distance is (1 - cosine_similarity), so score is 1 - distance
                score = 1.0 - float(row[7])
                retrieved.append((chunk, score))
            return retrieved

        else:
            # Fallback for SQLite / Local deployment: Use basic token overlap (BM25-lite) in pure Python
            all_chunks = self.db.query(DocumentChunk).all()
            
            # Incorporate Hymns directly into the RAG context!
            all_hymns = self.db.query(Hymn).all()
            for h in all_hymns:
                # Wrap hymn in a mock DocumentChunk for unified searching
                mock_chunk = DocumentChunk(
                    content=h.lyrics,
                    citation_tag=f"Hymn {h.hymn_number} ({h.language}) - {h.title}"
                )
                all_chunks.append(mock_chunk)

            if not all_chunks:
                return []
                
            # Tokenize query
            query_tokens = set(word.lower() for word in query.replace('.', ' ').replace(',', ' ').split() if len(word) > 0)
            if not query_tokens:
                query_tokens = set([query.lower()])
                
            scored_chunks = []
            
            for chunk in all_chunks:
                # Tokenize chunk content
                content_tokens = set(word.lower() for word in chunk.content.replace('.', ' ').replace(',', ' ').split() if len(word) > 0)
                
                # Calculate simple Jaccard-like overlap score
                intersection = query_tokens.intersection(content_tokens)
                
                # Boost score if words appear in citation tag (e.g. title)
                tag_tokens = set(word.lower() for word in chunk.citation_tag.replace('.', ' ').replace(',', ' ').split())
                tag_intersection = query_tokens.intersection(tag_tokens)
                
                score = (len(intersection) * 1.0) + (len(tag_intersection) * 3.0)
                
                if score > 0:
                    scored_chunks.append((chunk, float(score)))
                
            # Sort by similarity score descending
            scored_chunks.sort(key=lambda x: x[1], reverse=True)
            return scored_chunks[:top_k]

    def generate_answer(self, user_id: str, query: str) -> Dict[str, Any]:
        """
        Executes semantic retrieval and prompts Gemini to answer using ONLY retrieved facts.
        """
        start_time = time.time()
        
        # 1. Retrieve relevant source materials
        retrieved_items = self.retrieve_context(query)
        
        # Fallback if no matching records in database
        if not retrieved_items:
            response_text = "I could not find an official Methodist source for that."
            citations = []
            latency = int((time.time() - start_time) * 1000)
            
            # Log audit trail
            self._log_audit(user_id, query, response_text, citations, latency)
            return {
                "response": response_text,
                "citations": citations,
                "uncertainty_flag": True
            }

        # 2. Build prompt context
        context_blocks = []
        citations = []
        for idx, (chunk, score) in enumerate(retrieved_items):
            ref_id = idx + 1
            context_blocks.append(
                f"Source [{ref_id}]: {chunk.citation_tag}\n"
                f"Content: {chunk.content}\n"
                f"Relevance Score: {score:.2f}"
            )
            citations.append({
                "index": ref_id,
                "citation_tag": chunk.citation_tag,
                "snippet": chunk.content,
                "score": score
            })
            
        context_str = "\n\n".join(context_blocks)
        
        # 3. Strictly instruct Gemini
        system_instruction = """
        You are the official AI Assistant for the Methodist Church Kenya (MCK).
        Your task is to answer the user's question using ONLY the provided sources.
        
        STRICT RULES:
        1. You are strictly forbidden from answering using outside knowledge.
        2. If the provided sources do not contain the answer, you MUST reply EXACTLY with:
           "I could not find an official Methodist source for that." Do not say anything else.
        3. Do not invent details, scriptures, policies, or events not mentioned in the source context.
        4. Do not supplement the text with outside knowledge unless referencing common knowledge about spelling.
        5. You must include bracketed citations in your text referencing the sources (e.g. [1] or [2]).
        6. If the user asks in Swahili, translate the answer to Swahili, but ensure scripture references and quotes remain accurate.
        7. If the user asks for a Hymn, simply output the lyrics from the sources perfectly.
        """

        prompt = f"""
        {system_instruction}
        
        --- CONTEXT SOURCES ---
        {context_str}
        
        --- USER QUESTION ---
        {query}
        
        Answer:
        """
        
        # 4. Invoke LLM or simulate for dry-run
        is_uncertain = False
        if self.has_llm:
            try:
                response = self.model.generate_content(
                    prompt, 
                    generation_config=genai.types.GenerationConfig(temperature=0.0)
                )
                response_text = response.text.strip()
            except Exception as e:
                response_text = f"Error calling Gemini: {e}"
                is_uncertain = True
        else:
            # Full semantic search fallback for local/offline testing when API key is missing
            if retrieved_items:
                best_chunk, score = retrieved_items[0]
                response_text = f"{best_chunk.citation_tag}\n\n{best_chunk.content}"
            else:
                response_text = "I could not find an official Methodist source for that."
            is_uncertain = False

        # 5. Hallucination check
        if "I could not find an official Methodist source for that." in response_text or is_uncertain:
            response_text = "I could not find an official Methodist source for that."
            citations = []
            is_uncertain = True

        latency = int((time.time() - start_time) * 1000)
        
        # 6. Log audit trail
        self._log_audit(user_id, query, response_text, citations, latency)
        
        return {
            "response": response_text,
            "citations": citations,
            "uncertainty_flag": is_uncertain
        }

    def _log_audit(self, user_id: str, query: str, response: str, citations: List[Dict], latency: int):
        try:
            log = AuditLog(
                user_id=user_id,
                user_query=query,
                ai_response=response,
                citations=citations,
                is_flagged=("I could not find" in response),
                latency_ms=latency
            )
            self.db.add(log)
            self.db.commit()
        except Exception as e:
            print(f"Failed to write audit log: {e}")
            self.db.rollback()
        # Clean session so we don't hold state
        self.db.close()
