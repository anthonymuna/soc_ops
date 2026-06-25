import re
from typing import List, Dict, Any

class HierarchicalChurchChunker:
    """
    Parses and chunks structured church documents:
    - Standing Orders: Chunks split by specific standing order numbers (e.g. "Standing Order 45").
    - Hymn books: Chunks split by hymn numbers (e.g. "Hymn 23").
    - Bible: Chunks split by chapters (e.g. "Genesis Chapter 1").
    - General documents: Standard paragraph/heading splitting.
    """
    
    @staticmethod
    def chunk_standing_orders(text: str) -> List[Dict[str, Any]]:
        # Matches "Standing Order 45" or "S.O. 45"
        pattern = r"(Standing\s+Order\s+\d+|S\.O\.\s+\d+)"
        parts = re.split(pattern, text, flags=re.IGNORECASE)
        
        chunks = []
        if len(parts) < 2:
            # Fallback to paragraph splitting
            paragraphs = [p.strip() for p in text.split("\n\n") if p.strip()]
            for idx, para in enumerate(paragraphs):
                chunks.append({
                    "content": para,
                    "citation_tag": "Standing Orders Section",
                    "metadata": {"paragraph_index": idx}
                })
            return chunks
        
        # Lead-in content before the first matched pattern
        lead_in = parts[0].strip()
        if lead_in:
            chunks.append({
                "content": lead_in,
                "citation_tag": "Standing Orders Preamble",
                "metadata": {"so_number": 0}
            })

        # Interleaved matching
        for i in range(1, len(parts), 2):
            header = parts[i].strip()
            body = parts[i+1].strip() if i+1 < len(parts) else ""
            
            # Extract Standing Order number
            num_match = re.search(r"\d+", header)
            so_number = int(num_match.group()) if num_match else None
            
            chunks.append({
                "content": f"{header}\n{body}",
                "citation_tag": header,
                "metadata": {
                    "so_number": so_number,
                    "category": "standing_orders"
                }
            })
        return chunks

    @staticmethod
    def chunk_hymns(text: str) -> List[Dict[str, Any]]:
        # Matches "Hymn 23" or "Wimbo 23" or similar
        pattern = r"((?:Hymn|Wimbo|Song)\s+\d+)"
        parts = re.split(pattern, text, flags=re.IGNORECASE)
        
        chunks = []
        if len(parts) < 2:
            paragraphs = [p.strip() for p in text.split("\n\n") if p.strip()]
            for idx, para in enumerate(paragraphs):
                chunks.append({
                    "content": para,
                    "citation_tag": "Hymn Content",
                    "metadata": {"paragraph_index": idx}
                })
            return chunks

        lead_in = parts[0].strip()
        if lead_in:
            chunks.append({
                "content": lead_in,
                "citation_tag": "Hymn Book Intro",
                "metadata": {"hymn_number": 0}
            })

        for i in range(1, len(parts), 2):
            header = parts[i].strip()
            body = parts[i+1].strip() if i+1 < len(parts) else ""
            
            num_match = re.search(r"\d+", header)
            hymn_number = int(num_match.group()) if num_match else None
            
            chunks.append({
                "content": f"{header}\n{body}",
                "citation_tag": header,
                "metadata": {
                    "hymn_number": hymn_number,
                    "category": "hymn_book"
                }
            })
        return chunks

    @staticmethod
    def chunk_bible(text: str) -> List[Dict[str, Any]]:
        # Matches "Chapter 1" or "Mlango 1"
        pattern = r"((?:Chapter|Mlango)\s+\d+)"
        parts = re.split(pattern, text, flags=re.IGNORECASE)
        
        chunks = []
        if len(parts) < 2:
            paragraphs = [p.strip() for p in text.split("\n\n") if p.strip()]
            for idx, para in enumerate(paragraphs):
                chunks.append({
                    "content": para,
                    "citation_tag": "Bible Fragment",
                    "metadata": {"paragraph_index": idx}
                })
            return chunks

        lead_in = parts[0].strip()
        if lead_in:
            chunks.append({
                "content": lead_in,
                "citation_tag": "Bible Book Intro",
                "metadata": {"chapter": 0}
            })

        for i in range(1, len(parts), 2):
            header = parts[i].strip()
            body = parts[i+1].strip() if i+1 < len(parts) else ""
            
            num_match = re.search(r"\d+", header)
            chapter_number = int(num_match.group()) if num_match else None
            
            chunks.append({
                "content": f"{header}\n{body}",
                "citation_tag": header,
                "metadata": {
                    "chapter": chapter_number,
                    "category": "bible"
                }
            })
        return chunks

    @staticmethod
    def chunk_general(text: str, chunk_size: int = 1500, overlap: int = 200) -> List[Dict[str, Any]]:
        # Standard character-based sliding-window chunking for general documents
        chunks = []
        start = 0
        text_len = len(text)
        
        chunk_idx = 0
        while start < text_len:
            end = min(start + chunk_size, text_len)
            content = text[start:end]
            
            chunks.append({
                "content": content.strip(),
                "citation_tag": f"General Page Reference (Part {chunk_idx + 1})",
                "metadata": {"chunk_index": chunk_idx}
            })
            
            if end == text_len:
                break
            start += chunk_size - overlap
            chunk_idx += 1
            
        return chunks

    @classmethod
    def chunk_document(cls, category: str, text: str) -> List[Dict[str, Any]]:
        if category == "standing_orders":
            return cls.chunk_standing_orders(text)
        elif category == "hymn_book":
            return cls.chunk_hymns(text)
        elif category == "bible":
            return cls.chunk_bible(text)
        else:
            return cls.chunk_general(text)
