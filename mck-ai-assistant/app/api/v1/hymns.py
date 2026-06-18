import re
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Optional
from app.database.session import get_db
from app.database.models import Hymn, DocumentChunk
from app.auth.dependencies import require_role

router = APIRouter(prefix="/hymns", tags=["hymns"])

class HymnCreate(BaseModel):
    hymn_number: int
    title: str
    language: str  # en, sw, kik, etc.
    lyrics: str
    sheet_music_url: Optional[str] = None
    audio_midi_url: Optional[str] = None

class HymnOut(BaseModel):
    id: str
    hymn_number: int
    title: str
    language: str
    lyrics: str
    sheet_music_url: Optional[str]
    audio_midi_url: Optional[str]

@router.post("", response_model=HymnOut, dependencies=[Depends(require_role(["admin"]))])
def create_hymn(hymn_data: HymnCreate, db: Session = Depends(get_db)):
    # Check if hymn already exists for that language
    existing = db.query(Hymn).filter(
        Hymn.hymn_number == hymn_data.hymn_number,
        Hymn.language == hymn_data.language
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"Hymn {hymn_data.hymn_number} already exists in language '{hymn_data.language}'.")

    hymn = Hymn(
        hymn_number=hymn_data.hymn_number,
        title=hymn_data.title,
        language=hymn_data.language,
        lyrics=hymn_data.lyrics,
        sheet_music_url=hymn_data.sheet_music_url,
        audio_midi_url=hymn_data.audio_midi_url
    )
    db.add(hymn)
    db.commit()
    db.refresh(hymn)
    return hymn

@router.get("", response_model=List[HymnOut])
def get_hymns(
    number: Optional[int] = Query(None, description="Hymn number to look up"),
    language: Optional[str] = Query(None, description="Filter by language (e.g. en, sw)"),
    search: Optional[str] = Query(None, description="Keyword search in lyrics or title"),
    db: Session = Depends(get_db)
):
    query = db.query(Hymn)
    
    if number is not None:
        query = query.filter(Hymn.hymn_number == number)
    if language is not None:
        query = query.filter(Hymn.language == language)
    if search is not None:
        # Simple case-insensitive exact keyword match
        query = query.filter(Hymn.lyrics.ilike(f"%{search}%") | Hymn.title.ilike(f"%{search}%"))
        
    results = query.order_by(Hymn.hymn_number).all()
    
    # If no results found, search in raw DocumentChunks as fallback
    if not results:
        chunk_query = db.query(DocumentChunk)
        
        if number is not None:
            chunk_query = chunk_query.filter(
                (DocumentChunk.citation_tag.ilike(f"%hymn {number}%")) |
                (DocumentChunk.citation_tag.ilike(f"%wimbo {number}%")) |
                (DocumentChunk.citation_tag.ilike(f"%song {number}%"))
            )
        else:
            # Match any hymn/wimbo/song category pattern
            chunk_query = chunk_query.filter(
                (DocumentChunk.citation_tag.ilike("%hymn%")) |
                (DocumentChunk.citation_tag.ilike("%wimbo%")) |
                (DocumentChunk.citation_tag.ilike("%song%"))
            )
            
        if search is not None:
            chunk_query = chunk_query.filter(DocumentChunk.content.ilike(f"%{search}%"))
            
        chunks = chunk_query.limit(20).all()
        
        fallback_results = []
        for ch in chunks:
            # Extract number from citation_tag (e.g. "Hymn 23" -> 23)
            num_match = re.search(r"\d+", ch.citation_tag)
            extracted_num = int(num_match.group()) if num_match else (number or 0)
            
            # Simple title extraction
            lines = [line.strip() for line in ch.content.split("\n") if line.strip()]
            title = lines[1] if len(lines) >= 2 else ch.citation_tag
            if len(title) > 100:
                title = title[:97] + "..."
                
            fallback_results.append(Hymn(
                id=ch.id,
                hymn_number=extracted_num,
                title=title,
                language=language or "en",
                lyrics=ch.content
            ))
        return fallback_results
        
    return results
