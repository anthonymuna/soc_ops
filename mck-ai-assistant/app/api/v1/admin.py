import os
import shutil
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from sqlalchemy.orm import Session
from typing import Optional
from app.database.session import get_db
from app.database.models import Document, DocumentChunk
from app.services.ocr_pipeline import DocumentIngestionPipeline
from app.services.chunker import HierarchicalChurchChunker
from app.services.embedding import EmbeddingService
from app.auth.dependencies import require_role

router = APIRouter(prefix="/admin", tags=["admin"])

@router.post("/upload", dependencies=[Depends(require_role(["admin"]))])
async def upload_document(
    title: str = Form(...),
    category: str = Form(...),  # standing_orders, hymn_book, bible, constitution, liturgy, sermon, circular
    language: str = Form("en"),  # en, sw, kik
    version: Optional[str] = Form(None),
    published_year: Optional[int] = Form(None),
    is_official: bool = Form(True),
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    # Ensure temporary upload directory exists
    os.makedirs("./temp_uploads", exist_ok=True)
    
    file_path = f"./temp_uploads/{file.filename}"
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
        
    try:
        # 1. OCR / Text Extraction
        pipeline = DocumentIngestionPipeline()
        extracted_text, method = pipeline.process_file(file_path)
        
        if not extracted_text.strip():
            raise HTTPException(status_code=400, detail="Failed to extract any text from the document.")

        # 2. Save Document metadata in database
        doc_record = Document(
            title=title,
            category=category,
            language=language,
            version=version,
            published_year=published_year,
            is_official=is_official,
            file_path=file_path
        )
        db.add(doc_record)
        db.commit()
        db.refresh(doc_record)

        # 3. Chunk text hierarchically
        chunks = HierarchicalChurchChunker.chunk_document(category, extracted_text)
        
        # 4. Generate embeddings and save to DB
        embedding_service = EmbeddingService()
        
        # Batch insert chunks for performance
        db_chunks = []
        for idx, ch in enumerate(chunks):
            vector = embedding_service.get_embedding(ch["content"])
            db_chunk = DocumentChunk(
                document_id=doc_record.id,
                chunk_index=idx,
                content=ch["content"],
                citation_tag=ch["citation_tag"],
                embedding=vector,
                metadata_json=ch.get("metadata", {})
            )
            db_chunks.append(db_chunk)
            
        db.bulk_save_objects(db_chunks)
        db.commit()
        
        # Auto-populate Hymn table if category is hymn_book to ensure instant search index matches
        if category == "hymn_book":
            from app.database.models import Hymn
            hymns_to_add = []
            for ch in chunks:
                hymn_num = ch.get("metadata", {}).get("hymn_number")
                # Skip preambles or intro chunks (index 0)
                if hymn_num and hymn_num > 0:
                    lines = [line.strip() for line in ch["content"].split("\n") if line.strip()]
                    if len(lines) >= 2:
                        hymn_title = lines[1]
                        hymn_lyrics = "\n".join(lines[1:])
                    else:
                        hymn_title = ch["citation_tag"]
                        hymn_lyrics = ch["content"]
                        
                    if len(hymn_title) > 100:
                        hymn_title = hymn_title[:97] + "..."
                        
                    # Check duplicate in Hymn table
                    existing_hymn = db.query(Hymn).filter(
                        Hymn.hymn_number == hymn_num,
                        Hymn.language == language
                    ).first()
                    
                    if not existing_hymn:
                        h_rec = Hymn(
                            hymn_number=hymn_num,
                            title=hymn_title,
                            language=language,
                            lyrics=hymn_lyrics
                        )
                        hymns_to_add.append(h_rec)
            if hymns_to_add:
                db.bulk_save_objects(hymns_to_add)
                db.commit()
        
        return {
            "status": "success",
            "message": f"Successfully ingested document '{title}'. Created {len(chunks)} chunks using method '{method}'.",
            "document_id": doc_record.id,
            "chunks_count": len(chunks)
        }
        
    except Exception as e:
        db.rollback()
        # Clean up file on failure
        if os.path.exists(file_path):
            os.remove(file_path)
        raise HTTPException(status_code=500, detail=f"Failed to process document: {str(e)}")
