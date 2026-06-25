import sys
import os

# Append the current working directory to sys.path
sys.path.append(os.getcwd())

from sqlalchemy.orm import Session
from app.database.session import SessionLocal
from app.database.models import Hymn, Document, DocumentChunk
from app.services.embedding import EmbeddingService

def generate_hymns(db: Session, language: str, count: int, prefix: str):
    print(f"Generating {count} hymns for {language}...")
    existing_hymns = db.query(Hymn).filter(Hymn.language == language).count()
    if existing_hymns >= count:
        print(f"Hymns for {language} already seeded.")
        return

    hymns = []
    for i in range(1, count + 1):
        # We only generate missing hymns
        if db.query(Hymn).filter(Hymn.hymn_number == i, Hymn.language == language).first():
            continue
            
        lyrics = f"{prefix} {i}\n{prefix} Title {i}\nVerse 1 of {prefix} {i}: Praise the Lord in {language}.\nVerse 2: Let all the earth rejoice.\nVerse 3: Amen and Amen."
        h = Hymn(
            hymn_number=i,
            title=f"{prefix} Title {i}",
            language=language,
            lyrics=lyrics
        )
        hymns.append(h)
        
    if hymns:
        db.bulk_save_objects(hymns)
        db.commit()

def generate_bible(db: Session, embedding_service: EmbeddingService, language: str, b_name: str, prefix: str):
    print(f"Generating {b_name} ({language})...")
    doc = db.query(Document).filter(Document.title == b_name, Document.language == language).first()
    if not doc:
        doc = Document(
            title=b_name,
            category="bible",
            language=language,
            is_official=True
        )
        db.add(doc)
        db.commit()
        db.refresh(doc)
    else:
        # Check if chunks exist
        if db.query(DocumentChunk).filter(DocumentChunk.document_id == doc.id).count() > 0:
            print(f"{b_name} chunks already exist.")
            return

    books = [
        "Genesis", "Exodus", "Leviticus", "Numbers", "Deuteronomy", 
        "Joshua", "Judges", "Ruth", "1 Samuel", "2 Samuel", 
        "1 Kings", "2 Kings", "1 Chronicles", "2 Chronicles", "Ezra", 
        "Nehemiah", "Esther", "Job", "Psalms", "Proverbs", 
        "Ecclesiastes", "Song of Solomon", "Isaiah", "Jeremiah", "Lamentations", 
        "Ezekiel", "Daniel", "Hosea", "Joel", "Amos", 
        "Obadiah", "Jonah", "Micah", "Nahum", "Habakkuk", 
        "Zephaniah", "Haggai", "Zechariah", "Malachi",
        "Matthew", "Mark", "Luke", "John", "Acts", 
        "Romans", "1 Corinthians", "2 Corinthians", "Galatians", "Ephesians", 
        "Philippians", "Colossians", "1 Thessalonians", "2 Thessalonians", "1 Timothy", 
        "2 Timothy", "Titus", "Philemon", "Hebrews", "James", 
        "1 Peter", "2 Peter", "1 John", "2 John", "3 John", 
        "Jude", "Revelation"
    ]

    chunks = []
    chunk_idx = 0
    
    # Generate common verse for semantic search testing
    common_verse = "For God so loved the world, that he gave his only begotten Son."
    if language == "sw":
        common_verse = "Kwa maana jinsi hii Mungu aliupenda ulimwengu, hata akamtoa Mwanawe pekee."
    elif language == "kik":
        common_verse = "Nĩ gũkorũo Ngai nĩendire thĩ, nginya akĩheana Mũrũwe ũrĩa wa mũmwe."

    for book in books:
        # 3 chapters per book for demo
        for chapter in range(1, 4):
            ch_title = f"{book} {prefix} {chapter}"
            content = f"{ch_title}\nVerse 1: In the beginning of {book} chapter {chapter}.\nVerse 2: {common_verse}\nVerse 3: And it came to pass in the land.\nVerse 4: Praise be to God forever."
            
            vector = embedding_service.get_embedding(content)
            
            c = DocumentChunk(
                document_id=doc.id,
                chunk_index=chunk_idx,
                content=content,
                citation_tag=ch_title,
                embedding=vector,
                metadata_json={"book": book, "chapter": chapter, "category": "bible"}
            )
            chunks.append(c)
            chunk_idx += 1
            
            if len(chunks) >= 500:
                db.bulk_save_objects(chunks)
                db.commit()
                chunks = []
                
    if chunks:
        db.bulk_save_objects(chunks)
        db.commit()

def run_extended_seed():
    db = SessionLocal()
    try:
        embedding_service = EmbeddingService()
        
        # Hymns (1 to 500 for each language)
        generate_hymns(db, "en", 500, "Hymn")
        generate_hymns(db, "sw", 500, "Wimbo")
        generate_hymns(db, "kik", 500, "Rwimbo")
        
        # Bibles
        generate_bible(db, embedding_service, "en", "King James Version (KJV)", "Chapter")
        generate_bible(db, embedding_service, "sw", "Swahili Union Version (SUV)", "Mlango")
        generate_bible(db, embedding_service, "kik", "Kikuyu Bible (KBB)", "Gĩcigo")
        
        print("Extended seeding completed successfully!")
    finally:
        db.close()

if __name__ == "__main__":
    run_extended_seed()
