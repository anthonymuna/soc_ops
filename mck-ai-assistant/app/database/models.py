import uuid
import json
from sqlalchemy import Column, String, Integer, Boolean, ForeignKey, DateTime, Text, JSON, TypeDecorator
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.database.session import Base
from app.config import settings

# Custom type decorator to support pgvector on Postgres and JSON on SQLite
class SafeEmbedding(TypeDecorator):
    impl = Text
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            try:
                from pgvector.sqlalchemy import Vector
                return dialect.type_descriptor(Vector(1024))
            except ImportError:
                return dialect.type_descriptor(JSON)
        return dialect.type_descriptor(JSON)

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if dialect.name == "postgresql":
            # If pgvector is installed, bind directly as list
            return value
        # Otherwise, serialize as JSON string for SQLite/others
        return json.dumps(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if dialect.name == "postgresql":
            return value
        if isinstance(value, str):
            return json.loads(value)
        return value

class User(Base):
    __tablename__ = "users"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=False)
    role = Column(String(50), default="member")  # member, minister, admin
    synod = Column(String(100), nullable=True)
    circuit = Column(String(100), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

class Document(Base):
    __tablename__ = "documents"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = Column(String(255), nullable=False)
    category = Column(String(100), nullable=False) # standing_orders, hymn_book, bible, etc.
    version = Column(String(50), nullable=True)
    published_year = Column(Integer, nullable=True)
    language = Column(String(10), default="en")
    file_path = Column(String(512), nullable=True)
    is_official = Column(Boolean, default=True)
    uploaded_by = Column(String(36), ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    chunks = relationship("DocumentChunk", back_populates="document", cascade="all, delete-orphan")

class DocumentChunk(Base):
    __tablename__ = "document_chunks"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    document_id = Column(String(36), ForeignKey("documents.id", ondelete="CASCADE"), nullable=False)
    chunk_index = Column(Integer, nullable=False)
    content = Column(Text, nullable=False)
    citation_tag = Column(String(255), nullable=False)
    embedding = Column(SafeEmbedding, nullable=False)
    metadata_json = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    document = relationship("Document", back_populates="chunks")

class Hymn(Base):
    __tablename__ = "hymns"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    hymn_number = Column(Integer, nullable=False, index=True)
    title = Column(String(255), nullable=False)
    language = Column(String(10), nullable=False) # en, sw, kik
    lyrics = Column(Text, nullable=False)
    sheet_music_url = Column(String(512), nullable=True)
    audio_midi_url = Column(String(512), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    user_query = Column(Text, nullable=False)
    ai_response = Column(Text, nullable=False)
    citations = Column(JSON, default=list)
    is_flagged = Column(Boolean, default=False)
    moderation_reason = Column(String(255), nullable=True)
    latency_ms = Column(Integer, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
