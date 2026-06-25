import io
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.main import app
from app.database.session import Base, get_db
from app.database.models import User, Document, DocumentChunk, Hymn, AuditLog


# Use file-based sqlite for testing to allow shared connection state
TEST_DATABASE_URL = "sqlite:///./test_church.db"
engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Override database dependency in FastAPI
def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

@pytest.fixture(name="client_db")
def fixture_client_db():
    Base.metadata.create_all(bind=engine)
    client = TestClient(app)
    db = TestingSessionLocal()
    try:
        yield client, db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)
        import os
        if os.path.exists("./test_church.db"):
            try:
                os.remove("./test_church.db")
            except Exception:
                pass

def test_api_workflow(client_db):
    client, db = client_db

    # 1. Register admin user
    reg_response = client.post("/api/v1/auth/register", json={
        "email": "admin@mck.or.ke",
        "password": "secureadminpass",
        "full_name": "MCK Conference Admin",
        "role": "admin"
    })
    assert reg_response.status_code == 200
    token_data = reg_response.json()
    assert "access_token" in token_data
    token = token_data["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Add a Hymn
    hymn_response = client.post("/api/v1/hymns", headers=headers, json={
        "hymn_number": 23,
        "title": "Bwana u sehemu yangu",
        "language": "sw",
        "lyrics": "Bwana u sehemu yangu, Kiongozi cha safari...",
    })
    assert hymn_response.status_code == 200
    assert hymn_response.json()["hymn_number"] == 23

    # 3. Search Hymn (Public)
    search_response = client.get("/api/v1/hymns?number=23&language=sw")
    assert search_response.status_code == 200
    assert len(search_response.json()) == 1
    assert "Kiongozi cha safari" in search_response.json()[0]["lyrics"]

    # 4. Upload a document (Simulating PDF upload via Python io)
    # We will upload a simple text-based text file representing a church circular/doc
    # Ingestion pipeline processes text-based uploads easily as well.
    doc_file = io.BytesIO(b"Standing Order 45 Local Preachers Qualification\n1. Candidates must pass Quarterly meetings.")
    upload_response = client.post(
        "/api/v1/admin/upload",
        headers=headers,
        data={
            "title": "Methodist Standing Orders 2018",
            "category": "standing_orders",
            "language": "en",
            "is_official": True
        },
        files={
            "file": ("standing_orders.txt", doc_file, "text/plain")
        }
    )
    assert upload_response.status_code == 200
    upload_data = upload_response.json()
    assert upload_data["status"] == "success"
    assert upload_data["chunks_count"] > 0

    # 5. Query the RAG engine via chat endpoint
    chat_response = client.post("/api/v1/chat", json={
        "message": "What is the requirement for local preachers in Standing Order 45?"
    })
    assert chat_response.status_code == 200
    chat_data = chat_response.json()
    
    # Assert citation tags and details are correct
    assert chat_data["uncertainty_flag"] is False
    assert len(chat_data["citations"]) > 0
    assert chat_data["citations"][0]["citation_tag"] == "Standing Order 45"
    assert "Mock" in chat_data["response"] or "preachers" in chat_data["response"].lower()
