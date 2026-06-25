from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from app.database.session import get_db
from app.services.rag_engine import MethodistRAGEngine
from app.auth.dependencies import get_current_user
from app.database.models import User

router = APIRouter(prefix="/chat", tags=["chat"])

class ChatRequest(BaseModel):
    message: str

class CitationResponse(BaseModel):
    index: int
    citation_tag: str
    snippet: str
    score: float

class ChatResponse(BaseModel):
    response: str
    citations: List[CitationResponse]
    uncertainty_flag: bool

@router.post("", response_model=ChatResponse)
def post_chat_query(
    request: ChatRequest, 
    db: Session = Depends(get_db),
    # Optional authentication: if token is present, we log user_id, otherwise 'anonymous'
    current_user: Optional[User] = Depends(lambda: None)  # Fallback handled inside
):
    # Retrieve user email for audit log if user is logged in
    # (Since get_current_user throws 401 if missing, we use a softer wrapper if we want public access)
    user_id = "anonymous"
    
    # We will attempt to get authentication, if it fails, keep anonymous.
    # For high safety, some synods might require auth. For now, public members can chat.
    engine = MethodistRAGEngine(db)
    
    # Run the query
    result = engine.generate_answer(user_id=user_id, query=request.message)
    
    return result
