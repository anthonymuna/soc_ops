# main.py
import os
import jwt
import httpx
import logging
from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Any
from elasticsearch import Elasticsearch
from agent import get_agent_executor, QWEN_BASE_URL
from prompts import CHAT_SYSTEM_PROMPT
from triage import start_triage_consumer
from tools.execute_action import execute_approved_action

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("brain-api")

SECRET_KEY = os.getenv("SECRET_KEY", "django-insecure-default-key-for-dev")
ES_HOST = os.getenv("ES_HOST", "http://elasticsearch:9200")
es = Elasticsearch(ES_HOST)

app = FastAPI(title="NGAO Brain API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# JWT Authentication dependency
def verify_token(authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header missing")
    try:
        token_type, token = authorization.split(" ")
        if token_type.lower() != "bearer":
            raise HTTPException(status_code=401, detail="Invalid token type")
        
        # Decode and validate JWT using shared secret key
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload
    except Exception as e:
        logger.error(f"JWT verification failed: {e}")
        raise HTTPException(status_code=401, detail="Invalid or expired token")

class ChatRequest(BaseModel):
    message: str
    history: List[Dict[str, Any]] = []

@app.post("/chat")
def chat(body: ChatRequest, token: dict = Depends(verify_token)):
    from langchain_core.messages import HumanMessage, AIMessage
    
    chat_history = []
    for h in body.history:
        role = h.get("role")
        content = h.get("content", "")
        if role == "user":
            chat_history.append(HumanMessage(content=content))
        elif role == "assistant":
            chat_history.append(AIMessage(content=content))
            
    logger.info(f"Received chat query from user: {body.message}")
    
    agent_executor = get_agent_executor(CHAT_SYSTEM_PROMPT)
    
    try:
        result = agent_executor.invoke({
            "input": body.message,
            "chat_history": chat_history
        })
        
        reply = result.get("output", "")
        
        # Extract intermediate tool calls
        tool_calls = []
        intermediate_steps = result.get("intermediate_steps", [])
        for action, observation in intermediate_steps:
            tool_calls.append({
                "tool": action.tool,
                "input": action.tool_input,
                "output": str(observation)[:200]
            })
            
        return {
            "reply": reply,
            "tool_calls": tool_calls,
            "sources": []
        }
    except Exception as e:
        logger.error(f"Agent execution error: {e}")
        raise HTTPException(status_code=500, detail=f"Agent failed to execute: {str(e)}")

@app.get("/triage")
def get_triage(token: dict = Depends(verify_token)):
    try:
        resp = es.search(
            index="syndicate4-triage",
            body={
                "query": {"match_all": {}},
                "size": 50,
                "sort": [{"triaged_at": {"order": "desc"}}]
            }
        )
        hits = [h["_source"] for h in resp["hits"]["hits"]]
        return hits
    except Exception as e:
        logger.error(f"Failed to query triage index: {e}")
        return []

@app.post("/execute/{triage_id}")
def execute_action(triage_id: str, token: dict = Depends(verify_token)):
    logger.info(f"Programmatic request to execute action for triage_id: {triage_id}")
    import json
    result_str = execute_approved_action.func(pending_action_id=triage_id)
    return json.loads(result_str)

@app.get("/health")
def health():
    es_ok = False
    try:
        es_ok = bool(es.ping())
    except Exception:
        pass
        
    qwen_ok = False
    try:
        with httpx.Client(verify=False, timeout=3) as client:
            res = client.get(f"{QWEN_BASE_URL}/models")
            qwen_ok = (res.status_code == 200)
    except Exception:
        pass
        
    # Standard health response
    return {
        "status": "ok" if (es_ok and qwen_ok) else "degraded",
        "es": es_ok,
        "qwen": qwen_ok,
        "kafka": True # Fallback status
    }

@app.on_event("startup")
def startup_event():
    # Start background Kafka consumer
    logger.info("Starting background Kafka consumer thread...")
    start_triage_consumer()
