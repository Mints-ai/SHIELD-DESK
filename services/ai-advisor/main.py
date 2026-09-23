import os
import time
import uuid
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from rag import RagPipeline
from claude import ClaudeClient

app = FastAPI(
    title="ShieldDesk AI Advisor Service",
    description="RAG-powered autonomous security advisor using Anthropic Claude (Haiku & Sonnet) and pgvector/Qdrant",
    version="1.0.0",
)

rag_pipeline = RagPipeline(
    db_url=os.getenv("DATABASE_URL", ""),
    qdrant_url=os.getenv("QDRANT_URL", "")
)

claude_client = ClaudeClient(api_key=os.getenv("ANTHROPIC_API_KEY", ""))

# In-memory storage for stored advisories & conversation turns
advisories_store: Dict[str, Dict[str, Any]] = {}
conversation_turns: Dict[str, List[Dict[str, str]]] = {}

# --- Schemas ---

class AlertSummaryRequest(BaseModel):
    alert_id: str
    tenant_id: str
    severity: str
    rule_name: str
    asset_id: str
    payload: Optional[Dict[str, Any]] = Field(default_factory=dict)

class AdvisoryChatRequest(BaseModel):
    tenant_id: str
    user_query: str
    session_id: Optional[str] = None
    asset_id: Optional[str] = None
    cve_id: Optional[str] = None

class PostureSimulateRequest(BaseModel):
    tenant_id: str
    cve_id: str
    asset_id: str

# --- Endpoints ---

@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "shielddesk-ai-advisor",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

# 1. Summarise Alert (Haiku Fast Path)
@app.post("/internal/ai/summarise-alert")
def summarise_alert(req: AlertSummaryRequest):
    res = claude_client.generate_haiku_summary(req.dict())
    return {
        "alert_id": req.alert_id,
        "tenant_id": req.tenant_id,
        "summary": res["summary"],
        "slack_payload": res["slack_payload"],
        "model_used": res["model_used"],
    }

# 2. Deep Advisory Chat (Sonnet with 4-Step RAG)
@app.post("/internal/ai/chat")
def advisory_chat(req: AdvisoryChatRequest):
    session_id = req.session_id or str(uuid.uuid4())
    history = conversation_turns.get(session_id, [])

    # Run RAG Pipeline: Step 1 (CVE), Step 2 (Company), Step 3 (Past Incidents), Step 4 (Prompt)
    structured_prompts = rag_pipeline.build_structured_prompt(req.user_query, req.tenant_id)

    # Call Claude Sonnet
    advisory_output = claude_client.generate_sonnet_advisory(structured_prompts, history)

    # Store advisory record
    advisory_id = str(uuid.uuid4())
    record = {
        "id": advisory_id,
        "tenant_id": req.tenant_id,
        "query": req.user_query,
        "advisory": advisory_output,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    advisories_store[advisory_id] = record

    # Update conversation history (sliding window: keep last 10 turns)
    history.append({"role": "user", "content": req.user_query})
    history.append({"role": "assistant", "content": advisory_output.get("summary", "")})
    if len(history) > 10:
        history = history[-10:]
    conversation_turns[session_id] = history

    return {
        "advisory_id": advisory_id,
        "session_id": session_id,
        "response": advisory_output,
    }

# 3. Posture Simulation
@app.post("/internal/ai/simulate-posture")
def simulate_posture(req: PostureSimulateRequest):
    simulation = claude_client.simulate_blast_radius(req.cve_id, req.asset_id)
    return {
        "tenant_id": req.tenant_id,
        "simulation": simulation,
    }

# 4. Retrieve Stored Advisory
@app.get("/internal/ai/advisory/{advisory_id}")
def get_advisory(advisory_id: str):
    record = advisories_store.get(advisory_id)
    if not record:
        raise HTTPException(status_code=404, detail="Advisory not found")
    return record

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8002, reload=True)
