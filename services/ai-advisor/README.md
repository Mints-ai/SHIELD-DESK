# ShieldDesk AI Advisor Service (Python 3.12 + LangChain + Claude)

The AI Advisor Service provides RAG-powered autonomous security analysis using Anthropic Claude models (`claude-3-5-haiku` for fast summaries and `claude-3-5-sonnet` for deep advisory reasoning).

---

## 4-Step RAG Pipeline

1. **CVE Context Retrieval**: Queries `cve_embeddings` via pgvector for top-5 vulnerability descriptions and CVSS metrics.
2. **Company Context**: Loads tenant cloud infrastructure, active stack, and unresolved alert counts.
3. **Similar Incident Retrieval**: Queries `incident_embeddings` via Qdrant for top-3 past incident resolutions.
4. **Structured JSON Output**: Delivers an actionable, non-hallucinated response with technical root cause, step-by-step shell commands, estimated fix time, and business risk if ignored.

---

## Endpoints

- `POST /internal/ai/summarise-alert` — Haiku fast path generating concise summaries and formatted Slack alerts.
- `POST /internal/ai/chat` — Sonnet deep advisory session with RAG context and 10-turn sliding memory.
- `POST /internal/ai/simulate-posture` — Blast radius and posture downgrade simulation for unpatched CVEs.
- `GET  /internal/ai/advisory/{id}` — Retrieve persisted advisory recommendations.

---

## Local Development

```bash
cd services/ai-advisor
pip install -r requirements.txt
python run_tests.py
uvicorn main:app --port 8002 --reload
```
