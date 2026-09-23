import logging
from typing import Dict, Any, List

logger = logging.getLogger("advisor.rag")

# Simulated Knowledge Base for pgvector & Qdrant retrieval
MOCK_CVE_KNOWLEDGE = [
    {
        "cve_id": "CVE-2024-3400",
        "description": "PAN-OS GlobalProtect command injection vulnerability allowing unauthenticated remote code execution with root privileges.",
        "cvss": 10.0,
        "fix_command": "cli -c 'request system software upgrade-to 10.2.9-h1'",
    },
    {
        "cve_id": "CVE-2024-21626",
        "description": "runc container breakout allowing attackers to access host filesystem via file descriptor leak.",
        "cvss": 8.6,
        "fix_command": "apt-get install --only-upgrade -y runc",
    },
    {
        "cve_id": "CVE-2023-44487",
        "description": "HTTP/2 Rapid Reset distributed denial of service attack exploiting stream cancellation.",
        "cvss": 7.5,
        "fix_command": "nginx -s reload",
    },
]

MOCK_PAST_INCIDENTS = [
    {
        "incident_id": "INC-0891",
        "summary": "Suspicious base64 PowerShell invocation on finance workstation.",
        "resolution": "Isolated workstation from LAN, killed PID 4812, revoked Kerberos TGT.",
    },
    {
        "incident_id": "INC-0924",
        "summary": "Exposed AWS IAM key detected in public repository.",
        "resolution": "Deactivated access key AKIA..., rotated secrets in AWS Secrets Manager.",
    },
]

class RagPipeline:
    def __init__(self, db_url: str = "", qdrant_url: str = ""):
        self.db_url = db_url
        self.qdrant_url = qdrant_url

    def retrieve_cve_context(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """
        Step 1: Queries pgvector cve_embeddings for top-k similar CVEs.
        """
        logger.info(f"[RAG-Step1] Querying pgvector top-{top_k} CVEs for: {query[:40]}...")
        # In live deployment, execute vector similarity search:
        # SELECT cve_id, description, cvss FROM cve_embeddings ORDER BY embedding <=> $1 LIMIT $2
        return MOCK_CVE_KNOWLEDGE[:top_k]

    def load_company_context(self, tenant_id: str) -> Dict[str, Any]:
        """
        Step 2: Loads tenant tech stack, team size, cloud provider, and unresolved alerts.
        """
        logger.info(f"[RAG-Step2] Loading company profile for tenant {tenant_id}")
        return {
            "tenant_id": tenant_id,
            "cloud_provider": "AWS (us-east-1)",
            "tech_stack": ["Next.js", "PostgreSQL 16", "Docker", "Node.js 20"],
            "unresolved_alerts_count": 2,
            "assets_monitored": 18,
            "compliance_frameworks": ["SOC 2 Type II", "ISO 27001"],
        }

    def retrieve_similar_incidents(self, query: str, top_k: int = 3) -> List[Dict[str, Any]]:
        """
        Step 3: Queries Qdrant incident_embeddings for top-k past incidents.
        """
        logger.info(f"[RAG-Step3] Querying Qdrant past incidents top-{top_k}")
        return MOCK_PAST_INCIDENTS[:top_k]

    def build_structured_prompt(self, user_query: str, tenant_id: str) -> Dict[str, str]:
        """
        Step 4: Constructs XML-structured system, context, and query prompts.
        """
        cve_context = self.retrieve_cve_context(user_query)
        company_context = self.load_company_context(tenant_id)
        incident_context = self.retrieve_similar_incidents(user_query)

        cve_text = "\n".join([f"- {c['cve_id']} (CVSS {c['cvss']}): {c['description']}" for c in cve_context])
        inc_text = "\n".join([f"- {i['incident_id']}: {i['summary']} -> Resolution: {i['resolution']}" for i in incident_context])

        system_prompt = f"""You are ShieldDesk's AI security advisor for a startup.
Company context: {company_context}
Respond ONLY with valid JSON matching the schema below.
Never hallucinate CVE IDs. If unsure, say so explicitly.
Schema:
{{
  "severity": "critical|high|medium|low",
  "summary": "plain English summary in 2-3 sentences",
  "root_cause": "technical explanation",
  "fix_steps": [
    {{ "order": 1, "title": "step title", "command": "exact shell command", "explanation": "why" }}
  ],
  "estimated_fix_time": "15 minutes",
  "risk_if_ignored": "plain English consequence"
}}"""

        context_prompt = f"""<context>
Relevant CVEs:
{cve_text}

Similar past incidents:
{inc_text}
</context>"""

        return {
            "system": system_prompt,
            "context": context_prompt,
            "query": user_query,
        }
