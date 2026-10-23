"""
Pydantic Schemas for ShieldDesk CVE Intelligence & AI Mitigation Engine.

Enforces strict schema validation on:
- Inference inputs (/api/predict)
- Exact lookup responses (/api/lookup)
- Ingested threat intelligence feeds (CISA KEV, FIRST EPSS, NVD 2.0)
- Model registry and evaluation manifests
"""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, field_validator
import re

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,8}$", re.IGNORECASE)

class VulnerabilityInferenceRequest(BaseModel):
    description: str = Field(..., min_length=5, max_length=50000, description="Vulnerability text description")
    category: Optional[str] = Field("General", max_length=100, description="Software or OS category")
    cwe_id: Optional[str] = Field("Unknown", max_length=50, description="Common Weakness Enumeration ID")
    epss_score: Optional[float] = Field(None, ge=0.0, le=1.0, description="FIRST EPSS exploit probability")
    kev_listed: Optional[int] = Field(None, ge=0, le=1, description="CISA KEV flag (0 or 1)")
    top_k_similar: Optional[int] = Field(3, ge=1, le=10, description="Number of historical playbooks to return")
    context: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Operational context (asset criticality, blast radius)")

    @field_validator("description")
    @classmethod
    def sanitize_description(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Description cannot be empty or whitespace only.")
        return cleaned

class CISAKEVItem(BaseModel):
    cveID: str
    vendorProject: Optional[str] = ""
    product: Optional[str] = ""
    vulnerabilityName: Optional[str] = ""
    dateAdded: Optional[str] = ""
    shortDescription: Optional[str] = ""
    requiredAction: Optional[str] = ""
    dueDate: Optional[str] = ""
    knownRansomwareCampaignUse: Optional[str] = "Unknown"

    @field_validator("cveID")
    @classmethod
    def validate_cve(cls, v: str) -> str:
        v = v.strip().upper()
        if not CVE_PATTERN.match(v):
            raise ValueError(f"Invalid CVE ID format: {v}")
        return v

class EPSSRecord(BaseModel):
    cve: str
    epss: float = Field(..., ge=0.0, le=1.0)
    percentile: Optional[float] = Field(None, ge=0.0, le=1.0)

    @field_validator("cve")
    @classmethod
    def validate_cve(cls, v: str) -> str:
        v = v.strip().upper()
        if not CVE_PATTERN.match(v):
            raise ValueError(f"Invalid CVE ID format: {v}")
        return v

class LookupRecord(BaseModel):
    cve_id: str
    category: Optional[str] = "General"
    domain: Optional[str] = "Operating System"
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    cvss_severity: Optional[str] = "UNKNOWN"
    cwe_id: Optional[str] = "Unknown"
    kev_listed: Optional[int] = Field(0, ge=0, le=1)
    kev_required_action: Optional[str] = ""
    epss_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    description: Optional[str] = ""
    mitigation_plan: Optional[str] = ""
    assigned_tier: Optional[str] = "Tier 2 (Medium-Risk / Human-Approved)"
    source: Optional[str] = "harmonized_kb"
    last_updated: Optional[str] = None

class ModelStatusResponse(BaseModel):
    status: str
    service: str = "cve-ai-engine"
    champion_version: str
    challenger_version: Optional[str] = None
    shadow_eval_enabled: bool
    total_inferences: int
    shadow_divergences: int
    dataset_hash: Optional[str] = None
