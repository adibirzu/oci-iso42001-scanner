"""
OCI AI Compliance Agent — LangGraph-based agent for ISO 42001 compliance.

Provides an interactive AI assistant for OCI customers to:
  1. Scan their tenancy for ISO 42001/EU AI Act/NIST AI RMF compliance
  2. Query the compliance knowledge base (RAG) — 64 chunks across 7 frameworks
  3. Get remediation guidance for findings with OCI + alternative steps
  4. Classify AI systems under EU AI Act risk tiers
  5. Track certification roadmap progress
  6. Query their OCI infrastructure directly for compliance context
  7. Integrate with OCI-Coordinator or any external agent via MCP tools

Designed for deployment via:
  - OCI AI Agent Factory (GenAI Agents service)
  - Standalone LangGraph server
  - OCI-DEMO coordinator integration (as agent in catalog)
  - MCP tool server (callable by mcp-oci-database-observatory)

References (all public):
  - ISO/IEC 42001:2023: https://www.iso.org/standard/81230.html
  - NIST AI RMF 1.0: https://www.nist.gov/artificial-intelligence/executive-order-safe-secure-and-trustworthy-artificial-intelligence
  - NIST AI RMF Playbook: https://www.nist.gov/system/files/documents/2023/01/26/AI_RMF_Playbook.pdf
  - NIST-ISO 42001 Crosswalk: https://airc.nist.gov/AI_RMF_Interoperability_Crosswalks/ISO-IEC-42001-2023
  - EU AI Act (Reg. 2024/1689): https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32024R1689
  - CIS OCI Benchmark: https://www.cisecurity.org/benchmark/oracle_cloud
  - OCI CIS Landing Zone: https://docs.oracle.com/en/solutions/cis-oci-foundations-benchmark/index.html
  - OCI Security Features: https://docs.oracle.com/en-us/iaas/Content/Security/Concepts/security_features.htm
  - OCI Data Science: https://docs.oracle.com/en-us/iaas/data-science/using/overview.htm
  - OCI Generative AI: https://docs.oracle.com/en-us/iaas/Content/generative-ai/overview.htm
  - OCI Cloud Guard: https://docs.oracle.com/en-us/iaas/cloud-guard/using/index.htm
  - OCI IAM: https://docs.oracle.com/en-us/iaas/Content/Identity/Concepts/overview.htm
"""
from __future__ import annotations

import glob
import json
import os
import subprocess
from typing import Any

import httpx

SCANNER_URL = os.getenv("ISO42001_SCANNER_URL", "http://localhost:8080")
KB_PATH = os.getenv("ISO42001_KB_PATH",
                     os.path.join(os.path.dirname(__file__), "..", "compliance_kb"))

# ═══════════════════════════════════════════════════════════════
# KB Search — Multi-file JSONL loading with TF-IDF-like scoring
# ═══════════════════════════════════════════════════════════════

_KB_CACHE = None


def _load_kb() -> list[dict]:
    """Load all JSONL files from the KB directory. Cached after first load."""
    global _KB_CACHE
    if _KB_CACHE is not None:
        return _KB_CACHE

    chunks = []
    for jsonl_file in sorted(glob.glob(os.path.join(KB_PATH, "*.jsonl"))):
        with open(jsonl_file) as f:
            for line in f:
                line = line.strip()
                if line:
                    chunks.append(json.loads(line))

    _KB_CACHE = chunks
    return chunks


def _search_kb(query: str, framework: str = "", category: str = "",
               top_k: int = 5) -> list[dict]:
    """Search KB with weighted term matching."""
    chunks = _load_kb()
    query_terms = query.lower().split()
    results = []

    for chunk in chunks:
        if framework and framework.lower() not in chunk.get("framework", "").lower():
            continue
        if category and category.lower() not in chunk.get("category", "").lower():
            continue

        # Weighted scoring: title matches worth 3x, content matches 1x
        title = chunk.get("title", "").lower()
        content = chunk.get("content", "").lower()
        score = sum(3 for t in query_terms if t in title)
        score += sum(1 for t in query_terms if t in content)

        # Boost for exact phrase match
        if query.lower() in title:
            score += 10
        if query.lower() in content:
            score += 5

        if score > 0:
            results.append({
                "chunk_id": chunk["chunk_id"],
                "framework": chunk["framework"],
                "category": chunk.get("category", ""),
                "title": chunk["title"],
                "content": chunk["content"][:600],
                "source_url": chunk.get("source_url", ""),
                "maps_to": chunk.get("maps_to", []),
                "relevance_score": score,
            })

    results.sort(key=lambda x: -x["relevance_score"])
    return results[:top_k]


# ═══════════════════════════════════════════════════════════════
# Scanner API Tools
# ═══════════════════════════════════════════════════════════════

async def tool_scan_tenancy() -> dict:
    """Trigger an ISO 42001 compliance scan of the OCI tenancy.

    Scans 73 checks across Clauses 4-10 and Annex A.2-A.10.
    Product-neutral: only requirements affect score, recommendations
    suggest OCI services with alternatives listed.
    Takes 2-5 minutes. Returns scan trigger status.
    """
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(f"{SCANNER_URL}/api/iso42001/scan")
        return resp.json()


async def tool_get_compliance_summary() -> dict:
    """Get the latest ISO 42001 compliance scan summary.

    Returns overall score (requirements only), clause/annex breakdown,
    requirements vs recommendations counts, and section-by-section results.
    """
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(f"{SCANNER_URL}/api/iso42001/summary")
        return resp.json()


async def tool_get_findings(section: str = "", check_type: str = "") -> dict:
    """Get compliance findings, optionally filtered.

    Args:
        section: Filter by section (e.g., 'A.7', 'Cl.9', 'Data', 'Lifecycle')
        check_type: 'requirement' (scored) or 'recommendation' (informational)
    """
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(f"{SCANNER_URL}/api/iso42001/summary")
        data = resp.json()

    checks = data.get("checks", [])
    if section:
        checks = [c for c in checks if section.lower() in c.get("section", "").lower()]
    if check_type:
        checks = [c for c in checks if c.get("check_type") == check_type]

    return {
        "total": len(checks),
        "failed": [c for c in checks if c["compliant"] == "No"],
        "passed": [c for c in checks if c["compliant"] == "Yes"],
    }


async def tool_get_roadmap() -> dict:
    """Get 12-step ISO 42001 certification roadmap with progress."""
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(f"{SCANNER_URL}/api/iso42001/roadmap")
        return resp.json()


async def tool_get_gap_analysis(domain: str = "") -> dict:
    """Get gap analysis across 12 compliance domains.

    Domains: GOV, SCOPE, RISK, INVENTORY, LIFECYCLE, DATA,
    ACCESS, TRANSPARENCY, MONITORING, THIRDPARTY, PERFORMANCE, IMPROVEMENT.
    """
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(f"{SCANNER_URL}/api/iso42001/gaps")
        data = resp.json()
    if domain:
        data["domains"] = [d for d in data.get("domains", [])
                           if d.get("id", "").upper() == domain.upper()]
    return data


async def tool_get_cross_framework() -> dict:
    """Get cross-framework mapping: ISO 42001 ↔ EU AI Act ↔ NIST AI RMF."""
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(f"{SCANNER_URL}/api/iso42001/frameworks")
        return resp.json()


async def tool_classify_eu_ai_act_risk(
    domain: str = "other",
    purpose: str = "",
    uses_biometric: bool = False,
    public_sector: bool = False,
    safety_component: bool = False,
    affects_fundamental_rights: bool = False,
) -> dict:
    """Classify an AI system's EU AI Act risk tier.

    Decision: Art.5 prohibited → Art.6+Annex III high-risk → Art.50 limited → minimal.
    Ref: https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32024R1689
    """
    payload = {
        "domain": domain, "purpose": purpose,
        "uses_biometric": uses_biometric, "public_sector": public_sector,
        "safety_component": safety_component,
        "affects_fundamental_rights": affects_fundamental_rights,
        "prohibited_indicators": [], "transparency_triggers": [],
    }
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(f"{SCANNER_URL}/api/iso42001/classify", json=payload)
        return resp.json()


async def tool_get_evidence_register() -> dict:
    """Get evidence register with automated + manual evidence status."""
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(f"{SCANNER_URL}/api/iso42001/evidence")
        return resp.json()


# ═══════════════════════════════════════════════════════════════
# Knowledge Base Tools
# ═══════════════════════════════════════════════════════════════

def tool_query_compliance_kb(query: str, framework: str = "",
                              category: str = "") -> list[dict]:
    """Search the compliance knowledge base (64 chunks, 7 frameworks).

    Covers ISO 42001 (Clauses 4-10, Annex A controls, Annex B implementation
    guidance, Annex C risk objectives, Annex D sectors), NIST AI RMF 1.0
    (4 functions + subcategories + crosswalk), EU AI Act (Articles 5-53),
    CIS OCI Benchmark (Sections 1-5), and OCI service mappings.

    Args:
        query: Search query (e.g., "data governance", "human oversight")
        framework: Optional filter ("ISO/IEC 42001:2023", "EU AI Act",
                   "NIST AI RMF 1.0", "CIS OCI Foundations Benchmark", "OCI")
        category: Optional filter ("annex_b", "annex_a_detail", "article",
                  "clause", "service_mapping", "crosswalk")
    """
    return _search_kb(query, framework, category)


def tool_get_implementation_guidance(control_ref: str) -> list[dict]:
    """Get Annex B implementation guidance for a specific control.

    Args:
        control_ref: Annex reference (e.g., "B.7", "A.7", "B.6", "A.9")

    Returns matching Annex B guidance chunks with detailed implementation steps.
    """
    return _search_kb(control_ref, framework="ISO/IEC 42001:2023", category="annex_b")


# ═══════════════════════════════════════════════════════════════
# OCI Infrastructure Query Tools
# ═══════════════════════════════════════════════════════════════

def tool_query_oci_resource(service: str, command: str,
                             compartment_id: str = "") -> dict:
    """Query OCI infrastructure for compliance-relevant resource information.

    Executes OCI CLI commands to inspect the user's tenancy resources.
    Used to answer infrastructure-specific compliance questions like
    "how many Data Science projects do I have?" or "is MFA enabled?".

    Args:
        service: OCI service (e.g., "iam", "data-science", "kms", "cloud-guard")
        command: OCI CLI sub-command (e.g., "user list", "project list")
        compartment_id: Compartment OCID (uses tenancy root if empty)

    Returns:
        OCI CLI response parsed as JSON
    """
    # Build OCI CLI command
    cmd_parts = command.split()
    oci_args = ["oci", service] + cmd_parts

    # Add compartment if provided
    if compartment_id:
        oci_args += ["--compartment-id", compartment_id]

    # Try instance principal first, fall back to config
    for auth in ["--auth", "instance_principal"]:
        try:
            result = subprocess.run(
                oci_args + [auth, "--output", "json"],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                return {"success": True, "data": data.get("data", data)}
        except (subprocess.TimeoutExpired, json.JSONDecodeError):
            continue
        except Exception as e:
            return {"success": False, "error": str(e)}

    # Fallback without auth flag (uses default config)
    try:
        result = subprocess.run(
            oci_args + ["--output", "json"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout)
            return {"success": True, "data": data.get("data", data)}
        return {"success": False, "error": result.stderr[:500]}
    except Exception as e:
        return {"success": False, "error": str(e)}


def tool_check_oci_service_status(service_name: str) -> dict:
    """Check whether a specific OCI service is active in the tenancy.

    Useful for answering "do I have Cloud Guard enabled?" or "are there
    Data Safe targets configured?". Maps service status to ISO 42001 controls.

    Args:
        service_name: Service to check (cloud_guard, data_safe, kms, bastion,
                      log_analytics, data_science, generative_ai, monitoring)
    """
    SERVICE_CHECKS = {
        "cloud_guard": {
            "cmd": ["oci", "cloud-guard", "configuration", "get"],
            "check_field": "status",
            "expected": "ENABLED",
            "iso_controls": ["A.5.2", "Cl.6"],
            "description": "Security posture management for AI infrastructure",
        },
        "data_safe": {
            "cmd": ["oci", "data-safe", "target-database", "list"],
            "check_field": None,
            "expected": "list_not_empty",
            "iso_controls": ["A.7.2", "A.7.5"],
            "description": "Database security assessments and data protection",
        },
        "kms": {
            "cmd": ["oci", "kms", "vault", "list"],
            "check_field": None,
            "expected": "list_not_empty",
            "iso_controls": ["A.7.5", "A.6.5"],
            "description": "Encryption key management for AI data protection",
        },
        "log_analytics": {
            "cmd": ["oci", "log-analytics", "namespace", "list"],
            "check_field": None,
            "expected": "any_response",
            "iso_controls": ["A.8.4"],
            "description": "Centralized log analysis for AI system transparency",
        },
        "monitoring": {
            "cmd": ["oci", "monitoring", "alarm", "list"],
            "check_field": None,
            "expected": "list_not_empty",
            "iso_controls": ["A.9.4", "A.6.2.6"],
            "description": "Operational monitoring alarms for AI systems",
        },
    }

    if service_name not in SERVICE_CHECKS:
        return {
            "success": False,
            "error": f"Unknown service: {service_name}",
            "available_services": list(SERVICE_CHECKS.keys()),
        }

    check = SERVICE_CHECKS[service_name]
    return {
        "service": service_name,
        "iso_controls": check["iso_controls"],
        "description": check["description"],
        "note": "Use tool_query_oci_resource for actual status check",
    }


# ═══════════════════════════════════════════════════════════════
# Remediation Tools
# ═══════════════════════════════════════════════════════════════

def tool_get_remediation_guidance(check_id: str) -> dict:
    """Get remediation guidance for a specific failed check.

    Provides OCI-specific steps plus alternative approaches.
    All references use real OCI documentation URLs.
    """
    REMEDIATIONS = {
        "A2.2-01": {
            "title": "Create IAM policies for AI services",
            "oci_steps": [
                "Navigate to Identity > Policies in OCI Console",
                "Create: Allow group <AI-admins> to manage data-science-family in compartment <AI>",
                "Create: Allow group <AI-admins> to manage generative-ai-family in compartment <AI>",
            ],
            "alternatives": "Any IAM with RBAC for AI workloads",
            "reference": "https://docs.oracle.com/en-us/iaas/Content/Identity/policiesgs/get-started-with-policies.htm",
        },
        "A3.2-01": {
            "title": "Create dedicated AI administrator IAM group",
            "oci_steps": [
                "Navigate to Identity > Groups > Create Group",
                "Name: AI-Administrators (or similar)",
                "Add relevant users to the group",
                "Create scoped policies for AI services",
            ],
            "alternatives": "Any identity system with group-based access control",
            "reference": "https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/managinggroups.htm",
        },
        "A9.3-02": {
            "title": "Enable MFA for all users",
            "oci_steps": [
                "Identity > Users > Select user > Enable MFA",
                "Users enroll via Oracle Mobile Authenticator or FIDO2 keys",
            ],
            "alternatives": "Okta, Duo, Azure AD MFA, Google Authenticator",
            "reference": "https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/usingmfa.htm",
        },
        "CL6-01": {
            "title": "Enable Cloud Guard for risk identification",
            "oci_steps": [
                "Security > Cloud Guard > Enable in root compartment",
                "Configure targets for AI compartments",
                "Enable detector recipes",
            ],
            "alternatives": "Wiz, Prisma Cloud, Orca Security, AWS SecurityHub",
            "reference": "https://docs.oracle.com/en-us/iaas/cloud-guard/using/index.htm",
        },
        "A8.4-04": {
            "title": "Set audit log retention to 365+ days",
            "oci_steps": [
                "OCI CLI: oci audit config update --compartment-id <tenancy> --retention-period-days 365",
            ],
            "alternatives": "Forward logs to any SIEM with 365-day retention",
            "reference": "https://docs.oracle.com/en-us/iaas/Content/Audit/Tasks/settingretentionperiod.htm",
        },
        "A6.5-01": {
            "title": "Enable Object Storage bucket versioning",
            "oci_steps": [
                "Object Storage > Buckets > Select bucket > Enable Versioning",
                "Or: oci os bucket update --name <bucket> --versioning Enabled",
            ],
            "alternatives": "Any versioned storage: AWS S3 versioning, Azure Blob, MinIO",
            "reference": "https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/usingversioning.htm",
        },
        "A7.5-01": {
            "title": "Create KMS Vault for AI data encryption",
            "oci_steps": [
                "Security > Vault > Create Vault",
                "Create Master Encryption Key",
                "Enable auto-rotation on keys",
                "Assign CMK to buckets and databases",
            ],
            "alternatives": "AWS KMS, Azure Key Vault, HashiCorp Vault, GCP Cloud KMS",
            "reference": "https://docs.oracle.com/en-us/iaas/Content/KeyManagement/Concepts/keyoverview.htm",
        },
        "CL9-01": {
            "title": "Set audit log retention for performance records",
            "oci_steps": [
                "oci audit config update --compartment-id <tenancy> --retention-period-days 365",
            ],
            "alternatives": "Any audit system with configurable retention",
            "reference": "https://docs.oracle.com/en-us/iaas/Content/Audit/Tasks/settingretentionperiod.htm",
        },
    }

    if check_id in REMEDIATIONS:
        return {"success": True, "check_id": check_id, **REMEDIATIONS[check_id]}

    # Fall back to KB search for guidance
    kb_results = _search_kb(check_id)
    if kb_results:
        return {
            "success": True, "check_id": check_id,
            "title": f"Guidance from KB for {check_id}",
            "kb_guidance": kb_results[0],
            "note": "No specific OCI remediation steps. See KB guidance above.",
        }

    return {
        "success": False, "check_id": check_id,
        "message": f"No remediation for {check_id}. Use query_compliance_kb for guidance.",
    }


# ═══════════════════════════════════════════════════════════════
# Agent System Prompt
# ═══════════════════════════════════════════════════════════════

SYSTEM_PROMPT = """You are the OCI AI Compliance Agent — an expert assistant for ISO/IEC 42001:2023 AI Management System compliance on Oracle Cloud Infrastructure.

## Capabilities
1. Scan OCI tenancies for ISO 42001, EU AI Act, and NIST AI RMF compliance (73 checks)
2. Search a 64-chunk knowledge base covering all 4 frameworks + OCI service mappings
3. Provide implementation guidance from Annex B for every Annex A control
4. Classify AI systems under EU AI Act risk tiers (Art.5/6/50)
5. Track 12-step certification roadmap progress
6. Query the user's OCI infrastructure for compliance-specific questions
7. Generate remediation steps with OCI + alternative product guidance

## Key Principles
- PRODUCT-NEUTRAL: Recommend OCI services but always provide alternatives. Never penalize for missing an OCI service.
- EVIDENCE-BASED: All guidance references real standards with public URLs.
- RISK-BASED: Focus on high-severity requirements first. Score only counts requirements, not recommendations.
- FRAMEWORK-AWARE: Understand ISO 42001 ↔ EU AI Act ↔ NIST AI RMF ↔ CIS OCI cross-mappings.
- INFRASTRUCTURE-AWARE: Can query user's OCI resources for personalized compliance answers.
- CUSTOM AI SUPPORT: Works with any AI framework on OCI, not just OCI-native services.

## Workflow
1. For compliance questions → query_compliance_kb first, then scan if needed
2. For "how do I implement X?" → get_implementation_guidance for Annex B details
3. For infrastructure questions → tool_query_oci_resource to check actual state
4. For EU AI Act → classify_eu_ai_act_risk for risk tier determination
5. For remediation → get_remediation_guidance for step-by-step fixes

## Key References
- ISO 42001: https://www.iso.org/standard/81230.html
- NIST AI RMF: https://www.nist.gov/system/files/documents/2023/01/26/AI_RMF_Playbook.pdf
- NIST-ISO Crosswalk: https://airc.nist.gov/AI_RMF_Interoperability_Crosswalks/ISO-IEC-42001-2023
- EU AI Act: https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32024R1689
- CIS OCI: https://docs.oracle.com/en/solutions/cis-oci-foundations-benchmark/index.html
- OCI Security: https://docs.oracle.com/en-us/iaas/Content/Security/Concepts/security_features.htm
"""

# ═══════════════════════════════════════════════════════════════
# Tool Registry — For LangGraph / Agent Factory / MCP integration
# ═══════════════════════════════════════════════════════════════

AGENT_TOOLS = [
    # Scanner tools
    {"name": "scan_tenancy", "function": tool_scan_tenancy,
     "description": "Trigger ISO 42001 compliance scan (73 checks, 2-5 min)"},
    {"name": "get_compliance_summary", "function": tool_get_compliance_summary,
     "description": "Get compliance score and section breakdown"},
    {"name": "get_findings", "function": tool_get_findings,
     "description": "Get failed/passed checks filtered by section or type"},
    {"name": "get_roadmap", "function": tool_get_roadmap,
     "description": "Get 12-step certification roadmap with progress"},
    {"name": "get_gap_analysis", "function": tool_get_gap_analysis,
     "description": "Get gap analysis across 12 compliance domains"},
    {"name": "get_cross_framework", "function": tool_get_cross_framework,
     "description": "Get EU AI Act + NIST AI RMF cross-framework mapping"},
    {"name": "classify_eu_ai_act_risk", "function": tool_classify_eu_ai_act_risk,
     "description": "Classify AI system EU AI Act risk tier"},
    {"name": "get_evidence_register", "function": tool_get_evidence_register,
     "description": "Get evidence register (automated + manual)"},
    # Knowledge base tools
    {"name": "query_compliance_kb", "function": tool_query_compliance_kb,
     "description": "Search 64-chunk KB: ISO 42001/EU AI Act/NIST/CIS OCI"},
    {"name": "get_implementation_guidance", "function": tool_get_implementation_guidance,
     "description": "Get Annex B implementation guidance for controls"},
    # Remediation
    {"name": "get_remediation_guidance", "function": tool_get_remediation_guidance,
     "description": "Get remediation steps for failed checks (OCI + alternatives)"},
    # Infrastructure query tools
    {"name": "query_oci_resource", "function": tool_query_oci_resource,
     "description": "Query OCI infrastructure for compliance context"},
    {"name": "check_oci_service_status", "function": tool_check_oci_service_status,
     "description": "Check if an OCI service is active in the tenancy"},
]

# ═══════════════════════════════════════════════════════════════
# OCI-Coordinator Integration — Agent Catalog Entry
# ═══════════════════════════════════════════════════════════════

AGENT_CATALOG_ENTRY = {
    "agent_id": "compliance",
    "name": "AI Compliance Agent",
    "description": "ISO 42001/EU AI Act/NIST AI RMF compliance scanning, guidance, and remediation for OCI tenancies",
    "domain": "compliance",
    "capabilities": [
        "iso-42001-scanning",
        "eu-ai-act-classification",
        "nist-ai-rmf-mapping",
        "cis-oci-benchmark",
        "compliance-guidance",
        "certification-roadmap",
        "gap-analysis",
        "remediation-guidance",
        "infrastructure-query",
    ],
    "tools": [t["name"] for t in AGENT_TOOLS],
    "system_prompt": SYSTEM_PROMPT,
    "scanner_url": SCANNER_URL,
    "kb_chunks": 64,
    "frameworks": ["ISO/IEC 42001:2023", "EU AI Act", "NIST AI RMF 1.0",
                    "CIS OCI Foundations Benchmark"],
}
