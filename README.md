# OCI ISO/IEC 42001:2023 AI Compliance Scanner v2

Comprehensive, product-neutral compliance scanner for Oracle Cloud Infrastructure against **ISO/IEC 42001:2023 AI Management System**, with cross-framework mapping to **EU AI Act**, **NIST AI RMF 1.0**, and **CIS OCI Foundations Benchmark**.

## Key Features

- **73 automated checks** — 20 Clauses 4-10 (management system) + 53 Annex A (normative controls)
- **Product-neutral scoring** — Only governance requirements affect score; OCI service recommendations show alternatives
- **Cross-framework mapping** — EU AI Act risk tiers + NIST AI RMF functions (GOVERN/MAP/MEASURE/MANAGE)
- **12-step certification roadmap** — Auto-progress tracking from scan results
- **Gap analysis** — 12 domains, 66 items, Statement of Applicability generator
- **Evidence register** — Automated + manual evidence tracking
- **EU AI Act rules engine** — Deterministic risk tier classification (Art.5/6/50)
- **64-chunk compliance KB** — RAG-ready for AI agent integration
- **AI Compliance Agent** — 13 tools for LangGraph/OCI Agent Factory deployment

## Architecture

```
                   +-----------------+
                   | OCI-DEMO        |
                   | Control Plane   |
                   | (FastAPI proxy)  |
                   +--------+--------+
                            |
   +------------+   +-------v-------+   +------------------+
   | MCP Tools  |-->| Scanner HTTP  |<--| AI Compliance    |
   | (database- |   | API (server.py|   | Agent (LangGraph)|
   | observatory)|  | port 8080)    |   | 13 tools + KB    |
   +------------+   +-------+-------+   +------------------+
                            |
                   +--------v--------+
                   | Scanner Engine  |
                   | (scanner.py)    |
                   | 73 checks       |
                   | 11 classes      |
                   +-----------------+
                            |
                   +--------v--------+
                   | OCI CLI         |
                   | (instance_principal |
                   |  or config)     |
                   +-----------------+
```

## Scoring: Requirements vs Recommendations

The scanner is **product-neutral**. It does NOT penalize tenancies for not using specific OCI services.

- **Requirements** (affect score): Fundamental governance controls — IAM policies, MFA, audit retention, compartment structure, encryption keys. These are needed regardless of cloud provider.
- **Recommendations** (informational): OCI service suggestions with alternatives. E.g., "Data Safe recommended for A.7.2, alternatives: IBM Guardium, Imperva, or manual database reviews."

15 OCI services are classified as recommendations, each with rationale and alternative products.

## Use Cases

### 1. Standalone CLI

```bash
# Basic scan
python scanner.py --profile cap --tenancy <OCID>

# With all v2 features
python scanner.py --profile cap --tenancy <OCID> --all

# Individual features
python scanner.py --profile cap --tenancy <OCID> --frameworks --roadmap --gaps --evidence

# Instance principal (on OCI compute)
python scanner.py --auth instance_principal --tenancy <OCID> --all
```

Output: `iso42001_results.json`, `iso42001_results.csv`, `iso42001_soa.csv`

### 2. HTTP API Server

```bash
# Start server
python server.py --auth instance_principal --tenancy <OCID> --port 8080

# Or with config profile
python server.py --profile cap --tenancy <OCID> --port 8080 --scan-on-start
```

**Endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Server health and status |
| GET | `/api/iso42001/summary` | Compliance score and check results |
| GET | `/api/iso42001/roadmap` | 12-step certification roadmap |
| GET | `/api/iso42001/gaps` | Gap analysis (12 domains) |
| GET | `/api/iso42001/frameworks` | EU AI Act + NIST AI RMF mapping |
| GET | `/api/iso42001/soa` | Statement of Applicability |
| GET | `/api/iso42001/evidence` | Evidence register |
| GET | `/api/iso42001/scan/status` | Scan status |
| POST | `/api/iso42001/scan` | Trigger new scan |
| POST | `/api/iso42001/classify` | EU AI Act risk tier classification |

### 3. OCI-DEMO Integration (Component C0c)

The scanner integrates with OCI-DEMO Control Plane as component C0c:

- **Control Plane proxy**: `control_plane/api/routers/compliance.py` forwards to scanner HTTP API
- **Frontend**: `ComplianceView.vue` with 5 tabs (Overview, Roadmap, Gaps, Cross-Framework, AIMS Diagram)
- **API client**: `api.js` with 8 ISO 42001 functions
- **Logan dashboard**: `dashboards/compliance/iso42001_ai_governance.json` (12 widgets)

### 4. OCI Stack (Standalone Deployment)

Deploy to any OCI tenancy via Resource Manager:

```bash
cd deploy/terraform
terraform init
terraform apply -var="tenancy_ocid=<OCID>" -var="compartment_ocid=<COMP>" \
  -var="ssh_public_key=$(cat ~/.ssh/id_rsa.pub)"
```

Creates: compute instance, VCN, dynamic group, IAM policies (Instance Principal), systemd service, daily cron scan.

### 5. AI Compliance Agent

```python
from agent.compliance_agent import AGENT_TOOLS, SYSTEM_PROMPT, AGENT_CATALOG_ENTRY

# 13 tools available for LangGraph / OCI Agent Factory
for tool in AGENT_TOOLS:
    print(f"{tool['name']}: {tool['description']}")

# Register with OCI-Coordinator
print(AGENT_CATALOG_ENTRY)
```

### 6. MCP Tools (database-observatory)

8 MCP tools in `mcp-oci-database-observatory/src/mcp_server/tools/iso42001.py`:

- `oci_iso42001_get_summary` — Scan results
- `oci_iso42001_get_findings` — Failed/passed checks with filters
- `oci_iso42001_run_scan` — Trigger scan
- `oci_iso42001_get_roadmap` — Certification roadmap
- `oci_iso42001_get_gaps` — Gap analysis
- `oci_iso42001_get_frameworks` — Cross-framework mapping
- `oci_iso42001_get_evidence` — Evidence register
- `oci_iso42001_classify_risk` — EU AI Act classification

## Compliance Knowledge Base

64 RAG-ready chunks in `compliance_kb/*.jsonl`:

| Framework | Chunks | Content |
|-----------|--------|---------|
| ISO/IEC 42001:2023 | 29 | Clauses 4-10, Annex A controls, Annex B guidance, Annex C/D |
| EU AI Act | 15 | Articles 5, 6, 9-15, 17, 26, 27, 50, 53 |
| NIST AI RMF 1.0 | 7 | 4 functions, subcategories, ISO crosswalk |
| CIS OCI Benchmark | 6 | Sections 1-5 (IAM, Networking, Logging, Storage, Assets) |
| OCI Services | 5 | Data Science, GenAI, Cloud Guard, IAM mappings |
| Related Standards | 1 | ISO 22989, 23894, 38507, 27001 references |

All sources use verified public URLs.

## Frameworks Cross-Mapping

```
ISO 42001 Cl.5 + A.2  ←→  NIST GOVERN 1-2  ←→  EU AI Act Art.9(1)  ←→  CIS OCI Sec.1
ISO 42001 Cl.6 + A.5  ←→  NIST MAP 1-5     ←→  EU AI Act Art.9(2)
ISO 42001 Cl.8 + A.6  ←→  NIST MANAGE 1-3  ←→  EU AI Act Art.10-12
ISO 42001 Cl.9 + A.8  ←→  NIST MEASURE 1-3 ←→  EU AI Act Art.12-13  ←→  CIS OCI Sec.3
ISO 42001 A.7          ←→  NIST MAP 2       ←→  EU AI Act Art.10     ←→  CIS OCI Sec.4
ISO 42001 A.9          ←→  NIST GOVERN 2    ←→  EU AI Act Art.14     ←→  CIS OCI Sec.1
ISO 42001 A.10         ←→  NIST GOVERN 6    ←→  EU AI Act Art.53
```

## Requirements

- Python 3.9+
- OCI CLI (`pip install oci-cli`)
- OCI credentials (Instance Principal or config profile)
- Read permissions on tenancy resources

## Project Structure

```
oci-iso42001-scanner/
├── scanner.py               # Core scanner (73 checks, 11 classes, 2400+ lines)
├── server.py                # HTTP API server (all v2 endpoints)
├── agent/
│   └── compliance_agent.py  # AI agent (13 tools, 64-chunk KB, system prompt)
├── compliance_kb/
│   ├── frameworks.jsonl     # ISO 42001, NIST, EU AI Act, CIS OCI, OCI services
│   └── annex_b_guidance.jsonl # Annex B implementation guidance + A controls + C/D
├── config/
│   ├── controls.yaml        # Control definitions
│   └── logan_log_source.json # Log Analytics source config
├── deploy/
│   ├── setup.sh             # One-command setup for any OL8 instance
│   ├── iso42001-scanner.service # systemd service
│   └── terraform/
│       ├── main.tf          # OCI Stack (compute, VCN, IAM, dynamic group)
│       ├── schema.yaml      # Resource Manager schema
│       └── cloud-init.sh    # Instance bootstrapping
└── README.md
```

## References

- ISO/IEC 42001:2023: https://www.iso.org/standard/81230.html
- NIST AI RMF 1.0: https://www.nist.gov/artificial-intelligence/executive-order-safe-secure-and-trustworthy-artificial-intelligence
- NIST AI RMF Playbook: https://www.nist.gov/system/files/documents/2023/01/26/AI_RMF_Playbook.pdf
- NIST-ISO 42001 Crosswalk: https://airc.nist.gov/AI_RMF_Interoperability_Crosswalks/ISO-IEC-42001-2023
- EU AI Act (Reg. 2024/1689): https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32024R1689
- CIS OCI Benchmark: https://www.cisecurity.org/benchmark/oracle_cloud
- OCI CIS Landing Zone: https://docs.oracle.com/en/solutions/cis-oci-foundations-benchmark/index.html

ISO/IEC 42001:2023 is copyrighted by ISO/IEC. This scanner references control IDs for compliance assessment only. Purchase the standard at https://www.iso.org/standard/81230.html.
