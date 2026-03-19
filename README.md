# OCI ISO/IEC 42001:2023 AI Compliance Scanner

Automated compliance scanner for Oracle Cloud Infrastructure against **ISO/IEC 42001:2023 — AI Management System** (Annex A controls).

## What It Checks

| Section | Controls | OCI Services Checked |
|---------|----------|---------------------|
| **A.2 Policies** | AI governance policies, tagging | IAM, Tagging |
| **A.3 Organization** | AI admin groups, least-privilege | IAM |
| **A.4 Resources** | AI service inventory, private subnets | Data Science, GenAI, AI Vision/Language/Speech, Compute |
| **A.5 Impact** | Cloud Guard, security monitoring | Cloud Guard |
| **A.6 Lifecycle** | IaC, versioning, model metadata, logging | Resource Manager, Object Storage, Data Science, KMS |
| **A.7 Data** | Data Safe, encryption, vault | Data Safe, KMS, Object Storage |
| **A.8 Transparency** | Logging, Log Analytics, audit | Logging, Log Analytics, Audit |
| **A.9 Access** | MFA, auth policy, bastion, monitoring | IAM, Bastion, Monitoring, APM |
| **A.10 Third-Party** | Network controls, service gateways | Networking |

## Usage

```bash
# With OCI CLI profile
python scanner.py --profile cap --tenancy ocid1.tenancy.oc1..xxx

# With instance principal (on OCI compute)
python scanner.py --auth instance_principal --tenancy ocid1.tenancy.oc1..xxx

# Specify region and output directory
python scanner.py --profile cap --tenancy ocid1.tenancy.oc1..xxx --region eu-frankfurt-1 --output /tmp/results
```

## Output

- `iso42001_results.json` — Full structured results
- `iso42001_results.csv` — Spreadsheet-friendly format

## Requirements

- Python 3.9+
- OCI CLI (`pip install oci-cli`)
- OCI credentials (profile or instance principal)
- Read permissions on the tenancy
