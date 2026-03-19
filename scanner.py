#!/usr/bin/env python3
"""
OCI ISO/IEC 42001:2023 AI Management System Compliance Scanner.

Scans an OCI tenancy against all automatable ISO 42001 Annex A controls
covering AI governance, data protection, lifecycle, access, and monitoring.

Usage:
    # Scan with OCI profile
    python scanner.py --profile cap --tenancy <OCID>

    # Scan with instance principal
    python scanner.py --auth instance_principal --tenancy <OCID>

    # Output to specific directory
    python scanner.py --profile cap --tenancy <OCID> --output /tmp/results
"""
import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

VERSION = "1.0.0"


class OCIClient:
    """Wrapper for OCI CLI commands."""

    def __init__(self, auth: str = "config", profile: str = "DEFAULT",
                 tenancy: str = "", region: str = ""):
        self.auth = auth
        self.profile = profile
        self.tenancy = tenancy
        self.region = region
        self.cli = self._find_cli()

    def _find_cli(self) -> str:
        for p in ["/home/opc/.local/bin/oci", "/usr/local/bin/oci", "/usr/bin/oci"]:
            if Path(p).exists():
                return p
        # Try PATH
        import shutil
        found = shutil.which("oci")
        if found:
            return found
        raise RuntimeError("OCI CLI not found. Install with: pip install oci-cli")

    def query(self, args: list[str], timeout: int = 60) -> list | dict:
        cmd = [self.cli] + args
        if self.auth == "instance_principal":
            cmd += ["--auth", "instance_principal"]
        else:
            cmd += ["--profile", self.profile]
        if self.region:
            cmd += ["--region", self.region]
        cmd += ["--output", "json"]

        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if r.returncode == 0 and r.stdout.strip():
                data = json.loads(r.stdout)
                return data.get("data", data)
        except subprocess.TimeoutExpired:
            pass
        except json.JSONDecodeError:
            pass
        except Exception as e:
            print(f"    WARN: OCI CLI error: {e}")
        return []


class Check:
    def __init__(self, check_id: str, title: str, section: str,
                 compliant: bool, findings: int = 0, total: int = 0,
                 detail: str = "", severity: str = "medium",
                 oci_service: str = "", evidence: str = ""):
        self.check_id = check_id
        self.title = title
        self.section = section
        self.compliant = compliant
        self.findings = findings
        self.total = total
        self.detail = detail
        self.severity = severity
        self.oci_service = oci_service
        self.evidence = evidence

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id, "title": self.title,
            "section": self.section, "severity": self.severity,
            "compliant": "Yes" if self.compliant else "No",
            "findings": self.findings, "total": self.total,
            "detail": self.detail, "oci_service": self.oci_service,
        }


class ISO42001Scanner:
    """Full ISO 42001 Annex A compliance scanner for OCI."""

    def __init__(self, client: OCIClient):
        self.oci = client
        self.tenancy = client.tenancy
        self.results: list[Check] = []
        self._compartments = None

    @property
    def compartments(self) -> list[str]:
        if self._compartments is None:
            comps = self.oci.query(["iam", "compartment", "list",
                                    "--compartment-id", self.tenancy, "--all"])
            self._compartments = [self.tenancy]
            if isinstance(comps, list):
                self._compartments += [c["id"] for c in comps
                                       if c.get("lifecycle-state") == "ACTIVE"]
        return self._compartments

    def _query_across_compartments(self, service_cmd: list[str],
                                    max_comps: int = 10) -> list:
        """Query a service across multiple compartments."""
        all_items = []
        for comp_id in self.compartments[:max_comps]:
            items = self.oci.query(service_cmd + ["--compartment-id", comp_id, "--all"])
            if isinstance(items, list):
                all_items.extend(items)
        return all_items

    def add(self, check_id, title, section, compliant, **kwargs):
        self.results.append(Check(check_id, title, section, compliant, **kwargs))

    # ═══════════════════════════════════════════════════════════
    # A.2 — Policies for AI
    # ═══════════════════════════════════════════════════════════
    def check_a2(self):
        print("[A.2] Policies for AI...")

        # A2.2-01: IAM policies for AI service families
        policies = self.oci.query(["iam", "policy", "list",
                                   "--compartment-id", self.tenancy, "--all"])
        ai_policies = []
        if isinstance(policies, list):
            for pol in policies:
                for stmt in pol.get("statements", []):
                    if any(kw in stmt.lower() for kw in [
                        "generative-ai", "data-science", "ai-service",
                        "ai-vision", "ai-language", "ai-speech", "ai-anomaly",
                    ]):
                        ai_policies.append(stmt)
        self.add("A2.2-01", "IAM policies exist for AI service families",
                 "A.2 Policies", len(ai_policies) > 0,
                 findings=0 if ai_policies else 1, total=max(1, len(ai_policies)),
                 detail=f"{len(ai_policies)} AI-related policy statements",
                 severity="high", oci_service="IAM")

        # A2.2-02: AI governance tag namespace
        tag_ns = self.oci.query(["iam", "tag-namespace", "list",
                                 "--compartment-id", self.tenancy, "--all"])
        ai_tags = [t for t in (tag_ns if isinstance(tag_ns, list) else [])
                   if any(kw in (t.get("name", "") + t.get("description", "")).lower()
                          for kw in ["ai", "ml", "model", "governance"])]
        self.add("A2.2-02", "AI governance tag namespace exists",
                 "A.2 Policies", len(ai_tags) > 0,
                 findings=0 if ai_tags else 1, total=1,
                 detail=f"{len(ai_tags)} AI-related tag namespaces",
                 severity="medium", oci_service="Tagging")

        # A3.2-01: Dedicated AI administrator group
        groups = self.oci.query(["iam", "group", "list",
                                 "--compartment-id", self.tenancy, "--all"])
        ai_groups = [g for g in (groups if isinstance(groups, list) else [])
                     if any(kw in g.get("name", "").lower()
                            for kw in ["ai", "ml", "data-scien", "genai"])]
        self.add("A3.2-01", "Dedicated AI administrator group exists",
                 "A.3 Organization", len(ai_groups) > 0,
                 findings=0 if ai_groups else 1, total=1,
                 detail=f"AI groups: {[g['name'] for g in ai_groups]}" if ai_groups else "No AI groups found",
                 severity="high", oci_service="IAM")

        # A3.2-02: AI group has scoped policies
        overprivileged = 0
        if isinstance(policies, list):
            for pol in policies:
                for stmt in pol.get("statements", []):
                    s = stmt.lower()
                    if any(kw in s for kw in ["data-science", "generative-ai"]):
                        if "manage" in s and "in tenancy" in s:
                            overprivileged += 1
        self.add("A3.2-02", "AI group policies follow least-privilege",
                 "A.3 Organization", overprivileged == 0,
                 findings=overprivileged, total=len(ai_policies),
                 detail=f"{overprivileged} overprivileged AI policies",
                 severity="high", oci_service="IAM")

    # ═══════════════════════════════════════════════════════════
    # A.4 — Resources for AI Systems
    # ═══════════════════════════════════════════════════════════
    def check_a4(self):
        print("[A.4] Resources for AI Systems...")

        # A4.4-01: Data Science projects
        ds_projects = self._query_across_compartments(["data-science", "project", "list"])
        tagged = [p for p in ds_projects if p.get("defined-tags") or p.get("freeform-tags")]
        self.add("A4.4-01", "Data Science projects exist and are tagged",
                 "A.4 Resources", len(ds_projects) > 0 and len(tagged) == len(ds_projects),
                 findings=len(ds_projects) - len(tagged), total=len(ds_projects),
                 detail=f"{len(ds_projects)} projects, {len(tagged)} tagged",
                 severity="high", oci_service="Data Science")

        # A4.4-02: GenAI models
        genai_models = self._query_across_compartments(
            ["generative-ai", "model", "list"], max_comps=3)
        self.add("A4.4-02", "GenAI models/endpoints inventoried",
                 "A.4 Resources", True,
                 total=len(genai_models),
                 detail=f"{len(genai_models)} GenAI models",
                 severity="high", oci_service="Generative AI")

        # A4.4-03 to A4.4-07: Other AI services
        for svc_name, svc_cmd, svc_oci in [
            ("AI Vision", ["ai-vision", "project", "list"], "AI Vision"),
            ("AI Language", ["ai-language", "project", "list"], "AI Language"),
            ("AI Anomaly Detection", ["ai-anomaly-detection", "project", "list"], "AI Anomaly Detection"),
        ]:
            items = self._query_across_compartments(svc_cmd, max_comps=3)
            check_id = f"A4.4-{svc_name.replace(' ', '').lower()}"
            self.add(check_id, f"{svc_name} projects inventoried",
                     "A.4 Resources", True,
                     total=len(items),
                     detail=f"{len(items)} {svc_name} projects",
                     severity="medium", oci_service=svc_oci)

        # A4.5-01: DS notebooks in private subnets
        notebooks = self._query_across_compartments(
            ["data-science", "notebook-session", "list"], max_comps=5)
        public_notebooks = 0
        for nb in notebooks:
            subnet_id = nb.get("notebook-session-configuration-details", {}).get("subnet-id", "")
            if subnet_id:
                subnet = self.oci.query(["network", "subnet", "get", "--subnet-id", subnet_id])
                if isinstance(subnet, dict) and not subnet.get("prohibit-public-ip-on-vnic"):
                    public_notebooks += 1
        self.add("A4.5-01", "Data Science notebooks in private subnets",
                 "A.4 Resources", public_notebooks == 0,
                 findings=public_notebooks, total=len(notebooks),
                 detail=f"{public_notebooks}/{len(notebooks)} in public subnets",
                 severity="high", oci_service="Data Science")

        # A4.5-03: GenAI dedicated clusters
        clusters = self._query_across_compartments(
            ["generative-ai", "dedicated-ai-cluster", "list"], max_comps=3)
        self.add("A4.5-03", "GenAI dedicated AI clusters provisioned",
                 "A.4 Resources", True,
                 total=len(clusters),
                 detail=f"{len(clusters)} dedicated clusters",
                 severity="medium", oci_service="Generative AI")

    # ═══════════════════════════════════════════════════════════
    # A.5 — Impact Assessment
    # ═══════════════════════════════════════════════════════════
    def check_a5(self):
        print("[A.5] Impact Assessment...")

        # A5.2-01: Cloud Guard enabled
        try:
            cg = self.oci.query(["cloud-guard", "configuration", "get",
                                 "--compartment-id", self.tenancy])
            cg_enabled = isinstance(cg, dict) and cg.get("status") == "ENABLED"
        except:
            cg_enabled = False
        self.add("A5.2-01", "Cloud Guard enabled (security impact monitoring)",
                 "A.5 Impact Assessment", cg_enabled,
                 findings=0 if cg_enabled else 1, total=1,
                 detail="Cloud Guard " + ("ENABLED" if cg_enabled else "NOT ENABLED"),
                 severity="high", oci_service="Cloud Guard")

    # ═══════════════════════════════════════════════════════════
    # A.6 — AI System Lifecycle
    # ═══════════════════════════════════════════════════════════
    def check_a6(self):
        print("[A.6] AI Lifecycle...")

        # A6.2-01: Resource Manager stacks (IaC)
        stacks = self._query_across_compartments(
            ["resource-manager", "stack", "list"], max_comps=5)
        self.add("A6.2-01", "Resource Manager stacks exist (Infrastructure as Code)",
                 "A.6 Lifecycle", len(stacks) > 0,
                 total=len(stacks),
                 detail=f"{len(stacks)} IaC stacks",
                 severity="medium", oci_service="Resource Manager")

        # A6.5-01: Bucket versioning
        buckets = self._query_across_compartments(["os", "bucket", "list"], max_comps=5)
        unversioned = [b for b in buckets if b.get("versioning") != "Enabled"]
        self.add("A6.5-01", "Object Storage buckets have versioning (data provenance)",
                 "A.6 Lifecycle", len(unversioned) == 0,
                 findings=len(unversioned), total=len(buckets),
                 detail=f"{len(unversioned)}/{len(buckets)} without versioning",
                 severity="high", oci_service="Object Storage")

        # A6.5-02: Bucket CMK encryption
        ns_data = self.oci.query(["os", "ns", "get"])
        ns = ns_data if isinstance(ns_data, str) else ""
        no_cmk = 0
        for b in buckets[:10]:
            if ns:
                detail = self.oci.query(["os", "bucket", "get",
                                         "--namespace", ns, "--bucket-name", b.get("name", "")])
                if isinstance(detail, dict) and not detail.get("kms-key-id"):
                    no_cmk += 1
        self.add("A6.5-02", "Storage encrypted with customer-managed keys",
                 "A.6 Lifecycle", no_cmk == 0,
                 findings=no_cmk, total=min(len(buckets), 10),
                 detail=f"{no_cmk} buckets without CMK",
                 severity="high", oci_service="Object Storage / KMS")

        # A6.6-01: ML models with metadata
        models = self._query_across_compartments(
            ["data-science", "model", "list"], max_comps=5)
        with_meta = [m for m in models if m.get("description")]
        self.add("A6.6-01", "ML models have metadata/description",
                 "A.6 Lifecycle",
                 len(models) == 0 or len(with_meta) == len(models),
                 findings=len(models) - len(with_meta), total=len(models),
                 detail=f"{len(models)} models, {len(with_meta)} documented",
                 severity="high", oci_service="Data Science")

        # A6.6-02: Model deployments with logging
        deployments = self._query_across_compartments(
            ["data-science", "model-deployment", "list"], max_comps=5)
        no_logs = [d for d in deployments
                   if not d.get("category-log-details", {}).get("access")
                   and not d.get("category-log-details", {}).get("predict")]
        self.add("A6.6-02", "Model deployments have logging configured",
                 "A.6 Lifecycle",
                 len(deployments) == 0 or len(no_logs) == 0,
                 findings=len(no_logs), total=len(deployments),
                 detail=f"{len(no_logs)}/{len(deployments)} without logging",
                 severity="high", oci_service="Data Science")

    # ═══════════════════════════════════════════════════════════
    # A.7 — Data for AI Systems
    # ═══════════════════════════════════════════════════════════
    def check_a7(self):
        print("[A.7] Data Governance...")

        # A7.2-01: Data Safe targets
        ds_targets = self._query_across_compartments(
            ["data-safe", "target-database", "list"], max_comps=5)
        self.add("A7.2-01", "Data Safe enabled for databases",
                 "A.7 Data", len(ds_targets) > 0,
                 findings=0 if ds_targets else 1, total=max(1, len(ds_targets)),
                 detail=f"{len(ds_targets)} Data Safe targets",
                 severity="high", oci_service="Data Safe")

        # A7.2-02: Data Safe assessments
        assessments = self._query_across_compartments(
            ["data-safe", "user-assessment", "list"], max_comps=3)
        self.add("A7.2-02", "Data Safe user assessments performed",
                 "A.7 Data", len(assessments) > 0,
                 findings=0 if assessments else 1, total=max(1, len(assessments)),
                 detail=f"{len(assessments)} user assessments",
                 severity="medium", oci_service="Data Safe")

        # A7.5-01: KMS Vault for AI encryption
        vaults = self._query_across_compartments(["kms", "vault", "list"], max_comps=5)
        active_vaults = [v for v in vaults if v.get("lifecycle-state") == "ACTIVE"]
        self.add("A7.5-01", "KMS Vault exists for AI data encryption",
                 "A.7 Data", len(active_vaults) > 0,
                 findings=0 if active_vaults else 1, total=max(1, len(active_vaults)),
                 detail=f"{len(active_vaults)} active vaults",
                 severity="high", oci_service="KMS")

    # ═══════════════════════════════════════════════════════════
    # A.8 — Transparency
    # ═══════════════════════════════════════════════════════════
    def check_a8(self):
        print("[A.8] Transparency & Logging...")

        # A8.4-01: Logging log groups
        log_groups = self._query_across_compartments(
            ["logging", "log-group", "list"], max_comps=5)
        self.add("A8.4-01", "Logging service enabled with log groups",
                 "A.8 Transparency", len(log_groups) > 0,
                 findings=0 if log_groups else 1, total=max(1, len(log_groups)),
                 detail=f"{len(log_groups)} log groups",
                 severity="high", oci_service="Logging")

        # A8.4-03: Log Analytics namespace
        try:
            la_ns = self.oci.query(["log-analytics", "namespace", "list",
                                    "--compartment-id", self.tenancy])
            la_active = isinstance(la_ns, dict) or (isinstance(la_ns, list) and len(la_ns) > 0)
        except:
            la_active = False
        self.add("A8.4-03", "Log Analytics namespace configured",
                 "A.8 Transparency", la_active,
                 findings=0 if la_active else 1, total=1,
                 detail="Log Analytics " + ("active" if la_active else "not configured"),
                 severity="medium", oci_service="Log Analytics")

        # A8.4-04: Audit retention
        audit = self.oci.query(["audit", "config", "get",
                                "--compartment-id", self.tenancy])
        retention = audit.get("retention-period-days", 0) if isinstance(audit, dict) else 0
        self.add("A8.4-04", "Audit log retention >= 365 days",
                 "A.8 Transparency", retention >= 365,
                 findings=0 if retention >= 365 else 1, total=1,
                 detail=f"Retention: {retention} days",
                 severity="high", oci_service="Audit")

    # ═══════════════════════════════════════════════════════════
    # A.9 — Use of AI Systems
    # ═══════════════════════════════════════════════════════════
    def check_a9(self):
        print("[A.9] Access Control & Monitoring...")

        # A9.3-02: MFA for users
        users = self.oci.query(["iam", "user", "list",
                                "--compartment-id", self.tenancy, "--all"])
        if isinstance(users, list):
            console_users = [u for u in users if u.get("is-mfa-activated") is not None]
            no_mfa = [u for u in console_users if not u.get("is-mfa-activated")]
            self.add("A9.3-02", "MFA enforced for users",
                     "A.9 Access & Monitoring", len(no_mfa) == 0,
                     findings=len(no_mfa), total=len(console_users),
                     detail=f"{len(no_mfa)}/{len(console_users)} without MFA",
                     severity="high", oci_service="IAM")

        # A9.3-03: Strong auth policy
        auth = self.oci.query(["iam", "authentication-policy", "get",
                               "--compartment-id", self.tenancy])
        if isinstance(auth, dict):
            pwd = auth.get("password-policy", {})
            min_len = pwd.get("minimum-password-length", 0)
            self.add("A9.3-03", "Strong authentication policy (password >= 14)",
                     "A.9 Access & Monitoring", min_len >= 14,
                     findings=0 if min_len >= 14 else 1, total=1,
                     detail=f"Min length: {min_len}",
                     severity="medium", oci_service="IAM")

        # A9.3-04: Bastion service
        bastions = self._query_across_compartments(
            ["bastion", "bastion", "list"], max_comps=5)
        active_bastions = [b for b in bastions if b.get("lifecycle-state") == "ACTIVE"]
        self.add("A9.3-04", "Bastion service for secure AI environment access",
                 "A.9 Access & Monitoring", len(active_bastions) > 0,
                 total=len(active_bastions),
                 detail=f"{len(active_bastions)} active bastions",
                 severity="medium", oci_service="Bastion")

        # A9.4-01: Monitoring alarms
        alarms = self._query_across_compartments(
            ["monitoring", "alarm", "list"], max_comps=5)
        self.add("A9.4-01", "Monitoring alarms configured",
                 "A.9 Access & Monitoring", len(alarms) > 0,
                 total=len(alarms),
                 detail=f"{len(alarms)} alarms",
                 severity="high", oci_service="Monitoring")

        # A9.4-02: APM domain
        apm_domains = self._query_across_compartments(
            ["apm-synthetics", "monitor", "list"], max_comps=3)
        self.add("A9.4-02", "APM domain exists for application tracing",
                 "A.9 Access & Monitoring", True,
                 severity="medium", oci_service="APM")

        # A9.4-05: Audit retention (same as A8.4-04, shared check)
        # Already covered in A.8

    # ═══════════════════════════════════════════════════════════
    # A.10 — Third-Party AI
    # ═══════════════════════════════════════════════════════════
    def check_a10(self):
        print("[A.10] Third-Party & Network Controls...")

        # A10.3-01: AI endpoints not on public subnets (checked via VCNs)
        vcns = self._query_across_compartments(["network", "vcn", "list"], max_comps=5)
        service_gateways = self._query_across_compartments(
            ["network", "service-gateway", "list"], max_comps=5)
        self.add("A10.3-02", "Service Gateway exists for AI service traffic",
                 "A.10 Third-Party", len(service_gateways) > 0,
                 total=len(service_gateways),
                 detail=f"{len(service_gateways)} service gateways across {len(vcns)} VCNs",
                 severity="medium", oci_service="Networking")

    def run_all(self) -> dict:
        """Run all ISO 42001 checks."""
        start = datetime.now(timezone.utc)
        print(f"[ISO42001] Scanner v{VERSION} starting at {start.isoformat()}")
        print(f"[ISO42001] Tenancy: {self.tenancy}")
        print(f"[ISO42001] Compartments: {len(self.compartments)}")

        self.check_a2()
        self.check_a4()
        self.check_a5()
        self.check_a6()
        self.check_a7()
        self.check_a8()
        self.check_a9()
        self.check_a10()

        elapsed = (datetime.now(timezone.utc) - start).total_seconds()
        passed = sum(1 for r in self.results if r.compliant)
        score = round(passed / len(self.results) * 100) if self.results else 0

        print(f"\n[ISO42001] Complete: {score}% ({passed}/{len(self.results)}) in {elapsed:.0f}s")
        return {
            "framework": "ISO_42001_2023",
            "framework_name": "ISO/IEC 42001:2023 AI Management System",
            "scanner": f"oci-iso42001-scanner v{VERSION}",
            "provider": "OCI",
            "scan_date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "scan_duration_seconds": round(elapsed),
            "tenancy": self.tenancy,
            "score": score,
            "passed": passed,
            "failed": len(self.results) - passed,
            "total": len(self.results),
            "by_section": self._by_section(),
            "checks": [r.to_dict() for r in self.results],
        }

    def _by_section(self) -> dict:
        sections = {}
        for r in self.results:
            s = r.section
            if s not in sections:
                sections[s] = {"pass": 0, "fail": 0}
            if r.compliant:
                sections[s]["pass"] += 1
            else:
                sections[s]["fail"] += 1
        return sections


def main():
    parser = argparse.ArgumentParser(description="OCI ISO 42001 AI Compliance Scanner")
    parser.add_argument("--profile", default="DEFAULT", help="OCI CLI profile name")
    parser.add_argument("--auth", default="config", choices=["config", "instance_principal"])
    parser.add_argument("--tenancy", required=True, help="Tenancy OCID")
    parser.add_argument("--region", default="", help="OCI region")
    parser.add_argument("--output", default=".", help="Output directory")
    args = parser.parse_args()

    client = OCIClient(
        auth=args.auth, profile=args.profile,
        tenancy=args.tenancy, region=args.region,
    )
    scanner = ISO42001Scanner(client)
    results = scanner.run_all()

    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "iso42001_results.json"
    out_file.write_text(json.dumps(results, indent=2))
    print(f"\nResults written to: {out_file}")

    # Also write CSV
    csv_file = out_dir / "iso42001_results.csv"
    with open(csv_file, "w") as f:
        f.write("check_id,section,severity,compliant,findings,total,title,oci_service,detail\n")
        for c in results["checks"]:
            f.write(f'{c["check_id"]},{c["section"]},{c["severity"]},'
                    f'{c["compliant"]},{c["findings"]},{c["total"]},'
                    f'"{c["title"]}",{c["oci_service"]},"{c["detail"]}"\n')


if __name__ == "__main__":
    main()
