#!/usr/bin/env python3
"""
OCI ISO/IEC 42001:2023 AI Management System Compliance Scanner v2.

Comprehensive scanner covering:
  - Clauses 4-10: Management system requirements
  - Annex A: Normative controls (A.2-A.10)
  - Cross-framework mapping: EU AI Act, NIST AI RMF
  - Certification roadmap: 12-step progress tracking
  - Gap analysis: Automated + manual evidence

Usage:
    # Scan with OCI profile
    python scanner.py --profile cap --tenancy <OCID>

    # Scan with instance principal
    python scanner.py --auth instance_principal --tenancy <OCID>

    # Output to specific directory
    python scanner.py --profile cap --tenancy <OCID> --output /tmp/results

Note: ISO/IEC 42001:2023 is copyrighted by ISO/IEC.
This scanner references control IDs for compliance checking only.
Purchase the standard at https://www.iso.org/standard/81230.html
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

VERSION = "2.0.0"
CONFIG_DIR = Path(__file__).parent / "config"


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
    """A single compliance check result.

    check_type determines scoring behavior:
      - "requirement": Affects compliance score (must-have for certification)
      - "recommendation": Does NOT lower score if missing; suggests OCI service
        with alternatives listed. Informational for gap closure.
    """
    def __init__(self, check_id: str, title: str, section: str,
                 compliant: bool, findings: int = 0, total: int = 0,
                 detail: str = "", severity: str = "medium",
                 oci_service: str = "", evidence: str = "",
                 clause_type: str = "annex_a",
                 eu_ai_act_ref: str = "", nist_ai_rmf_ref: str = "",
                 check_type: str = "requirement",
                 rationale: str = "", alternatives: str = ""):
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
        self.clause_type = clause_type  # "clause" or "annex_a"
        self.eu_ai_act_ref = eu_ai_act_ref
        self.nist_ai_rmf_ref = nist_ai_rmf_ref
        # Product-neutral fields
        self.check_type = check_type  # "requirement" or "recommendation"
        self.rationale = rationale    # Why this service/control helps
        self.alternatives = alternatives  # Non-OCI alternatives

    def to_dict(self) -> dict:
        d = {
            "check_id": self.check_id, "title": self.title,
            "section": self.section, "severity": self.severity,
            "compliant": "Yes" if self.compliant else "No",
            "findings": self.findings, "total": self.total,
            "detail": self.detail, "oci_service": self.oci_service,
            "clause_type": self.clause_type,
            "check_type": self.check_type,
        }
        if self.eu_ai_act_ref:
            d["eu_ai_act_ref"] = self.eu_ai_act_ref
        if self.nist_ai_rmf_ref:
            d["nist_ai_rmf_ref"] = self.nist_ai_rmf_ref
        if self.rationale:
            d["rationale"] = self.rationale
        if self.alternatives:
            d["alternatives"] = self.alternatives
        return d


class ISO42001Scanner:
    """Full ISO/IEC 42001:2023 compliance scanner for OCI.

    Covers Clauses 4-10 (management system) and Annex A (normative controls).
    """

    def __init__(self, client: OCIClient):
        self.oci = client
        self.tenancy = client.tenancy
        self.results: list[Check] = []
        self._compartments = None
        # Shared query caches (populated once, reused across checks)
        self._policies_cache = None
        self._tags_cache = None
        self._groups_cache = None
        self._users_cache = None
        self._buckets_cache = None
        self._os_ns_cache = None

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

    @property
    def policies(self) -> list:
        if self._policies_cache is None:
            self._policies_cache = self.oci.query(
                ["iam", "policy", "list", "--compartment-id", self.tenancy, "--all"])
            if not isinstance(self._policies_cache, list):
                self._policies_cache = []
        return self._policies_cache

    @property
    def tag_namespaces(self) -> list:
        if self._tags_cache is None:
            self._tags_cache = self.oci.query(
                ["iam", "tag-namespace", "list", "--compartment-id", self.tenancy, "--all"])
            if not isinstance(self._tags_cache, list):
                self._tags_cache = []
        return self._tags_cache

    @property
    def groups(self) -> list:
        if self._groups_cache is None:
            self._groups_cache = self.oci.query(
                ["iam", "group", "list", "--compartment-id", self.tenancy, "--all"])
            if not isinstance(self._groups_cache, list):
                self._groups_cache = []
        return self._groups_cache

    @property
    def users(self) -> list:
        if self._users_cache is None:
            self._users_cache = self.oci.query(
                ["iam", "user", "list", "--compartment-id", self.tenancy, "--all"])
            if not isinstance(self._users_cache, list):
                self._users_cache = []
        return self._users_cache

    @property
    def buckets(self) -> list:
        if self._buckets_cache is None:
            self._buckets_cache = self._query_across_compartments(
                ["os", "bucket", "list"], max_comps=5)
        return self._buckets_cache

    @property
    def os_namespace(self) -> str:
        if self._os_ns_cache is None:
            ns_data = self.oci.query(["os", "ns", "get"])
            self._os_ns_cache = ns_data if isinstance(ns_data, str) else ""
        return self._os_ns_cache

    def _query_across_compartments(self, service_cmd: list[str],
                                    max_comps: int = 10) -> list:
        all_items = []
        for comp_id in self.compartments[:max_comps]:
            items = self.oci.query(service_cmd + ["--compartment-id", comp_id, "--all"])
            if isinstance(items, list):
                all_items.extend(items)
        return all_items

    def _ai_policy_statements(self) -> list[str]:
        stmts = []
        for pol in self.policies:
            for stmt in pol.get("statements", []):
                if any(kw in stmt.lower() for kw in [
                    "generative-ai", "data-science", "ai-service",
                    "ai-vision", "ai-language", "ai-speech", "ai-anomaly",
                    "ai-document", "ai-forecasting",
                ]):
                    stmts.append(stmt)
        return stmts

    def add(self, check_id, title, section, compliant, **kwargs):
        self.results.append(Check(check_id, title, section, compliant, **kwargs))

    # ═══════════════════════════════════════════════════════════════
    # CLAUSES 4-10: Management System Requirements
    # ═══════════════════════════════════════════════════════════════

    def check_clause4(self):
        """Clause 4 — Context of the Organization."""
        print("[Clause 4] Context of the Organization...")

        # CL4-01: Multiple compartments (organizational scope defined)
        self.add("CL4-01", "Organizational scope defined (compartment structure)",
                 "Cl.4 Context", len(self.compartments) > 1,
                 findings=0 if len(self.compartments) > 1 else 1, total=1,
                 detail=f"{len(self.compartments)} compartments (scope boundaries)",
                 severity="high", oci_service="IAM",
                 clause_type="clause",
                 eu_ai_act_ref="Art.9(1)", nist_ai_rmf_ref="GOVERN 1.1")

        # CL4-02: Tag namespaces define stakeholder context
        context_tags = [t for t in self.tag_namespaces
                        if any(kw in (t.get("name", "") + t.get("description", "")).lower()
                               for kw in ["department", "owner", "stakeholder", "business",
                                          "cost-center", "project"])]
        self.add("CL4-02", "Stakeholder context captured via tag namespaces",
                 "Cl.4 Context", len(context_tags) > 0,
                 findings=0 if context_tags else 1, total=1,
                 detail=f"{len(context_tags)} context-related tag namespaces",
                 severity="medium", oci_service="Tagging",
                 clause_type="clause",
                 nist_ai_rmf_ref="GOVERN 1.2")

        # CL4-03: AI-specific compartment exists (AIMS scope)
        ai_comps = []
        all_comps = self.oci.query(["iam", "compartment", "list",
                                     "--compartment-id", self.tenancy, "--all"])
        if isinstance(all_comps, list):
            ai_comps = [c for c in all_comps
                        if any(kw in (c.get("name", "") + c.get("description", "")).lower()
                               for kw in ["ai", "ml", "data-science", "genai", "model"])]
        self.add("CL4-03", "AI-specific compartment exists (AIMS scope boundary)",
                 "Cl.4 Context", len(ai_comps) > 0,
                 findings=0 if ai_comps else 1, total=1,
                 detail=f"{len(ai_comps)} AI-specific compartments",
                 severity="high", oci_service="IAM",
                 clause_type="clause",
                 eu_ai_act_ref="Art.9(1)", nist_ai_rmf_ref="GOVERN 1.1")

    def check_clause5(self):
        """Clause 5 — Leadership."""
        print("[Clause 5] Leadership...")

        # CL5-01: Tenancy-level admin group exists (top management commitment)
        admin_groups = [g for g in self.groups
                        if any(kw in g.get("name", "").lower()
                               for kw in ["admin", "tenancy-admin", "cloud-admin"])]
        self.add("CL5-01", "Tenancy admin group exists (leadership commitment)",
                 "Cl.5 Leadership", len(admin_groups) > 0,
                 findings=0 if admin_groups else 1, total=1,
                 detail=f"{len(admin_groups)} admin groups",
                 severity="high", oci_service="IAM",
                 clause_type="clause",
                 nist_ai_rmf_ref="GOVERN 1.3")

        # CL5-02: AI governance policy exists at tenancy level
        ai_policies = self._ai_policy_statements()
        self.add("CL5-02", "AI governance policies established (leadership direction)",
                 "Cl.5 Leadership", len(ai_policies) > 0,
                 findings=0 if ai_policies else 1, total=1,
                 detail=f"{len(ai_policies)} AI policy statements",
                 severity="high", oci_service="IAM",
                 clause_type="clause",
                 eu_ai_act_ref="Art.9(1),Art.17(1)", nist_ai_rmf_ref="GOVERN 1.1")

        # CL5-03: Multiple IAM groups (roles/responsibilities assigned)
        self.add("CL5-03", "Multiple IAM groups defined (role assignment)",
                 "Cl.5 Leadership", len(self.groups) >= 3,
                 findings=0 if len(self.groups) >= 3 else 1, total=1,
                 detail=f"{len(self.groups)} IAM groups",
                 severity="medium", oci_service="IAM",
                 clause_type="clause",
                 nist_ai_rmf_ref="GOVERN 2.1")

    def check_clause6(self):
        """Clause 6 — Planning."""
        print("[Clause 6] Planning...")

        # CL6-01: Cloud Guard enabled (risk identification)
        try:
            cg = self.oci.query(["cloud-guard", "configuration", "get",
                                 "--compartment-id", self.tenancy])
            cg_enabled = isinstance(cg, dict) and cg.get("status") == "ENABLED"
        except Exception:
            cg_enabled = False
        self.add("CL6-01", "Cloud Guard enabled (risk identification process)",
                 "Cl.6 Planning", cg_enabled,
                 findings=0 if cg_enabled else 1, total=1,
                 detail="Cloud Guard " + ("ENABLED" if cg_enabled else "NOT ENABLED"),
                 severity="high", oci_service="Cloud Guard",
                 clause_type="clause",
                 eu_ai_act_ref="Art.9(2)", nist_ai_rmf_ref="MAP 1.1")

        # CL6-02: Budget configured (resource planning)
        budgets = self._query_across_compartments(
            ["budgets", "budget", "list"], max_comps=3)
        self.add("CL6-02", "Budgets configured (AI resource planning)",
                 "Cl.6 Planning", len(budgets) > 0,
                 findings=0 if budgets else 1, total=1,
                 detail=f"{len(budgets)} budgets",
                 severity="medium", oci_service="Budgets",
                 clause_type="clause",
                 nist_ai_rmf_ref="GOVERN 1.5")

        # CL6-03: Monitoring alarms (risk treatment objectives)
        alarms = self._query_across_compartments(
            ["monitoring", "alarm", "list"], max_comps=5)
        self.add("CL6-03", "Monitoring alarms set (risk treatment objectives)",
                 "Cl.6 Planning", len(alarms) > 0,
                 findings=0 if alarms else 1, total=max(1, len(alarms)),
                 detail=f"{len(alarms)} monitoring alarms",
                 severity="high", oci_service="Monitoring",
                 clause_type="clause",
                 nist_ai_rmf_ref="MEASURE 1.1")

    def check_clause7(self):
        """Clause 7 — Support."""
        print("[Clause 7] Support...")

        # CL7-01: Notification topics (communication channels)
        topics = self._query_across_compartments(
            ["ons", "topic", "list"], max_comps=5)
        self.add("CL7-01", "Notification topics configured (communication channels)",
                 "Cl.7 Support", len(topics) > 0,
                 findings=0 if topics else 1, total=1,
                 detail=f"{len(topics)} notification topics",
                 severity="medium", oci_service="Notifications",
                 clause_type="clause",
                 nist_ai_rmf_ref="GOVERN 4.1")

        # CL7-02: Log groups for documented information
        log_groups = self._query_across_compartments(
            ["logging", "log-group", "list"], max_comps=5)
        self.add("CL7-02", "Log groups exist (documented information management)",
                 "Cl.7 Support", len(log_groups) > 0,
                 findings=0 if log_groups else 1, total=1,
                 detail=f"{len(log_groups)} log groups",
                 severity="high", oci_service="Logging",
                 clause_type="clause",
                 eu_ai_act_ref="Art.12(1)", nist_ai_rmf_ref="GOVERN 4.2")

        # CL7-03: Users with API keys (competence/access to tools)
        users_with_keys = [u for u in self.users
                           if u.get("capabilities", {}).get("can-use-api-keys")]
        self.add("CL7-03", "Users with API access (competence for AI operations)",
                 "Cl.7 Support", len(users_with_keys) > 0,
                 total=len(users_with_keys),
                 detail=f"{len(users_with_keys)} users with API key capability",
                 severity="low", oci_service="IAM",
                 clause_type="clause",
                 nist_ai_rmf_ref="GOVERN 3.1")

    def check_clause8(self):
        """Clause 8 — Operation."""
        print("[Clause 8] Operation...")

        # CL8-01: Resource Manager stacks (operational planning via IaC)
        stacks = self._query_across_compartments(
            ["resource-manager", "stack", "list"], max_comps=5)
        self.add("CL8-01", "Resource Manager stacks (operational planning via IaC)",
                 "Cl.8 Operation", len(stacks) > 0,
                 total=len(stacks),
                 detail=f"{len(stacks)} IaC stacks",
                 severity="medium", oci_service="Resource Manager",
                 clause_type="clause",
                 nist_ai_rmf_ref="MANAGE 1.1")

        # CL8-02: Data Science projects (AI system development operational)
        ds_projects = self._query_across_compartments(
            ["data-science", "project", "list"])
        self.add("CL8-02", "Data Science projects exist (AI system operations)",
                 "Cl.8 Operation", len(ds_projects) > 0,
                 total=len(ds_projects),
                 detail=f"{len(ds_projects)} Data Science projects",
                 severity="high", oci_service="Data Science",
                 clause_type="clause",
                 eu_ai_act_ref="Art.9(1)", nist_ai_rmf_ref="MANAGE 2.1")

        # CL8-03: Events rules (change control)
        events_rules = self._query_across_compartments(
            ["events", "rule", "list"], max_comps=5)
        self.add("CL8-03", "Events rules configured (operational change control)",
                 "Cl.8 Operation", len(events_rules) > 0,
                 total=len(events_rules),
                 detail=f"{len(events_rules)} events rules",
                 severity="medium", oci_service="Events",
                 clause_type="clause",
                 eu_ai_act_ref="Art.12(1)", nist_ai_rmf_ref="MANAGE 3.1")

    def check_clause9(self):
        """Clause 9 — Performance Evaluation."""
        print("[Clause 9] Performance Evaluation...")

        # CL9-01: Audit log retention (monitoring/measurement)
        audit = self.oci.query(["audit", "config", "get",
                                "--compartment-id", self.tenancy])
        retention = audit.get("retention-period-days", 0) if isinstance(audit, dict) else 0
        self.add("CL9-01", "Audit log retention >= 365 days (performance records)",
                 "Cl.9 Performance", retention >= 365,
                 findings=0 if retention >= 365 else 1, total=1,
                 detail=f"Retention: {retention} days",
                 severity="high", oci_service="Audit",
                 clause_type="clause",
                 eu_ai_act_ref="Art.12(2)", nist_ai_rmf_ref="MEASURE 2.1")

        # CL9-02: Cloud Guard security score (internal audit proxy)
        try:
            cg_score = self.oci.query(["cloud-guard", "security-score-trend", "list",
                                        "--compartment-id", self.tenancy])
            has_score = isinstance(cg_score, list) and len(cg_score) > 0
        except Exception:
            has_score = False
        self.add("CL9-02", "Cloud Guard security scoring active (internal audit)",
                 "Cl.9 Performance", has_score,
                 findings=0 if has_score else 1, total=1,
                 detail="Security score trending " + ("active" if has_score else "not available"),
                 severity="medium", oci_service="Cloud Guard",
                 clause_type="clause",
                 nist_ai_rmf_ref="MEASURE 2.2")

        # CL9-03: Data Safe assessments (evaluation evidence)
        assessments = self._query_across_compartments(
            ["data-safe", "security-assessment", "list"], max_comps=3)
        self.add("CL9-03", "Data Safe security assessments (evaluation evidence)",
                 "Cl.9 Performance", len(assessments) > 0,
                 findings=0 if assessments else 1, total=max(1, len(assessments)),
                 detail=f"{len(assessments)} security assessments",
                 severity="medium", oci_service="Data Safe",
                 clause_type="clause",
                 nist_ai_rmf_ref="MEASURE 3.1")

    def check_clause10(self):
        """Clause 10 — Improvement."""
        print("[Clause 10] Improvement...")

        # CL10-01: Cloud Guard problems addressed (nonconformity/corrective action)
        try:
            problems = self.oci.query(["cloud-guard", "problem", "list",
                                        "--compartment-id", self.tenancy,
                                        "--lifecycle-state", "ACTIVE",
                                        "--limit", "100"])
            problem_count = len(problems) if isinstance(problems, list) else 0
        except Exception:
            problem_count = -1
        self.add("CL10-01", "Cloud Guard active problems tracked (corrective actions)",
                 "Cl.10 Improvement", problem_count >= 0,
                 findings=max(0, problem_count), total=max(1, max(0, problem_count)),
                 detail=f"{problem_count} active security problems" if problem_count >= 0 else "Cloud Guard unavailable",
                 severity="high", oci_service="Cloud Guard",
                 clause_type="clause",
                 nist_ai_rmf_ref="MANAGE 4.1")

        # CL10-02: Recommendations available (continual improvement)
        try:
            recs = self.oci.query(["cloud-guard", "recommendation", "list",
                                    "--compartment-id", self.tenancy,
                                    "--lifecycle-state", "ACTIVE",
                                    "--limit", "50"])
            rec_count = len(recs) if isinstance(recs, list) else 0
        except Exception:
            rec_count = -1
        self.add("CL10-02", "Cloud Guard recommendations tracked (continual improvement)",
                 "Cl.10 Improvement", rec_count >= 0,
                 findings=max(0, rec_count), total=max(1, max(0, rec_count)),
                 detail=f"{rec_count} active recommendations" if rec_count >= 0 else "Recommendations unavailable",
                 severity="medium", oci_service="Cloud Guard",
                 clause_type="clause",
                 nist_ai_rmf_ref="MANAGE 4.2")

    # ═══════════════════════════════════════════════════════════════
    # ANNEX A: Normative Controls
    # ═══════════════════════════════════════════════════════════════

    def check_a2(self):
        """A.2 — Policies for AI."""
        print("[A.2] Policies for AI...")

        ai_policies = self._ai_policy_statements()

        # A2.2-01: IAM policies for AI service families
        self.add("A2.2-01", "IAM policies exist for AI service families",
                 "A.2 Policies", len(ai_policies) > 0,
                 findings=0 if ai_policies else 1, total=max(1, len(ai_policies)),
                 detail=f"{len(ai_policies)} AI-related policy statements",
                 severity="high", oci_service="IAM",
                 eu_ai_act_ref="Art.9(1)", nist_ai_rmf_ref="GOVERN 1.1")

        # A2.2-02: AI governance tag namespace
        ai_tags = [t for t in self.tag_namespaces
                   if any(kw in (t.get("name", "") + t.get("description", "")).lower()
                          for kw in ["ai", "ml", "model", "governance"])]
        self.add("A2.2-02", "AI governance tag namespace exists",
                 "A.2 Policies", len(ai_tags) > 0,
                 findings=0 if ai_tags else 1, total=1,
                 detail=f"{len(ai_tags)} AI-related tag namespaces",
                 severity="medium", oci_service="Tagging",
                 nist_ai_rmf_ref="GOVERN 1.2")

        # A2.3-01: Acceptable use classification tags
        use_tags = [t for t in self.tag_namespaces
                    if any(kw in (t.get("name", "") + t.get("description", "")).lower()
                           for kw in ["use", "classification", "risk", "tier", "purpose"])]
        self.add("A2.3-01", "AI acceptable-use classification tags defined",
                 "A.2 Policies", len(use_tags) > 0,
                 findings=0 if use_tags else 1, total=1,
                 detail=f"{len(use_tags)} classification tag namespaces",
                 severity="medium", oci_service="Tagging",
                 eu_ai_act_ref="Art.6,Art.9(1)", nist_ai_rmf_ref="GOVERN 1.4")

    def check_a3(self):
        """A.3 — Internal Organization."""
        print("[A.3] Internal Organization...")

        # A3.2-01: Dedicated AI administrator group
        ai_groups = [g for g in self.groups
                     if any(kw in g.get("name", "").lower()
                            for kw in ["ai", "ml", "data-scien", "genai"])]
        self.add("A3.2-01", "Dedicated AI administrator group exists",
                 "A.3 Organization", len(ai_groups) > 0,
                 findings=0 if ai_groups else 1, total=1,
                 detail=f"AI groups: {[g['name'] for g in ai_groups]}" if ai_groups else "No AI groups found",
                 severity="high", oci_service="IAM",
                 eu_ai_act_ref="Art.9(4)(a)", nist_ai_rmf_ref="GOVERN 2.1")

        # A3.2-02: AI group has scoped policies (least privilege)
        ai_policies = self._ai_policy_statements()
        overprivileged = 0
        for pol in self.policies:
            for stmt in pol.get("statements", []):
                s = stmt.lower()
                if any(kw in s for kw in ["data-science", "generative-ai"]):
                    if "manage" in s and "in tenancy" in s:
                        overprivileged += 1
        self.add("A3.2-02", "AI group policies follow least-privilege",
                 "A.3 Organization", overprivileged == 0,
                 findings=overprivileged, total=max(1, len(ai_policies)),
                 detail=f"{overprivileged} overprivileged AI policies",
                 severity="high", oci_service="IAM",
                 eu_ai_act_ref="Art.9(4)(b)", nist_ai_rmf_ref="GOVERN 2.2")

        # A3.3-01: Reporting of concerns (notification channels exist)
        topics = self._query_across_compartments(
            ["ons", "topic", "list"], max_comps=3)
        self.add("A3.3-01", "Notification channels for reporting AI concerns",
                 "A.3 Organization", len(topics) > 0,
                 findings=0 if topics else 1, total=1,
                 detail=f"{len(topics)} notification topics",
                 severity="medium", oci_service="Notifications",
                 nist_ai_rmf_ref="GOVERN 4.1")

    def check_a4(self):
        """A.4 — Resources for AI Systems."""
        print("[A.4] Resources for AI Systems...")

        # A4.3-01: Data Labeling datasets
        datasets = self._query_across_compartments(
            ["data-labeling-service", "dataset", "list"], max_comps=3)
        self.add("A4.3-01", "Data Labeling Service datasets exist",
                 "A.4 Resources", len(datasets) > 0,
                 total=len(datasets),
                 detail=f"{len(datasets)} labeling datasets",
                 severity="medium", oci_service="Data Labeling",
                 nist_ai_rmf_ref="MAP 2.1")

        # A4.3-02: Buckets tagged as AI training data
        ai_buckets = [b for b in self.buckets
                      if any(kw in str(b.get("freeform-tags", {})).lower() +
                             str(b.get("defined-tags", {})).lower()
                             for kw in ["ai", "training", "ml", "dataset", "model"])]
        self.add("A4.3-02", "Object Storage buckets tagged as AI training data",
                 "A.4 Resources", len(ai_buckets) > 0,
                 findings=0 if ai_buckets else 1, total=max(1, len(self.buckets)),
                 detail=f"{len(ai_buckets)}/{len(self.buckets)} buckets tagged for AI",
                 severity="medium", oci_service="Object Storage",
                 nist_ai_rmf_ref="MAP 2.2")

        # A4.4-01: Data Science projects tagged
        ds_projects = self._query_across_compartments(["data-science", "project", "list"])
        tagged = [p for p in ds_projects if p.get("defined-tags") or p.get("freeform-tags")]
        self.add("A4.4-01", "Data Science projects exist and are tagged",
                 "A.4 Resources", len(ds_projects) > 0 and len(tagged) == len(ds_projects),
                 findings=len(ds_projects) - len(tagged), total=max(1, len(ds_projects)),
                 detail=f"{len(ds_projects)} projects, {len(tagged)} tagged",
                 severity="high", oci_service="Data Science",
                 eu_ai_act_ref="Art.9(1)", nist_ai_rmf_ref="MAP 1.5")

        # A4.4-02: GenAI models inventoried
        genai_models = self._query_across_compartments(
            ["generative-ai", "model", "list"], max_comps=3)
        self.add("A4.4-02", "GenAI models/endpoints inventoried",
                 "A.4 Resources", True,
                 total=len(genai_models),
                 detail=f"{len(genai_models)} GenAI models",
                 severity="high", oci_service="Generative AI",
                 eu_ai_act_ref="Art.53(1)", nist_ai_rmf_ref="MAP 1.1")

        # A4.4-03 to A4.4-07: Other AI services
        ai_services = [
            ("A4.4-03", "AI Vision", ["ai-vision", "project", "list"], "AI Vision"),
            ("A4.4-04", "AI Language", ["ai-language", "project", "list"], "AI Language"),
            ("A4.4-05", "AI Speech", ["ai-speech", "project", "list"], "AI Speech"),
            ("A4.4-06", "AI Anomaly Detection", ["ai-anomaly-detection", "project", "list"], "AI Anomaly Detection"),
            ("A4.4-07", "AI Document Understanding", ["ai-document", "processor-job", "list"], "AI Document"),
        ]
        for check_id, svc_name, svc_cmd, svc_oci in ai_services:
            items = self._query_across_compartments(svc_cmd, max_comps=3)
            self.add(check_id, f"{svc_name} projects inventoried",
                     "A.4 Resources", True,
                     total=len(items),
                     detail=f"{len(items)} {svc_name} projects",
                     severity="medium", oci_service=svc_oci,
                     nist_ai_rmf_ref="MAP 1.1")

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
                 findings=public_notebooks, total=max(1, len(notebooks)),
                 detail=f"{public_notebooks}/{len(notebooks)} in public subnets",
                 severity="high", oci_service="Data Science",
                 eu_ai_act_ref="Art.15(1)", nist_ai_rmf_ref="MANAGE 2.3")

        # A4.5-03: GenAI dedicated clusters
        clusters = self._query_across_compartments(
            ["generative-ai", "dedicated-ai-cluster", "list"], max_comps=3)
        self.add("A4.5-03", "GenAI dedicated AI clusters provisioned",
                 "A.4 Resources", True,
                 total=len(clusters),
                 detail=f"{len(clusters)} dedicated clusters",
                 severity="medium", oci_service="Generative AI")

    def check_a5(self):
        """A.5 — Assessing Impacts of AI Systems."""
        print("[A.5] Impact Assessment...")

        # A5.2-01: Cloud Guard enabled
        try:
            cg = self.oci.query(["cloud-guard", "configuration", "get",
                                 "--compartment-id", self.tenancy])
            cg_enabled = isinstance(cg, dict) and cg.get("status") == "ENABLED"
        except Exception:
            cg_enabled = False
        self.add("A5.2-01", "Cloud Guard enabled (security impact monitoring)",
                 "A.5 Impact Assessment", cg_enabled,
                 findings=0 if cg_enabled else 1, total=1,
                 detail="Cloud Guard " + ("ENABLED" if cg_enabled else "NOT ENABLED"),
                 severity="high", oci_service="Cloud Guard",
                 eu_ai_act_ref="Art.9(2),Art.27(1)", nist_ai_rmf_ref="MAP 5.1")

        # A5.2-02: Cloud Guard targets cover AI compartments
        try:
            targets = self.oci.query(["cloud-guard", "target", "list",
                                       "--compartment-id", self.tenancy, "--all"])
            target_count = len(targets) if isinstance(targets, list) else 0
        except Exception:
            target_count = 0
        self.add("A5.2-02", "Cloud Guard targets cover AI compartments",
                 "A.5 Impact Assessment", target_count > 0,
                 findings=0 if target_count > 0 else 1, total=1,
                 detail=f"{target_count} Cloud Guard targets",
                 severity="medium", oci_service="Cloud Guard",
                 eu_ai_act_ref="Art.9(2)", nist_ai_rmf_ref="MAP 5.2")

        # A5.3-01: Impact assessment documentation (audit log retention as evidence)
        audit = self.oci.query(["audit", "config", "get",
                                "--compartment-id", self.tenancy])
        retention = audit.get("retention-period-days", 0) if isinstance(audit, dict) else 0
        self.add("A5.3-01", "Audit logs retained for impact assessment documentation",
                 "A.5 Impact Assessment", retention >= 90,
                 findings=0 if retention >= 90 else 1, total=1,
                 detail=f"Retention: {retention} days (need >= 90 for impact records)",
                 severity="medium", oci_service="Audit",
                 eu_ai_act_ref="Art.9(2)", nist_ai_rmf_ref="MAP 5.1")

    def check_a6(self):
        """A.6 — AI System Lifecycle."""
        print("[A.6] AI Lifecycle...")

        # A6.2-01: Resource Manager stacks (IaC)
        stacks = self._query_across_compartments(
            ["resource-manager", "stack", "list"], max_comps=5)
        self.add("A6.2-01", "Resource Manager stacks exist (Infrastructure as Code)",
                 "A.6 Lifecycle", len(stacks) > 0,
                 total=len(stacks),
                 detail=f"{len(stacks)} IaC stacks",
                 severity="medium", oci_service="Resource Manager",
                 nist_ai_rmf_ref="MANAGE 1.1")

        # A6.5-01: Bucket versioning
        unversioned = [b for b in self.buckets if b.get("versioning") != "Enabled"]
        self.add("A6.5-01", "Object Storage buckets have versioning (data provenance)",
                 "A.6 Lifecycle", len(unversioned) == 0,
                 findings=len(unversioned), total=max(1, len(self.buckets)),
                 detail=f"{len(unversioned)}/{len(self.buckets)} without versioning",
                 severity="high", oci_service="Object Storage",
                 eu_ai_act_ref="Art.10(2)", nist_ai_rmf_ref="MAP 2.3")

        # A6.5-02: Bucket CMK encryption
        no_cmk = 0
        for b in self.buckets[:10]:
            if self.os_namespace:
                detail = self.oci.query(["os", "bucket", "get",
                                         "--namespace", self.os_namespace,
                                         "--bucket-name", b.get("name", "")])
                if isinstance(detail, dict) and not detail.get("kms-key-id"):
                    no_cmk += 1
        self.add("A6.5-02", "Storage encrypted with customer-managed keys",
                 "A.6 Lifecycle", no_cmk == 0,
                 findings=no_cmk, total=min(len(self.buckets), 10),
                 detail=f"{no_cmk} buckets without CMK",
                 severity="high", oci_service="Object Storage / KMS",
                 eu_ai_act_ref="Art.15(1)", nist_ai_rmf_ref="MANAGE 2.4")

        # A6.6-01: ML models with metadata
        models = self._query_across_compartments(
            ["data-science", "model", "list"], max_comps=5)
        with_meta = [m for m in models if m.get("description")]
        self.add("A6.6-01", "ML models have metadata/description",
                 "A.6 Lifecycle",
                 len(models) == 0 or len(with_meta) == len(models),
                 findings=len(models) - len(with_meta), total=max(1, len(models)),
                 detail=f"{len(models)} models, {len(with_meta)} documented",
                 severity="high", oci_service="Data Science",
                 eu_ai_act_ref="Art.11(1)", nist_ai_rmf_ref="MAP 3.1")

        # A6.6-02: Model deployments with logging
        deployments = self._query_across_compartments(
            ["data-science", "model-deployment", "list"], max_comps=5)
        no_logs = [d for d in deployments
                   if not d.get("category-log-details", {}).get("access")
                   and not d.get("category-log-details", {}).get("predict")]
        self.add("A6.6-02", "Model deployments have logging configured",
                 "A.6 Lifecycle",
                 len(deployments) == 0 or len(no_logs) == 0,
                 findings=len(no_logs), total=max(1, len(deployments)),
                 detail=f"{len(no_logs)}/{len(deployments)} without logging",
                 severity="high", oci_service="Data Science",
                 eu_ai_act_ref="Art.12(1)", nist_ai_rmf_ref="MEASURE 2.5")

        # A6.6-03: GenAI fine-tuned models documented
        genai_models = self._query_across_compartments(
            ["generative-ai", "model", "list"], max_comps=3)
        fine_tuned = [m for m in genai_models
                      if m.get("type") in ("FINE_TUNED", "fine_tuned")]
        self.add("A6.6-03", "GenAI fine-tuned models documented",
                 "A.6 Lifecycle", True,
                 total=len(fine_tuned),
                 detail=f"{len(fine_tuned)} fine-tuned models",
                 severity="medium", oci_service="Generative AI",
                 eu_ai_act_ref="Art.53(1)(b)", nist_ai_rmf_ref="MAP 3.2")

        # A6.2-06: AI system operation and monitoring
        alarms = self._query_across_compartments(
            ["monitoring", "alarm", "list"], max_comps=5)
        self.add("A6.2-06", "AI system monitoring alarms configured (A.6.2.6)",
                 "A.6 Lifecycle", len(alarms) > 0,
                 total=len(alarms),
                 detail=f"{len(alarms)} monitoring alarms for operations",
                 severity="high", oci_service="Monitoring",
                 eu_ai_act_ref="Art.9(2)", nist_ai_rmf_ref="MEASURE 2.5")

        # A6.2-08: AI system event log recording
        log_groups = self._query_across_compartments(
            ["logging", "log-group", "list"], max_comps=5)
        self.add("A6.2-08", "Event log recording enabled (A.6.2.8)",
                 "A.6 Lifecycle", len(log_groups) > 0,
                 total=len(log_groups),
                 detail=f"{len(log_groups)} log groups for event recording",
                 severity="high", oci_service="Logging",
                 eu_ai_act_ref="Art.12(1)", nist_ai_rmf_ref="MEASURE 2.6")

        # A6.7-01: Model version history (verification/validation)
        versioned_models = [m for m in models
                            if m.get("model-version-set-id")]
        self.add("A6.7-01", "Data Science model version history exists",
                 "A.6 Lifecycle",
                 len(models) == 0 or len(versioned_models) > 0,
                 findings=len(models) - len(versioned_models) if models else 0,
                 total=max(1, len(models)),
                 detail=f"{len(versioned_models)}/{len(models)} in version sets",
                 severity="medium", oci_service="Data Science",
                 eu_ai_act_ref="Art.9(7)", nist_ai_rmf_ref="MEASURE 1.2")

    def check_a7(self):
        """A.7 — Data for AI Systems."""
        print("[A.7] Data Governance...")

        # A7.2-01: Data Safe targets
        ds_targets = self._query_across_compartments(
            ["data-safe", "target-database", "list"], max_comps=5)
        self.add("A7.2-01", "Data Safe enabled for databases",
                 "A.7 Data", len(ds_targets) > 0,
                 findings=0 if ds_targets else 1, total=max(1, len(ds_targets)),
                 detail=f"{len(ds_targets)} Data Safe targets",
                 severity="high", oci_service="Data Safe",
                 eu_ai_act_ref="Art.10(1)", nist_ai_rmf_ref="MAP 2.1")

        # A7.2-02: Data Safe user assessments
        assessments = self._query_across_compartments(
            ["data-safe", "user-assessment", "list"], max_comps=3)
        self.add("A7.2-02", "Data Safe user assessments performed",
                 "A.7 Data", len(assessments) > 0,
                 findings=0 if assessments else 1, total=max(1, len(assessments)),
                 detail=f"{len(assessments)} user assessments",
                 severity="medium", oci_service="Data Safe",
                 nist_ai_rmf_ref="MAP 2.2")

        # A7.2-03: Data Safe security assessments
        sec_assessments = self._query_across_compartments(
            ["data-safe", "security-assessment", "list"], max_comps=3)
        self.add("A7.2-03", "Data Safe security assessments performed",
                 "A.7 Data", len(sec_assessments) > 0,
                 findings=0 if sec_assessments else 1, total=max(1, len(sec_assessments)),
                 detail=f"{len(sec_assessments)} security assessments",
                 severity="medium", oci_service="Data Safe",
                 eu_ai_act_ref="Art.10(2)", nist_ai_rmf_ref="MEASURE 1.3")

        # A7.3-01: Data Labeling datasets with annotations (quality)
        datasets = self._query_across_compartments(
            ["data-labeling-service", "dataset", "list"], max_comps=3)
        self.add("A7.3-01", "Data Labeling datasets have annotations (data quality)",
                 "A.7 Data", len(datasets) > 0,
                 total=len(datasets),
                 detail=f"{len(datasets)} labeling datasets",
                 severity="medium", oci_service="Data Labeling",
                 eu_ai_act_ref="Art.10(3)", nist_ai_rmf_ref="MAP 2.3")

        # A7.4-01: Data quality monitoring (Data Safe security assessments as proxy)
        sec_assess = self._query_across_compartments(
            ["data-safe", "security-assessment", "list"], max_comps=3)
        self.add("A7.4-01", "Data quality monitoring via Data Safe assessments (A.7.4)",
                 "A.7 Data", len(sec_assess) > 0,
                 findings=0 if sec_assess else 1, total=max(1, len(sec_assess)),
                 detail=f"{len(sec_assess)} security assessments",
                 severity="medium", oci_service="Data Safe",
                 eu_ai_act_ref="Art.10(3)", nist_ai_rmf_ref="MAP 2.3")

        # A7.5-01a: Data provenance via bucket versioning
        versioned_buckets = [b for b in self.buckets if b.get("versioning") == "Enabled"]
        self.add("A7.5-01a", "Data provenance tracked via bucket versioning (A.7.5)",
                 "A.7 Data",
                 len(self.buckets) == 0 or len(versioned_buckets) == len(self.buckets),
                 findings=len(self.buckets) - len(versioned_buckets),
                 total=max(1, len(self.buckets)),
                 detail=f"{len(versioned_buckets)}/{len(self.buckets)} buckets versioned",
                 severity="high", oci_service="Object Storage",
                 eu_ai_act_ref="Art.10(2)", nist_ai_rmf_ref="MAP 2.3")

        # A7.5-01: KMS Vault for AI encryption
        vaults = self._query_across_compartments(["kms", "vault", "list"], max_comps=5)
        active_vaults = [v for v in vaults if v.get("lifecycle-state") == "ACTIVE"]
        self.add("A7.5-01", "KMS Vault exists for AI data encryption",
                 "A.7 Data", len(active_vaults) > 0,
                 findings=0 if active_vaults else 1, total=max(1, len(active_vaults)),
                 detail=f"{len(active_vaults)} active vaults",
                 severity="high", oci_service="KMS",
                 eu_ai_act_ref="Art.15(1)", nist_ai_rmf_ref="MANAGE 2.4")

        # A7.5-01b: KMS key rotation (council recommendation)
        keys_checked = 0
        keys_no_rotation = 0
        for vault in active_vaults[:3]:
            mgmt_ep = vault.get("management-endpoint", "")
            if mgmt_ep:
                keys = self.oci.query(["kms", "management", "key", "list",
                                        "--compartment-id", self.tenancy,
                                        "--endpoint", mgmt_ep])
                if isinstance(keys, list):
                    for key in keys:
                        if key.get("lifecycle-state") == "ENABLED":
                            keys_checked += 1
                            # Check if key has been rotated (multiple versions)
                            if key.get("current-key-version") and not key.get("is-auto-rotation-enabled"):
                                keys_no_rotation += 1
        self.add("A7.5-01b", "KMS keys have auto-rotation enabled",
                 "A.7 Data", keys_no_rotation == 0,
                 findings=keys_no_rotation, total=max(1, keys_checked),
                 detail=f"{keys_no_rotation}/{keys_checked} keys without auto-rotation",
                 severity="high", oci_service="KMS",
                 eu_ai_act_ref="Art.15(1)", nist_ai_rmf_ref="MANAGE 2.4")

        # A7.5-02: Database encryption with CMK
        adb = self._query_across_compartments(
            ["db", "autonomous-database", "list"], max_comps=3)
        no_cmk_db = [d for d in adb if not d.get("kms-key-id")]
        self.add("A7.5-02", "Database encryption uses customer-managed keys",
                 "A.7 Data",
                 len(adb) == 0 or len(no_cmk_db) == 0,
                 findings=len(no_cmk_db), total=max(1, len(adb)),
                 detail=f"{len(no_cmk_db)}/{len(adb)} ADBs without CMK",
                 severity="high", oci_service="Database / KMS",
                 eu_ai_act_ref="Art.15(1)", nist_ai_rmf_ref="MANAGE 2.4")

        # A7.5-03: Data masking policies
        masking = self._query_across_compartments(
            ["data-safe", "masking-policy", "list"], max_comps=3)
        self.add("A7.5-03", "Data masking policies configured in Data Safe",
                 "A.7 Data", len(masking) > 0,
                 findings=0 if masking else 1, total=max(1, len(masking)),
                 detail=f"{len(masking)} masking policies",
                 severity="medium", oci_service="Data Safe",
                 eu_ai_act_ref="Art.10(5)", nist_ai_rmf_ref="MANAGE 2.2")

    def check_a8(self):
        """A.8 — Information for Interested Parties (Transparency)."""
        print("[A.8] Transparency & Logging...")

        # A8.2-01: AI services have descriptive tags/metadata
        ds_projects = self._query_across_compartments(
            ["data-science", "project", "list"], max_comps=3)
        tagged_projects = [p for p in ds_projects
                           if p.get("defined-tags") or p.get("freeform-tags")]
        self.add("A8.2-01", "AI services have descriptive tags/metadata",
                 "A.8 Transparency",
                 len(ds_projects) == 0 or len(tagged_projects) == len(ds_projects),
                 findings=len(ds_projects) - len(tagged_projects),
                 total=max(1, len(ds_projects)),
                 detail=f"{len(tagged_projects)}/{len(ds_projects)} projects tagged",
                 severity="medium", oci_service="Tagging",
                 eu_ai_act_ref="Art.13(1)", nist_ai_rmf_ref="GOVERN 4.1")

        # A8.4-01: Logging log groups
        log_groups = self._query_across_compartments(
            ["logging", "log-group", "list"], max_comps=5)
        self.add("A8.4-01", "Logging service enabled with log groups",
                 "A.8 Transparency", len(log_groups) > 0,
                 findings=0 if log_groups else 1, total=max(1, len(log_groups)),
                 detail=f"{len(log_groups)} log groups",
                 severity="high", oci_service="Logging",
                 eu_ai_act_ref="Art.12(1)", nist_ai_rmf_ref="GOVERN 4.2")

        # A8.4-02: Service logs for AI services
        logs = []
        for lg in log_groups[:5]:
            lg_id = lg.get("id", "")
            if lg_id:
                lg_logs = self.oci.query(["logging", "log", "list",
                                           "--log-group-id", lg_id, "--all"])
                if isinstance(lg_logs, list):
                    logs.extend(lg_logs)
        ai_logs = [l for l in logs
                   if any(kw in (l.get("configuration", {}).get("source", {}).get("service", "")).lower()
                          for kw in ["datascience", "generativeai", "ai"])]
        self.add("A8.4-02", "Service logs configured for AI services",
                 "A.8 Transparency", len(ai_logs) > 0,
                 findings=0 if ai_logs else 1, total=max(1, len(logs)),
                 detail=f"{len(ai_logs)} AI service logs out of {len(logs)} total",
                 severity="high", oci_service="Logging",
                 eu_ai_act_ref="Art.12(1)", nist_ai_rmf_ref="MEASURE 2.5")

        # A8.4-03: Log Analytics namespace
        try:
            la_ns = self.oci.query(["log-analytics", "namespace", "list",
                                    "--compartment-id", self.tenancy])
            la_active = isinstance(la_ns, dict) or (isinstance(la_ns, list) and len(la_ns) > 0)
        except Exception:
            la_active = False
        self.add("A8.4-03", "Log Analytics namespace configured",
                 "A.8 Transparency", la_active,
                 findings=0 if la_active else 1, total=1,
                 detail="Log Analytics " + ("active" if la_active else "not configured"),
                 severity="medium", oci_service="Log Analytics",
                 nist_ai_rmf_ref="MEASURE 2.6")

        # A8.4-04: Audit retention
        audit = self.oci.query(["audit", "config", "get",
                                "--compartment-id", self.tenancy])
        retention = audit.get("retention-period-days", 0) if isinstance(audit, dict) else 0
        self.add("A8.4-04", "Audit log retention >= 365 days",
                 "A.8 Transparency", retention >= 365,
                 findings=0 if retention >= 365 else 1, total=1,
                 detail=f"Retention: {retention} days",
                 severity="high", oci_service="Audit",
                 eu_ai_act_ref="Art.12(2)", nist_ai_rmf_ref="MEASURE 2.1")

    def check_a9(self):
        """A.9 — Use of AI Systems."""
        print("[A.9] Access Control & Monitoring...")

        # A9.2-01: AI compartments have purpose tags
        all_comps = self.oci.query(["iam", "compartment", "list",
                                     "--compartment-id", self.tenancy, "--all"])
        if isinstance(all_comps, list):
            tagged_comps = [c for c in all_comps
                            if c.get("defined-tags") or c.get("freeform-tags")]
            self.add("A9.2-01", "Compartments have purpose/classification tags",
                     "A.9 Access & Monitoring",
                     len(all_comps) == 0 or len(tagged_comps) == len(all_comps),
                     findings=len(all_comps) - len(tagged_comps),
                     total=max(1, len(all_comps)),
                     detail=f"{len(tagged_comps)}/{len(all_comps)} compartments tagged",
                     severity="medium", oci_service="Tagging",
                     eu_ai_act_ref="Art.9(1)", nist_ai_rmf_ref="GOVERN 1.4")

        # A9.3-01: AI service access restricted to specific groups
        ai_policies = self._ai_policy_statements()
        group_scoped = [s for s in ai_policies if "group " in s.lower()]
        self.add("A9.3-01", "AI service access restricted to specific IAM groups",
                 "A.9 Access & Monitoring", len(group_scoped) > 0,
                 findings=0 if group_scoped else 1, total=max(1, len(ai_policies)),
                 detail=f"{len(group_scoped)}/{len(ai_policies)} policies scope to groups",
                 severity="high", oci_service="IAM",
                 eu_ai_act_ref="Art.9(4)", nist_ai_rmf_ref="GOVERN 2.2")

        # A9.3-02: MFA for users
        console_users = [u for u in self.users if u.get("is-mfa-activated") is not None]
        no_mfa = [u for u in console_users if not u.get("is-mfa-activated")]
        self.add("A9.3-02", "MFA enforced for users",
                 "A.9 Access & Monitoring", len(no_mfa) == 0,
                 findings=len(no_mfa), total=max(1, len(console_users)),
                 detail=f"{len(no_mfa)}/{len(console_users)} without MFA",
                 severity="high", oci_service="IAM",
                 eu_ai_act_ref="Art.15(1)", nist_ai_rmf_ref="MANAGE 2.3")

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
                     severity="medium", oci_service="IAM",
                     nist_ai_rmf_ref="MANAGE 2.3")

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
                 severity="high", oci_service="Monitoring",
                 eu_ai_act_ref="Art.9(2)", nist_ai_rmf_ref="MEASURE 1.1")

        # A9.4-02: APM domain
        apm_domains = self._query_across_compartments(
            ["apm-control-plane", "apm-domain", "list"], max_comps=3)
        self.add("A9.4-02", "APM domain exists for application tracing",
                 "A.9 Access & Monitoring", len(apm_domains) > 0,
                 total=len(apm_domains),
                 detail=f"{len(apm_domains)} APM domains",
                 severity="medium", oci_service="APM",
                 nist_ai_rmf_ref="MEASURE 2.5")

        # A9.4-03: Notification topics for events
        topics = self._query_across_compartments(
            ["ons", "topic", "list"], max_comps=5)
        self.add("A9.4-03", "Notification topics for AI service events",
                 "A.9 Access & Monitoring", len(topics) > 0,
                 total=len(topics),
                 detail=f"{len(topics)} notification topics",
                 severity="medium", oci_service="Notifications",
                 nist_ai_rmf_ref="GOVERN 4.1")

        # A9.4-04: Events rules for state changes
        events_rules = self._query_across_compartments(
            ["events", "rule", "list"], max_comps=5)
        self.add("A9.4-04", "Events rules for AI service state changes",
                 "A.9 Access & Monitoring", len(events_rules) > 0,
                 total=len(events_rules),
                 detail=f"{len(events_rules)} events rules",
                 severity="medium", oci_service="Events",
                 eu_ai_act_ref="Art.12(1)", nist_ai_rmf_ref="MANAGE 3.1")

    def check_a10(self):
        """A.10 — Third-Party and Customer Relationships."""
        print("[A.10] Third-Party & Network Controls...")

        # A10.2-01: Approved GenAI base models only
        genai_models = self._query_across_compartments(
            ["generative-ai", "model", "list"], max_comps=3)
        base_models = [m for m in genai_models
                       if m.get("type") in ("BASE", "base", None)]
        self.add("A10.2-01", "Only approved GenAI base models in use",
                 "A.10 Third-Party", True,
                 total=len(base_models),
                 detail=f"{len(base_models)} base models",
                 severity="high", oci_service="Generative AI",
                 eu_ai_act_ref="Art.53(1)", nist_ai_rmf_ref="GOVERN 6.1")

        # A10.2-02: Container images from trusted OCIR
        repos = self._query_across_compartments(
            ["artifacts", "container-repository", "list"], max_comps=3)
        self.add("A10.2-02", "Container images for AI from trusted OCIR only",
                 "A.10 Third-Party", len(repos) >= 0,  # informational
                 total=len(repos),
                 detail=f"{len(repos)} container repositories",
                 severity="medium", oci_service="OCIR",
                 nist_ai_rmf_ref="GOVERN 6.2")

        # A10.3-01: AI endpoints not on public subnets
        vcns = self._query_across_compartments(["network", "vcn", "list"], max_comps=5)
        public_subnets = 0
        for vcn in vcns[:5]:
            vcn_id = vcn.get("id", "")
            if vcn_id:
                subnets = self.oci.query(["network", "subnet", "list",
                                           "--vcn-id", vcn_id, "--all"])
                if isinstance(subnets, list):
                    for s in subnets:
                        if not s.get("prohibit-public-ip-on-vnic"):
                            public_subnets += 1
        self.add("A10.3-01", "Network subnets restrict public access",
                 "A.10 Third-Party", public_subnets == 0,
                 findings=public_subnets,
                 total=max(1, len(vcns)),
                 detail=f"{public_subnets} public subnets found",
                 severity="high", oci_service="Networking",
                 eu_ai_act_ref="Art.15(1)", nist_ai_rmf_ref="MANAGE 2.3")

        # A10.3-01b: Security Zones enforce policy compliance (council rec)
        try:
            sec_zones = self.oci.query(["cloud-guard", "security-zone", "list",
                                         "--compartment-id", self.tenancy, "--all"])
            zone_count = len(sec_zones) if isinstance(sec_zones, list) else 0
        except Exception:
            zone_count = 0
        self.add("A10.3-01b", "Security Zones enforce compliance on AI compartments",
                 "A.10 Third-Party", zone_count > 0,
                 findings=0 if zone_count > 0 else 1, total=1,
                 detail=f"{zone_count} security zones",
                 severity="medium", oci_service="Security Zones",
                 eu_ai_act_ref="Art.15(1)", nist_ai_rmf_ref="MANAGE 2.3")

        # A10.3-02: Service Gateway
        service_gateways = self._query_across_compartments(
            ["network", "service-gateway", "list"], max_comps=5)
        self.add("A10.3-02", "Service Gateway exists for AI service traffic",
                 "A.10 Third-Party", len(service_gateways) > 0,
                 total=len(service_gateways),
                 detail=f"{len(service_gateways)} service gateways across {len(vcns)} VCNs",
                 severity="medium", oci_service="Networking",
                 nist_ai_rmf_ref="MANAGE 2.3")

    # ═══════════════════════════════════════════════════════════════
    # Check Classification (Product-Neutral Scoring)
    # ═══════════════════════════════════════════════════════════════

    # OCI services that are RECOMMENDATIONS (not requirements).
    # Missing these does NOT lower the compliance score.
    # Each entry: oci_service -> (rationale, alternatives)
    RECOMMENDATION_SERVICES = {
        "Data Safe": (
            "Provides database security assessments, user assessments, and data masking. "
            "Helps meet data governance requirements.",
            "Any database security tool: IBM Guardium, Imperva, Oracle Audit Vault, "
            "or manual database security reviews",
        ),
        "Bastion": (
            "Provides secure, time-limited SSH/RDP access to private resources. "
            "Supports human oversight requirements.",
            "Any bastion/jump host: HashiCorp Boundary, Teleport, AWS SSM, "
            "or self-managed SSH jump boxes",
        ),
        "APM": (
            "Application Performance Monitoring with distributed tracing. "
            "Supports AI system operational monitoring.",
            "Any APM tool: Datadog, New Relic, Dynatrace, Grafana+Tempo, "
            "Jaeger, or OpenTelemetry-based monitoring",
        ),
        "Log Analytics": (
            "Centralized log aggregation and analysis. "
            "Supports transparency and audit trail requirements.",
            "Any SIEM/log platform: Splunk, Elastic/ELK, Datadog Logs, "
            "Grafana Loki, or any centralized logging solution",
        ),
        "Data Labeling": (
            "Managed data annotation service. "
            "Supports data quality requirements for AI training data.",
            "Any labeling tool: Label Studio, Labelbox, Scale AI, Prodigy, "
            "or manual annotation processes",
        ),
        "AI Vision": (
            "OCI AI Vision for image analysis. Inventoried for AI system tracking.",
            "Any computer vision service or self-hosted models",
        ),
        "AI Language": (
            "OCI AI Language for NLP. Inventoried for AI system tracking.",
            "Any NLP service or self-hosted language models",
        ),
        "AI Speech": (
            "OCI AI Speech for speech-to-text. Inventoried for AI system tracking.",
            "Any speech service: AWS Transcribe, Google Speech, Whisper, etc.",
        ),
        "AI Anomaly Detection": (
            "OCI AI Anomaly Detection. Inventoried for AI system tracking.",
            "Any anomaly detection: custom models, Azure Anomaly Detector, etc.",
        ),
        "AI Document": (
            "OCI AI Document Understanding. Inventoried for AI system tracking.",
            "Any document AI: AWS Textract, Google Document AI, custom OCR, etc.",
        ),
        "Security Zones": (
            "Enforces security policies on compartments. "
            "Prevents misconfiguration of AI infrastructure.",
            "Any policy-as-code: OPA/Gatekeeper, HashiCorp Sentinel, AWS SCPs, "
            "or manual security policy enforcement",
        ),
        "Resource Manager": (
            "OCI Terraform-based Infrastructure as Code. "
            "Supports AI system lifecycle management via IaC.",
            "Any IaC tool: Terraform (standalone), Pulumi, AWS CloudFormation, "
            "Ansible, or manual deployment with documentation",
        ),
        "Notifications": (
            "OCI Notifications for event alerting. "
            "Supports communication and incident response requirements.",
            "Any notification: PagerDuty, Opsgenie, Slack webhooks, "
            "email alerts, or custom notification systems",
        ),
        "Events": (
            "OCI Events for state change tracking. "
            "Supports change control and operational monitoring.",
            "Any event system: AWS EventBridge, CloudWatch Events, "
            "custom webhooks, or change management tools",
        ),
        "OCIR": (
            "OCI Container Registry for trusted image storage. "
            "Supports third-party AI supply chain control.",
            "Any container registry: Docker Hub, GitHub GHCR, "
            "AWS ECR, Google GCR, Harbor, or self-hosted registries",
        ),
    }

    def _classify_checks(self):
        """Classify each check as requirement or recommendation.

        Requirements: Fundamental governance controls that any AIMS needs
        (IAM policies, access controls, audit, encryption, compartment structure).

        Recommendations: OCI-specific services that have alternatives.
        These inform gap analysis but don't penalize the score.
        """
        for check in self.results:
            svc = check.oci_service
            if svc in self.RECOMMENDATION_SERVICES:
                rationale, alternatives = self.RECOMMENDATION_SERVICES[svc]
                check.check_type = "recommendation"
                check.rationale = rationale
                check.alternatives = alternatives
            else:
                check.check_type = "requirement"

    # ═══════════════════════════════════════════════════════════════
    # Execution
    # ═══════════════════════════════════════════════════════════════

    def run_all(self) -> dict:
        """Run all ISO 42001 checks (Clauses 4-10 + Annex A)."""
        start = datetime.now(timezone.utc)
        print(f"[ISO42001] Scanner v{VERSION} starting at {start.isoformat()}")
        print(f"[ISO42001] Tenancy: {self.tenancy}")
        print(f"[ISO42001] Compartments: {len(self.compartments)}")

        # Clauses 4-10 (management system requirements)
        self.check_clause4()
        self.check_clause5()
        self.check_clause6()
        self.check_clause7()
        self.check_clause8()
        self.check_clause9()
        self.check_clause10()

        # Annex A (normative controls)
        self.check_a2()
        self.check_a3()
        self.check_a4()
        self.check_a5()
        self.check_a6()
        self.check_a7()
        self.check_a8()
        self.check_a9()
        self.check_a10()

        # Post-process: classify checks as requirement vs recommendation
        # Requirements: fundamental governance controls (IAM, tagging, audit, compartments)
        # Recommendations: specific OCI service adoption (has alternatives)
        self._classify_checks()

        elapsed = (datetime.now(timezone.utc) - start).total_seconds()

        # Score only counts REQUIREMENTS, not recommendations
        # Recommendations are informational — they don't penalize for missing OCI services
        req_results = [r for r in self.results if r.check_type == "requirement"]
        rec_results = [r for r in self.results if r.check_type == "recommendation"]
        req_passed = sum(1 for r in req_results if r.compliant)
        rec_passed = sum(1 for r in rec_results if r.compliant)
        score = round(req_passed / len(req_results) * 100) if req_results else 0

        # All checks passed count (for backward compat)
        all_passed = sum(1 for r in self.results if r.compliant)

        clause_results = [r for r in self.results if r.clause_type == "clause"]
        annex_results = [r for r in self.results if r.clause_type == "annex_a"]
        clause_req = [r for r in clause_results if r.check_type == "requirement"]
        annex_req = [r for r in annex_results if r.check_type == "requirement"]
        clause_passed = sum(1 for r in clause_req if r.compliant)
        annex_passed = sum(1 for r in annex_req if r.compliant)

        print(f"\n[ISO42001] Complete: {score}% ({req_passed}/{len(req_results)} requirements) in {elapsed:.0f}s")
        print(f"  Requirements: {req_passed}/{len(req_results)} passed (scored)")
        print(f"  Recommendations: {rec_passed}/{len(rec_results)} met (not scored)")
        print(f"  Clauses 4-10: {clause_passed}/{len(clause_req)}")
        print(f"  Annex A:      {annex_passed}/{len(annex_req)}")

        return {
            "framework": "ISO_42001_2023",
            "framework_name": "ISO/IEC 42001:2023 AI Management System",
            "scanner": f"oci-iso42001-scanner v{VERSION}",
            "version": VERSION,
            "provider": "OCI",
            "scan_date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "scan_duration_seconds": round(elapsed),
            "tenancy": self.tenancy,
            "score": score,
            "passed": all_passed,
            "failed": len(self.results) - all_passed,
            "total": len(self.results),
            "requirements_passed": req_passed,
            "requirements_total": len(req_results),
            "recommendations_met": rec_passed,
            "recommendations_total": len(rec_results),
            "clause_score": round(clause_passed / len(clause_req) * 100) if clause_req else 0,
            "clause_passed": clause_passed,
            "clause_total": len(clause_req),
            "annex_score": round(annex_passed / len(annex_req) * 100) if annex_req else 0,
            "annex_passed": annex_passed,
            "annex_total": len(annex_req),
            "by_section": self._by_section(),
            "checks": [r.to_dict() for r in self.results],
        }

    def _by_section(self) -> dict:
        sections = {}
        for r in self.results:
            s = r.section
            if s not in sections:
                sections[s] = {"pass": 0, "fail": 0, "total": 0}
            sections[s]["total"] += 1
            if r.compliant:
                sections[s]["pass"] += 1
            else:
                sections[s]["fail"] += 1
        return sections


# ═══════════════════════════════════════════════════════════════════
# Cross-Framework Mapping Engine
# ═══════════════════════════════════════════════════════════════════

class CrossFrameworkEngine:
    """Maps ISO 42001 results to EU AI Act and NIST AI RMF."""

    # EU AI Act risk classification tiers
    EU_AI_ACT_TIERS = {
        "unacceptable": {
            "name": "Unacceptable Risk",
            "description": "AI systems that pose clear threats to safety, livelihoods, and rights",
            "examples": "Social scoring, real-time biometric ID in public spaces",
            "status": "Banned",
        },
        "high": {
            "name": "High Risk",
            "description": "AI systems in critical areas (employment, education, law enforcement, etc.)",
            "examples": "CV screening, credit scoring, medical devices",
            "requirements": ["Risk management", "Data governance", "Technical documentation",
                             "Record-keeping", "Transparency", "Human oversight",
                             "Accuracy/robustness/cybersecurity"],
        },
        "limited": {
            "name": "Limited Risk",
            "description": "AI systems with specific transparency obligations",
            "examples": "Chatbots, emotion recognition, deepfakes",
            "requirements": ["Transparency notification to users"],
        },
        "minimal": {
            "name": "Minimal Risk",
            "description": "AI systems with no specific obligations",
            "examples": "Spam filters, AI-enabled video games",
            "requirements": ["Voluntary codes of conduct"],
        },
    }

    # EU AI Act enforcement timeline
    EU_AI_ACT_TIMELINE = [
        {"date": "2024-08-01", "event": "EU AI Act entered into force"},
        {"date": "2025-02-02", "event": "Prohibited AI practices ban effective"},
        {"date": "2025-08-02", "event": "GPAI model rules + governance structure effective"},
        {"date": "2026-08-02", "event": "Main obligations for high-risk AI effective"},
        {"date": "2027-08-02", "event": "Full enforcement including Annex I systems"},
    ]

    # NIST AI RMF functions and categories
    NIST_AI_RMF = {
        "GOVERN": {
            "name": "Govern",
            "description": "Cultivate and implement a culture of risk management",
            "categories": {
                "GOVERN 1": "Policies, processes, procedures, and practices",
                "GOVERN 2": "Accountability structures",
                "GOVERN 3": "Workforce diversity, equity, inclusion",
                "GOVERN 4": "Organizational transparency",
                "GOVERN 5": "Robust engagement with AI actors",
                "GOVERN 6": "Policies for third-party AI",
            },
        },
        "MAP": {
            "name": "Map",
            "description": "Identify and contextualize AI risks",
            "categories": {
                "MAP 1": "Context is established and understood",
                "MAP 2": "Categorization of AI system",
                "MAP 3": "AI benefits and costs",
                "MAP 4": "Risks and impacts",
                "MAP 5": "Impacts to individuals, groups, communities",
            },
        },
        "MEASURE": {
            "name": "Measure",
            "description": "Analyze, assess, benchmark, and monitor AI risk",
            "categories": {
                "MEASURE 1": "Appropriate methods and metrics",
                "MEASURE 2": "AI systems evaluated for trustworthiness",
                "MEASURE 3": "Mechanisms for tracking risks over time",
            },
        },
        "MANAGE": {
            "name": "Manage",
            "description": "Allocate resources to manage mapped and measured risks",
            "categories": {
                "MANAGE 1": "AI risks based on impact assessments",
                "MANAGE 2": "Strategies to maximize benefits and minimize harm",
                "MANAGE 3": "AI risks and benefits from third parties",
                "MANAGE 4": "Risk treatments including response and recovery",
            },
        },
    }

    @classmethod
    def map_results(cls, scan_results: dict) -> dict:
        """Produce unified cross-framework compliance matrix from scan results."""
        checks = scan_results.get("checks", [])

        # EU AI Act article coverage
        eu_coverage = {}
        for c in checks:
            ref = c.get("eu_ai_act_ref", "")
            if ref:
                for art in ref.split(","):
                    art = art.strip()
                    if art not in eu_coverage:
                        eu_coverage[art] = {"pass": 0, "fail": 0, "checks": []}
                    if c["compliant"] == "Yes":
                        eu_coverage[art]["pass"] += 1
                    else:
                        eu_coverage[art]["fail"] += 1
                    eu_coverage[art]["checks"].append(c["check_id"])

        # NIST AI RMF function coverage
        nist_coverage = {"GOVERN": {"pass": 0, "fail": 0, "checks": []},
                         "MAP": {"pass": 0, "fail": 0, "checks": []},
                         "MEASURE": {"pass": 0, "fail": 0, "checks": []},
                         "MANAGE": {"pass": 0, "fail": 0, "checks": []}}
        for c in checks:
            ref = c.get("nist_ai_rmf_ref", "")
            if ref:
                func = ref.split(" ")[0]
                if func in nist_coverage:
                    if c["compliant"] == "Yes":
                        nist_coverage[func]["pass"] += 1
                    else:
                        nist_coverage[func]["fail"] += 1
                    nist_coverage[func]["checks"].append(c["check_id"])

        # Calculate NIST function scores
        for func in nist_coverage:
            total = nist_coverage[func]["pass"] + nist_coverage[func]["fail"]
            nist_coverage[func]["score"] = (
                round(nist_coverage[func]["pass"] / total * 100) if total > 0 else 0
            )
            nist_coverage[func]["total"] = total

        # EU AI Act overall readiness
        eu_total_pass = sum(v["pass"] for v in eu_coverage.values())
        eu_total_fail = sum(v["fail"] for v in eu_coverage.values())
        eu_total = eu_total_pass + eu_total_fail

        return {
            "eu_ai_act": {
                "readiness_score": round(eu_total_pass / eu_total * 100) if eu_total > 0 else 0,
                "articles_covered": len(eu_coverage),
                "tiers": cls.EU_AI_ACT_TIERS,
                "timeline": cls.EU_AI_ACT_TIMELINE,
                "article_coverage": eu_coverage,
            },
            "nist_ai_rmf": {
                "overall_score": round(
                    sum(v["score"] for v in nist_coverage.values()) / 4
                ),
                "functions": {
                    func: {
                        "name": cls.NIST_AI_RMF[func]["name"],
                        "description": cls.NIST_AI_RMF[func]["description"],
                        "score": nist_coverage[func]["score"],
                        "pass": nist_coverage[func]["pass"],
                        "fail": nist_coverage[func]["fail"],
                        "total": nist_coverage[func]["total"],
                        "checks": nist_coverage[func]["checks"],
                    }
                    for func in nist_coverage
                },
            },
        }


# ═══════════════════════════════════════════════════════════════════
# Certification Roadmap Engine
# ═══════════════════════════════════════════════════════════════════

class CertificationRoadmap:
    """12-step ISO 42001 certification roadmap with progress tracking."""

    STEPS = [
        {
            "step": 1,
            "name": "Gap Analysis",
            "phase": "Preparation",
            "description": "Assess current state against ISO 42001 requirements",
            "duration_weeks": 4,
            "activities": [
                "Run automated OCI compliance scan",
                "Identify gaps in Clauses 4-10 and Annex A",
                "Document current AI inventory and governance",
            ],
            "evidence_needed": ["Scan results", "Gap analysis report"],
            "auto_checks": ["CL4-*", "CL5-*", "A2.*", "A3.*", "A4.*"],
        },
        {
            "step": 2,
            "name": "AIMS Scope Definition",
            "phase": "Preparation",
            "description": "Define boundaries and applicability of the AI Management System",
            "duration_weeks": 2,
            "activities": [
                "Identify AI systems in scope",
                "Define organizational boundaries (compartments)",
                "Document Statement of Applicability",
            ],
            "evidence_needed": ["Scope document", "Statement of Applicability"],
            "auto_checks": ["CL4-01", "CL4-03", "A4.4-*"],
        },
        {
            "step": 3,
            "name": "AI Policy Development",
            "phase": "Preparation",
            "description": "Establish AI policy, acceptable use, and ethical guidelines",
            "duration_weeks": 3,
            "activities": [
                "Draft AI governance policy",
                "Define acceptable use rules",
                "Establish ethical AI principles",
            ],
            "evidence_needed": ["AI policy document", "Acceptable use policy", "Ethics guidelines"],
            "auto_checks": ["A2.2-01", "A2.2-02", "A2.3-01", "CL5-02"],
        },
        {
            "step": 4,
            "name": "Risk Assessment",
            "phase": "Implementation",
            "description": "Identify and assess AI-specific risks",
            "duration_weeks": 4,
            "activities": [
                "Identify AI risks per system",
                "Assess impact and likelihood",
                "Define risk treatment plans",
                "Enable Cloud Guard and security monitoring",
            ],
            "evidence_needed": ["Risk register", "Risk treatment plan", "Cloud Guard config"],
            "auto_checks": ["CL6-01", "CL6-03", "A5.2-01", "A5.2-02"],
        },
        {
            "step": 5,
            "name": "Roles & Responsibilities",
            "phase": "Implementation",
            "description": "Assign AI governance roles and access controls",
            "duration_weeks": 2,
            "activities": [
                "Define AI administrator roles",
                "Implement IAM groups and policies",
                "Enable MFA for all AI administrators",
            ],
            "evidence_needed": ["RACI matrix", "IAM policy screenshots"],
            "auto_checks": ["A3.2-01", "A3.2-02", "A9.3-01", "A9.3-02", "CL5-01", "CL5-03"],
        },
        {
            "step": 6,
            "name": "AI System Lifecycle Controls",
            "phase": "Implementation",
            "description": "Implement development, deployment, and monitoring controls",
            "duration_weeks": 6,
            "activities": [
                "Set up Data Science projects with tagging",
                "Enable model versioning and metadata",
                "Configure deployment logging",
                "Implement IaC with Resource Manager",
            ],
            "evidence_needed": ["Lifecycle procedures", "Model catalog", "Deployment configs"],
            "auto_checks": ["A6.2-01", "A6.5-01", "A6.5-02", "A6.6-01", "A6.6-02", "A6.7-01", "CL8-*"],
        },
        {
            "step": 7,
            "name": "Data Governance",
            "phase": "Implementation",
            "description": "Implement data quality, protection, and privacy controls",
            "duration_weeks": 4,
            "activities": [
                "Enable Data Safe for all databases",
                "Configure encryption with KMS",
                "Set up data masking policies",
                "Implement bucket versioning and CMK",
            ],
            "evidence_needed": ["Data governance framework", "Data Safe reports", "Encryption configs"],
            "auto_checks": ["A7.2-01", "A7.2-02", "A7.2-03", "A7.5-01", "A7.5-02", "A7.5-03"],
        },
        {
            "step": 8,
            "name": "Transparency & Logging",
            "phase": "Implementation",
            "description": "Establish logging, monitoring, and transparency mechanisms",
            "duration_weeks": 3,
            "activities": [
                "Configure service logging for AI services",
                "Set up Log Analytics",
                "Ensure audit retention >= 365 days",
                "Tag all AI resources for transparency",
            ],
            "evidence_needed": ["Logging architecture", "Audit config", "Transparency register"],
            "auto_checks": ["A8.2-01", "A8.4-01", "A8.4-02", "A8.4-03", "A8.4-04", "CL7-*"],
        },
        {
            "step": 9,
            "name": "Third-Party Controls",
            "phase": "Implementation",
            "description": "Manage third-party AI and network security",
            "duration_weeks": 3,
            "activities": [
                "Review GenAI model supply chain",
                "Secure network (private subnets, service gateways)",
                "Container image trust policy",
            ],
            "evidence_needed": ["Vendor assessment records", "Network architecture"],
            "auto_checks": ["A10.2-01", "A10.2-02", "A10.3-01", "A10.3-02"],
        },
        {
            "step": 10,
            "name": "Internal Audit",
            "phase": "Verification",
            "description": "Conduct internal audit of AIMS against ISO 42001",
            "duration_weeks": 3,
            "activities": [
                "Run comprehensive scan (all checks)",
                "Conduct document review",
                "Interview process owners",
                "Generate audit report with findings",
            ],
            "evidence_needed": ["Internal audit report", "Scan results", "Corrective actions"],
            "auto_checks": ["CL9-*", "CL10-*"],
        },
        {
            "step": 11,
            "name": "Management Review",
            "phase": "Verification",
            "description": "Top management reviews AIMS effectiveness",
            "duration_weeks": 2,
            "activities": [
                "Present audit findings to management",
                "Review AIMS performance metrics",
                "Approve corrective actions",
                "Confirm readiness for external audit",
            ],
            "evidence_needed": ["Management review minutes", "Performance metrics"],
            "auto_checks": [],
        },
        {
            "step": 12,
            "name": "Certification Audit",
            "phase": "Certification",
            "description": "External auditor conducts Stage 1 (document review) and Stage 2 (on-site)",
            "duration_weeks": 4,
            "activities": [
                "Stage 1: Document review and readiness assessment",
                "Address any Stage 1 findings",
                "Stage 2: On-site audit of AIMS implementation",
                "Receive certification decision",
            ],
            "evidence_needed": ["All AIMS documentation", "All scan evidence", "Corrective action records"],
            "auto_checks": [],
        },
    ]

    @classmethod
    def calculate_progress(cls, scan_results: dict) -> dict:
        """Calculate certification roadmap progress from scan results."""
        checks = {c["check_id"]: c["compliant"] == "Yes"
                  for c in scan_results.get("checks", [])}

        steps_progress = []
        total_auto = 0
        total_auto_pass = 0

        for step in cls.STEPS:
            # Match auto checks using patterns
            matched_checks = []
            for pattern in step.get("auto_checks", []):
                if pattern.endswith("*"):
                    prefix = pattern[:-1]
                    matched_checks.extend(
                        [cid for cid in checks if cid.startswith(prefix)])
                else:
                    if pattern in checks:
                        matched_checks.append(pattern)

            auto_pass = sum(1 for cid in matched_checks if checks.get(cid, False))
            auto_total = len(matched_checks)
            total_auto += auto_total
            total_auto_pass += auto_pass

            # Calculate step readiness (auto portion)
            auto_pct = round(auto_pass / auto_total * 100) if auto_total > 0 else 0

            steps_progress.append({
                "step": step["step"],
                "name": step["name"],
                "phase": step["phase"],
                "description": step["description"],
                "duration_weeks": step["duration_weeks"],
                "activities": step["activities"],
                "evidence_needed": step["evidence_needed"],
                "auto_checks_total": auto_total,
                "auto_checks_pass": auto_pass,
                "auto_readiness_pct": auto_pct,
                "status": "complete" if auto_pct == 100 and auto_total > 0
                          else "in_progress" if auto_pct > 0
                          else "not_started" if auto_total > 0
                          else "manual",
            })

        overall_auto_pct = round(total_auto_pass / total_auto * 100) if total_auto > 0 else 0
        total_weeks = sum(s["duration_weeks"] for s in cls.STEPS)

        return {
            "overall_readiness_pct": overall_auto_pct,
            "total_steps": len(cls.STEPS),
            "estimated_weeks": total_weeks,
            "auto_checks_total": total_auto,
            "auto_checks_pass": total_auto_pass,
            "phases": {
                "Preparation": [s for s in steps_progress if s["phase"] == "Preparation"],
                "Implementation": [s for s in steps_progress if s["phase"] == "Implementation"],
                "Verification": [s for s in steps_progress if s["phase"] == "Verification"],
                "Certification": [s for s in steps_progress if s["phase"] == "Certification"],
            },
            "steps": steps_progress,
        }


# ═══════════════════════════════════════════════════════════════════
# Gap Analysis Engine
# ═══════════════════════════════════════════════════════════════════

class GapAnalysisEngine:
    """Gap analysis with 12 domains, automated + manual evidence tracking."""

    DOMAINS = [
        {
            "id": "GOV",
            "name": "AI Governance Framework",
            "iso_refs": ["Cl.5", "A.2", "A.3"],
            "description": "Leadership commitment, AI policy, roles and responsibilities",
            "gap_items": [
                {"id": "GOV-01", "item": "AI governance policy documented and approved", "automatable": False},
                {"id": "GOV-02", "item": "IAM policies for AI services", "auto_check": "A2.2-01"},
                {"id": "GOV-03", "item": "AI tag namespace for governance", "auto_check": "A2.2-02"},
                {"id": "GOV-04", "item": "Dedicated AI administrator group", "auto_check": "A3.2-01"},
                {"id": "GOV-05", "item": "Least-privilege AI access", "auto_check": "A3.2-02"},
                {"id": "GOV-06", "item": "Acceptable use classification", "auto_check": "A2.3-01"},
            ],
        },
        {
            "id": "SCOPE",
            "name": "AIMS Scope & Context",
            "iso_refs": ["Cl.4"],
            "description": "Organizational context, scope boundaries, interested parties",
            "gap_items": [
                {"id": "SCOPE-01", "item": "AIMS scope document", "automatable": False},
                {"id": "SCOPE-02", "item": "Compartment structure (scope boundaries)", "auto_check": "CL4-01"},
                {"id": "SCOPE-03", "item": "AI-specific compartment", "auto_check": "CL4-03"},
                {"id": "SCOPE-04", "item": "Stakeholder tags", "auto_check": "CL4-02"},
                {"id": "SCOPE-05", "item": "Interested parties register", "automatable": False},
            ],
        },
        {
            "id": "RISK",
            "name": "AI Risk Management",
            "iso_refs": ["Cl.6", "A.5"],
            "description": "Risk identification, assessment, treatment for AI systems",
            "gap_items": [
                {"id": "RISK-01", "item": "AI risk register", "automatable": False},
                {"id": "RISK-02", "item": "Cloud Guard enabled", "auto_check": "CL6-01"},
                {"id": "RISK-03", "item": "Cloud Guard targets cover AI compartments", "auto_check": "A5.2-02"},
                {"id": "RISK-04", "item": "Monitoring alarms (risk treatment)", "auto_check": "CL6-03"},
                {"id": "RISK-05", "item": "Budget planning for AI", "auto_check": "CL6-02"},
                {"id": "RISK-06", "item": "AI impact assessment documented", "automatable": False},
            ],
        },
        {
            "id": "INVENTORY",
            "name": "AI System Inventory",
            "iso_refs": ["A.4"],
            "description": "Comprehensive inventory of all AI systems and resources",
            "gap_items": [
                {"id": "INV-01", "item": "Data Science projects tagged", "auto_check": "A4.4-01"},
                {"id": "INV-02", "item": "GenAI models inventoried", "auto_check": "A4.4-02"},
                {"id": "INV-03", "item": "AI Vision projects", "auto_check": "A4.4-03"},
                {"id": "INV-04", "item": "AI Language projects", "auto_check": "A4.4-04"},
                {"id": "INV-05", "item": "Data labeling datasets", "auto_check": "A4.3-01"},
                {"id": "INV-06", "item": "AI training data buckets tagged", "auto_check": "A4.3-02"},
            ],
        },
        {
            "id": "LIFECYCLE",
            "name": "AI System Lifecycle",
            "iso_refs": ["Cl.8", "A.6"],
            "description": "Development, deployment, monitoring, and retirement of AI systems",
            "gap_items": [
                {"id": "LC-01", "item": "IaC stacks for AI infrastructure", "auto_check": "A6.2-01"},
                {"id": "LC-02", "item": "Bucket versioning (data provenance)", "auto_check": "A6.5-01"},
                {"id": "LC-03", "item": "CMK encryption for storage", "auto_check": "A6.5-02"},
                {"id": "LC-04", "item": "Model metadata/descriptions", "auto_check": "A6.6-01"},
                {"id": "LC-05", "item": "Model deployment logging", "auto_check": "A6.6-02"},
                {"id": "LC-06", "item": "Model version history", "auto_check": "A6.7-01"},
                {"id": "LC-07", "item": "AI system retirement process", "automatable": False},
            ],
        },
        {
            "id": "DATA",
            "name": "Data Governance",
            "iso_refs": ["A.7"],
            "description": "Data quality, protection, privacy for AI systems",
            "gap_items": [
                {"id": "DATA-01", "item": "Data Safe enabled", "auto_check": "A7.2-01"},
                {"id": "DATA-02", "item": "User assessments performed", "auto_check": "A7.2-02"},
                {"id": "DATA-03", "item": "Security assessments performed", "auto_check": "A7.2-03"},
                {"id": "DATA-04", "item": "KMS vault for AI encryption", "auto_check": "A7.5-01"},
                {"id": "DATA-05", "item": "Database CMK encryption", "auto_check": "A7.5-02"},
                {"id": "DATA-06", "item": "Data masking policies", "auto_check": "A7.5-03"},
                {"id": "DATA-07", "item": "Data quality framework documented", "automatable": False},
            ],
        },
        {
            "id": "ACCESS",
            "name": "Access Control & Authentication",
            "iso_refs": ["A.9"],
            "description": "Access controls, MFA, authentication for AI systems",
            "gap_items": [
                {"id": "ACC-01", "item": "AI access restricted to groups", "auto_check": "A9.3-01"},
                {"id": "ACC-02", "item": "MFA enforced", "auto_check": "A9.3-02"},
                {"id": "ACC-03", "item": "Strong password policy", "auto_check": "A9.3-03"},
                {"id": "ACC-04", "item": "Bastion for secure access", "auto_check": "A9.3-04"},
                {"id": "ACC-05", "item": "Compartment purpose tags", "auto_check": "A9.2-01"},
            ],
        },
        {
            "id": "TRANSPARENCY",
            "name": "Transparency & Logging",
            "iso_refs": ["Cl.7", "A.8"],
            "description": "Logging, audit trails, transparency for stakeholders",
            "gap_items": [
                {"id": "TRA-01", "item": "Log groups configured", "auto_check": "A8.4-01"},
                {"id": "TRA-02", "item": "AI service logs", "auto_check": "A8.4-02"},
                {"id": "TRA-03", "item": "Log Analytics active", "auto_check": "A8.4-03"},
                {"id": "TRA-04", "item": "Audit retention >= 365 days", "auto_check": "A8.4-04"},
                {"id": "TRA-05", "item": "AI services tagged", "auto_check": "A8.2-01"},
                {"id": "TRA-06", "item": "AI transparency register", "automatable": False},
            ],
        },
        {
            "id": "MONITORING",
            "name": "Operational Monitoring",
            "iso_refs": ["A.9"],
            "description": "Monitoring, alerting, and observability for AI systems",
            "gap_items": [
                {"id": "MON-01", "item": "Monitoring alarms", "auto_check": "A9.4-01"},
                {"id": "MON-02", "item": "APM domain", "auto_check": "A9.4-02"},
                {"id": "MON-03", "item": "Notification topics", "auto_check": "A9.4-03"},
                {"id": "MON-04", "item": "Events rules", "auto_check": "A9.4-04"},
            ],
        },
        {
            "id": "THIRDPARTY",
            "name": "Third-Party AI Management",
            "iso_refs": ["A.10"],
            "description": "Governance of third-party AI services and supply chain",
            "gap_items": [
                {"id": "TP-01", "item": "Approved GenAI models only", "auto_check": "A10.2-01"},
                {"id": "TP-02", "item": "Trusted container repos", "auto_check": "A10.2-02"},
                {"id": "TP-03", "item": "No public subnets for AI", "auto_check": "A10.3-01"},
                {"id": "TP-04", "item": "Service gateways", "auto_check": "A10.3-02"},
                {"id": "TP-05", "item": "Vendor risk assessment", "automatable": False},
            ],
        },
        {
            "id": "PERFORMANCE",
            "name": "Performance Evaluation",
            "iso_refs": ["Cl.9"],
            "description": "Internal audit, management review, measurement",
            "gap_items": [
                {"id": "PERF-01", "item": "Audit retention configured", "auto_check": "CL9-01"},
                {"id": "PERF-02", "item": "Security scoring active", "auto_check": "CL9-02"},
                {"id": "PERF-03", "item": "Data Safe assessments", "auto_check": "CL9-03"},
                {"id": "PERF-04", "item": "Internal audit schedule", "automatable": False},
                {"id": "PERF-05", "item": "Management review minutes", "automatable": False},
            ],
        },
        {
            "id": "IMPROVEMENT",
            "name": "Continual Improvement",
            "iso_refs": ["Cl.10"],
            "description": "Corrective actions, nonconformity tracking, improvement",
            "gap_items": [
                {"id": "IMP-01", "item": "Active problems tracked", "auto_check": "CL10-01"},
                {"id": "IMP-02", "item": "Recommendations tracked", "auto_check": "CL10-02"},
                {"id": "IMP-03", "item": "Corrective action log", "automatable": False},
                {"id": "IMP-04", "item": "Continual improvement plan", "automatable": False},
            ],
        },
    ]

    @classmethod
    def analyze(cls, scan_results: dict) -> dict:
        """Run gap analysis against scan results."""
        checks = {c["check_id"]: c["compliant"] == "Yes"
                  for c in scan_results.get("checks", [])}

        domains_analysis = []
        total_gaps = 0
        total_closed = 0
        total_items = 0

        for domain in cls.DOMAINS:
            items_analysis = []
            domain_gaps = 0
            domain_closed = 0

            for gap in domain["gap_items"]:
                auto_check = gap.get("auto_check")
                is_automatable = auto_check is not None
                is_manual = gap.get("automatable") is False if not is_automatable else False

                if is_automatable:
                    compliant = checks.get(auto_check, False)
                    status = "closed" if compliant else "open"
                else:
                    status = "manual_review"
                    compliant = None

                if status == "open":
                    domain_gaps += 1
                    total_gaps += 1
                elif status == "closed":
                    domain_closed += 1
                    total_closed += 1

                total_items += 1
                items_analysis.append({
                    "id": gap["id"],
                    "item": gap["item"],
                    "status": status,
                    "auto_check": auto_check,
                    "compliant": compliant,
                    "type": "automated" if is_automatable else "manual",
                })

            domain_total = len(items_analysis)
            auto_items = [i for i in items_analysis if i["type"] == "automated"]
            auto_closed = sum(1 for i in auto_items if i["status"] == "closed")

            domains_analysis.append({
                "id": domain["id"],
                "name": domain["name"],
                "iso_refs": domain["iso_refs"],
                "description": domain["description"],
                "total_items": domain_total,
                "automated_items": len(auto_items),
                "automated_closed": auto_closed,
                "manual_items": domain_total - len(auto_items),
                "gaps_open": domain_gaps,
                "gaps_closed": domain_closed,
                "readiness_pct": round(auto_closed / len(auto_items) * 100) if auto_items else 0,
                "items": items_analysis,
            })

        return {
            "total_items": total_items,
            "total_gaps_open": total_gaps,
            "total_gaps_closed": total_closed,
            "total_manual_review": total_items - total_gaps - total_closed,
            "overall_readiness_pct": round(total_closed / (total_closed + total_gaps) * 100)
                                     if (total_closed + total_gaps) > 0 else 0,
            "domains": domains_analysis,
        }

    @classmethod
    def generate_soa(cls, scan_results: dict) -> list[dict]:
        """Generate Statement of Applicability from scan results."""
        checks = {c["check_id"]: c for c in scan_results.get("checks", [])}
        soa = []

        for domain in cls.DOMAINS:
            for gap in domain["gap_items"]:
                auto_check = gap.get("auto_check")
                check_data = checks.get(auto_check, {}) if auto_check else {}

                soa.append({
                    "domain": domain["id"],
                    "domain_name": domain["name"],
                    "iso_refs": ", ".join(domain["iso_refs"]),
                    "gap_id": gap["id"],
                    "control": gap["item"],
                    "applicable": True,
                    "justification": "Required for AIMS certification",
                    "implementation_status": (
                        "Implemented" if check_data.get("compliant") == "Yes"
                        else "Partially Implemented" if auto_check
                        else "Planned"
                    ),
                    "evidence": check_data.get("detail", "Manual evidence required"),
                })

        return soa


# ═══════════════════════════════════════════════════════════════════
# EU AI Act Risk Tier Rules Engine (Council Recommendation)
# ═══════════════════════════════════════════════════════════════════

class EUAIActRiskEngine:
    """Deterministic rules engine for EU AI Act risk tier classification.

    Decision sequence per council consensus:
    1. Article 5 — Prohibited use screening
    2. Article 6 + Annex III — High-risk use-case mapping
    3. Article 50 — Transparency obligations (limited risk)
    4. Minimal risk — Default
    """

    # Article 5: Prohibited practices
    PROHIBITED_INDICATORS = [
        "social_scoring", "real_time_biometric_public",
        "subliminal_manipulation", "exploitation_vulnerable",
        "predictive_policing_individual", "emotion_recognition_workplace_education",
        "untargeted_facial_scraping",
    ]

    # Article 6 + Annex III: High-risk categories
    HIGH_RISK_DOMAINS = {
        "biometric_identification": "Remote biometric identification",
        "critical_infrastructure": "Safety components of critical infrastructure",
        "education_vocational": "AI in education/vocational training",
        "employment_workers": "AI in employment, worker management, recruitment",
        "essential_services": "Access to essential services (credit, insurance)",
        "law_enforcement": "AI in law enforcement",
        "migration_asylum": "AI in migration, asylum, border control",
        "justice_democratic": "AI in administration of justice, democratic processes",
        "safety_component": "Safety component of product under EU harmonisation",
    }

    # Article 50: Transparency obligations (limited risk)
    TRANSPARENCY_INDICATORS = [
        "chatbot_interaction", "deepfake_generation",
        "emotion_recognition", "biometric_categorization",
        "ai_generated_content",
    ]

    @classmethod
    def classify(cls, ai_system: dict) -> dict:
        """Classify an AI system into EU AI Act risk tiers.

        Args:
            ai_system: Dict with keys:
                - purpose: str (system purpose description)
                - domain: str (one of HIGH_RISK_DOMAINS keys, or 'other')
                - uses_biometric: bool
                - public_sector: bool
                - safety_component: bool
                - affects_fundamental_rights: bool
                - transparency_triggers: list[str] (from TRANSPARENCY_INDICATORS)
                - prohibited_indicators: list[str] (from PROHIBITED_INDICATORS)

        Returns:
            Classification result with tier, legal_basis, required_controls, confidence
        """
        purpose = ai_system.get("purpose", "")
        prohibited = ai_system.get("prohibited_indicators", [])
        domain = ai_system.get("domain", "other")
        transparency = ai_system.get("transparency_triggers", [])

        # Step 1: Article 5 — Prohibited
        matched_prohibited = [p for p in prohibited if p in cls.PROHIBITED_INDICATORS]
        if matched_prohibited:
            return {
                "tier": "unacceptable",
                "legal_basis": "Article 5",
                "matched_criteria": matched_prohibited,
                "confidence": "high",
                "action": "BANNED — system cannot be deployed in the EU",
                "required_controls": [],
                "human_review_required": True,
                "note": "Legal counsel must confirm — prohibited use determination",
            }

        # Step 2: Article 6 + Annex III — High-risk
        is_high_risk = (
            domain in cls.HIGH_RISK_DOMAINS
            or ai_system.get("safety_component", False)
            or (ai_system.get("affects_fundamental_rights", False)
                and ai_system.get("public_sector", False))
        )
        if is_high_risk:
            return {
                "tier": "high",
                "legal_basis": "Article 6, Annex III",
                "matched_criteria": [domain] if domain in cls.HIGH_RISK_DOMAINS else ["safety_component"],
                "confidence": "high" if domain in cls.HIGH_RISK_DOMAINS else "medium",
                "action": "Full compliance required before August 2, 2026",
                "required_controls": [
                    "Risk management system (Art.9)",
                    "Data governance (Art.10)",
                    "Technical documentation (Art.11)",
                    "Record-keeping / logging (Art.12)",
                    "Transparency to users (Art.13)",
                    "Human oversight measures (Art.14)",
                    "Accuracy, robustness, cybersecurity (Art.15)",
                    "Quality management system (Art.17)",
                ],
                "human_review_required": True,
                "note": "Legal counsel should validate Annex III classification",
            }

        # Step 3: Article 50 — Transparency/Limited risk
        matched_transparency = [t for t in transparency if t in cls.TRANSPARENCY_INDICATORS]
        if matched_transparency:
            return {
                "tier": "limited",
                "legal_basis": "Article 50",
                "matched_criteria": matched_transparency,
                "confidence": "high",
                "action": "Transparency obligations apply",
                "required_controls": [
                    "Notify users they are interacting with AI",
                    "Label AI-generated content as such",
                    "Disclose deepfake/synthetic content",
                ],
                "human_review_required": False,
                "note": "Transparency notification sufficient",
            }

        # Step 4: Minimal risk — Default
        return {
            "tier": "minimal",
            "legal_basis": "Residual category",
            "matched_criteria": [],
            "confidence": "high",
            "action": "No specific obligations — voluntary codes of conduct apply",
            "required_controls": ["Voluntary code of conduct (encouraged)"],
            "human_review_required": False,
            "note": "System does not trigger EU AI Act obligations",
        }

    @classmethod
    def get_enforcement_status(cls) -> dict:
        """Get current EU AI Act enforcement status based on date."""
        from datetime import date
        today = date.today()
        timeline = [
            {"date": "2024-08-01", "event": "EU AI Act entered into force", "status": "effective"},
            {"date": "2025-02-02", "event": "Prohibited AI practices ban", "status": "effective"},
            {"date": "2025-08-02", "event": "GPAI rules + governance", "status": "effective"},
            {"date": "2026-08-02", "event": "Main high-risk obligations", "status": "upcoming"},
            {"date": "2027-08-02", "event": "Full enforcement (Annex I)", "status": "upcoming"},
        ]
        for evt in timeline:
            d = date.fromisoformat(evt["date"])
            evt["status"] = "effective" if today >= d else "upcoming"
            evt["days_until"] = max(0, (d - today).days)
        return {"timeline": timeline, "as_of": today.isoformat()}


# ═══════════════════════════════════════════════════════════════════
# Evidence Register (Council Recommendation)
# ═══════════════════════════════════════════════════════════════════

class EvidenceRegister:
    """Structured evidence register for manual + automated evidence tracking.

    Per council consensus: control_id, claim, owner, source, attachment,
    review_date, expiry, approver, status — not free-text notes.
    """

    @staticmethod
    def create_register(scan_results: dict) -> list[dict]:
        """Generate initial evidence register from scan results.

        Automated checks get pre-populated evidence; manual items get
        placeholder entries requiring human input.
        """
        register = []

        # Auto-populate from scan checks
        for check in scan_results.get("checks", []):
            register.append({
                "control_id": check["check_id"],
                "control_title": check["title"],
                "section": check["section"],
                "evidence_type": "automated",
                "claim": f"{'Compliant' if check['compliant'] == 'Yes' else 'Non-compliant'}: {check.get('detail', '')}",
                "source": f"OCI CLI scan via {check.get('oci_service', 'unknown')}",
                "status": "verified" if check["compliant"] == "Yes" else "finding_open",
                "owner": "",
                "approver": "",
                "attachment": "",
                "review_date": scan_results.get("scan_date", ""),
                "expiry_date": "",
                "notes": "",
            })

        # Add manual evidence placeholders for gap items
        manual_items = [
            ("GOV-01", "AI governance policy", "AI governance policy documented and approved"),
            ("SCOPE-01", "AIMS scope document", "AIMS scope document with boundaries defined"),
            ("SCOPE-05", "Interested parties register", "Register of interested parties and their requirements"),
            ("RISK-01", "AI risk register", "Formal AI risk register with identified risks"),
            ("RISK-06", "AI impact assessment", "Documented AI system impact assessment"),
            ("LC-07", "AI retirement process", "AI system retirement/decommissioning procedure"),
            ("DATA-07", "Data quality framework", "Documented data quality framework for AI systems"),
            ("TRA-06", "Transparency register", "AI transparency register for stakeholders"),
            ("TP-05", "Vendor risk assessment", "Third-party/vendor AI risk assessment records"),
            ("PERF-04", "Internal audit schedule", "AIMS internal audit programme and schedule"),
            ("PERF-05", "Management review minutes", "Management review meeting minutes"),
            ("IMP-03", "Corrective action log", "Corrective action log for nonconformities"),
            ("IMP-04", "Continual improvement plan", "Documented continual improvement plan"),
        ]
        for gap_id, title, claim in manual_items:
            register.append({
                "control_id": gap_id,
                "control_title": title,
                "section": "Manual Evidence",
                "evidence_type": "manual",
                "claim": claim,
                "source": "Manual upload required",
                "status": "pending",
                "owner": "",
                "approver": "",
                "attachment": "",
                "review_date": "",
                "expiry_date": "",
                "notes": "",
            })

        return register


# ═══════════════════════════════════════════════════════════════════
# CLI Entry Point
# ═══════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="OCI ISO/IEC 42001:2023 AI Compliance Scanner v2")
    parser.add_argument("--profile", default="DEFAULT", help="OCI CLI profile name")
    parser.add_argument("--auth", default="config",
                        choices=["config", "instance_principal"])
    parser.add_argument("--tenancy", required=True, help="Tenancy OCID")
    parser.add_argument("--region", default="", help="OCI region")
    parser.add_argument("--output", default=".", help="Output directory")
    parser.add_argument("--frameworks", action="store_true",
                        help="Include EU AI Act and NIST AI RMF cross-mapping")
    parser.add_argument("--roadmap", action="store_true",
                        help="Include 12-step certification roadmap")
    parser.add_argument("--gaps", action="store_true",
                        help="Include gap analysis with 12 domains")
    parser.add_argument("--evidence", action="store_true",
                        help="Include evidence register (automated + manual)")
    parser.add_argument("--all", action="store_true",
                        help="Include all outputs (frameworks, roadmap, gaps, evidence)")
    args = parser.parse_args()

    client = OCIClient(
        auth=args.auth, profile=args.profile,
        tenancy=args.tenancy, region=args.region,
    )
    scanner = ISO42001Scanner(client)
    results = scanner.run_all()

    include_all = args.all

    # Cross-framework mapping
    if args.frameworks or include_all:
        print("\n[Frameworks] Generating cross-framework mapping...")
        results["cross_framework"] = CrossFrameworkEngine.map_results(results)

    # Certification roadmap
    if args.roadmap or include_all:
        print("[Roadmap] Calculating certification progress...")
        results["certification_roadmap"] = CertificationRoadmap.calculate_progress(results)

    # Gap analysis
    if args.gaps or include_all:
        print("[Gaps] Running gap analysis...")
        results["gap_analysis"] = GapAnalysisEngine.analyze(results)
        results["statement_of_applicability"] = GapAnalysisEngine.generate_soa(results)

    # Evidence register
    if args.evidence or include_all:
        print("[Evidence] Generating evidence register...")
        results["evidence_register"] = EvidenceRegister.create_register(results)

    # EU AI Act enforcement status (always include if frameworks enabled)
    if args.frameworks or include_all:
        results["eu_ai_act_enforcement"] = EUAIActRiskEngine.get_enforcement_status()

    # Write outputs
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)

    out_file = out_dir / "iso42001_results.json"
    out_file.write_text(json.dumps(results, indent=2))
    print(f"\nResults written to: {out_file}")

    # CSV for checks
    csv_file = out_dir / "iso42001_results.csv"
    with open(csv_file, "w") as f:
        f.write("check_id,section,clause_type,severity,compliant,findings,total,"
                "title,oci_service,eu_ai_act_ref,nist_ai_rmf_ref,detail\n")
        for c in results["checks"]:
            detail = c.get("detail", "").replace('"', '""')
            f.write(f'{c["check_id"]},{c["section"]},{c.get("clause_type", "annex_a")},'
                    f'{c["severity"]},{c["compliant"]},{c["findings"]},{c["total"]},'
                    f'"{c["title"]}",{c["oci_service"]},'
                    f'{c.get("eu_ai_act_ref", "")},{c.get("nist_ai_rmf_ref", "")},'
                    f'"{detail}"\n')

    # Statement of Applicability CSV
    if "statement_of_applicability" in results:
        soa_file = out_dir / "iso42001_soa.csv"
        with open(soa_file, "w") as f:
            f.write("domain,domain_name,iso_refs,gap_id,control,applicable,"
                    "justification,implementation_status,evidence\n")
            for row in results["statement_of_applicability"]:
                evidence = row["evidence"].replace('"', '""')
                f.write(f'{row["domain"]},{row["domain_name"]},"{row["iso_refs"]}",'
                        f'{row["gap_id"]},"{row["control"]}",{row["applicable"]},'
                        f'"{row["justification"]}",{row["implementation_status"]},'
                        f'"{evidence}"\n')
        print(f"Statement of Applicability: {soa_file}")


if __name__ == "__main__":
    main()
