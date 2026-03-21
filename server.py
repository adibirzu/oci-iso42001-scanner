#!/usr/bin/env python3
"""
OCI ISO/IEC 42001:2023 Scanner HTTP API Server.

Wraps scanner.py as a lightweight HTTP API for integration with:
  - OCI-DEMO Control Plane (proxy at /api/compliance/iso42001/*)
  - MCP tools (database-observatory iso42001 tools)
  - Standalone web dashboard

Runs on port 8080 by default. Designed for 1 OCPU OL8 instances.

Usage:
    # Start with instance principal auth (production)
    python server.py --auth instance_principal --tenancy <OCID>

    # Start with config profile (development)
    python server.py --profile cap --tenancy <OCID> --port 8080
"""
from __future__ import annotations

import argparse
import json
import os
import threading
import time
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from scanner import (
    OCIClient, ISO42001Scanner, CrossFrameworkEngine,
    CertificationRoadmap, GapAnalysisEngine, EUAIActRiskEngine,
    EvidenceRegister, VERSION,
)

# Global state
_latest_results = None
_scan_running = False
_scan_lock = threading.Lock()
_client = None
_results_dir = Path("/tmp/iso42001-results")
_scan_history: list[dict] = []
MAX_HISTORY = 30


# ── Remediation Catalog ──

REMEDIATIONS = {
    "CL4-03": {
        "title": "Create AI-specific compartment",
        "steps": [
            "oci iam compartment create --name ai-workloads --compartment-id <TENANCY> --description 'AI/ML workloads compartment'",
            "Apply tags: AIGovernance.Purpose=ai-workloads",
        ],
        "alternatives": "Any cloud provider with resource grouping (AWS Accounts, Azure Resource Groups, GCP Projects)",
    },
    "CL5-02": {
        "title": "Create AI governance policies",
        "steps": [
            "Create IAM policy: allow group ai-admins to manage generative-ai-family in compartment ai-workloads",
            "Create IAM policy: allow group ai-admins to manage data-science-family in compartment ai-workloads",
        ],
        "alternatives": "AWS IAM policies for SageMaker/Bedrock, Azure RBAC for Azure AI",
    },
    "CL9-01": {
        "title": "Enable 365-day audit log retention",
        "steps": [
            "oci audit config update --compartment-id <TENANCY> --retention-period-days 365",
        ],
        "alternatives": "AWS CloudTrail with S3 lifecycle, Azure Activity Log with Log Analytics workspace retention",
    },
    "A2.2-01": {
        "title": "Create AI service IAM policies",
        "steps": [
            "oci iam policy create --name ai-governance-policy --compartment-id <TENANCY> --statements '[\"allow group ai-admins to manage generative-ai-family in tenancy\"]'",
        ],
        "alternatives": "Any IAM system with service-scoped access controls",
    },
    "A6.5-01": {
        "title": "Enable bucket versioning for data provenance",
        "steps": [
            "oci os bucket update --name <BUCKET> --versioning Enabled --namespace <NS>",
        ],
        "alternatives": "AWS S3 versioning, Azure Blob soft-delete, GCS object versioning",
    },
    "A6.5-02": {
        "title": "Enable customer-managed encryption keys",
        "steps": [
            "oci kms management vault create --compartment-id <COMP> --display-name ai-vault --vault-type DEFAULT",
            "oci kms management key create --compartment-id <COMP> --display-name ai-master-key --key-shape '{\"algorithm\":\"AES\",\"length\":32}'",
            "oci os bucket update --name <BUCKET> --kms-key-id <KEY_OCID>",
        ],
        "alternatives": "AWS KMS with CMK, Azure Key Vault, GCP Cloud KMS",
    },
    "A7.5-01": {
        "title": "Create KMS Vault for AI data encryption",
        "steps": [
            "oci kms management vault create --compartment-id <COMP> --display-name ai-data-vault --vault-type DEFAULT",
        ],
        "alternatives": "AWS KMS, Azure Key Vault, GCP Cloud KMS, HashiCorp Vault",
    },
    "A8.4-02": {
        "title": "Configure logging for AI services",
        "steps": [
            "oci logging log-group create --compartment-id <COMP> --display-name ai-service-logs",
            "oci logging log create --log-group-id <LG_ID> --display-name datascience-log --log-type SERVICE --configuration '{\"source\":{\"service\":\"datascience\",\"resource\":\"\",\"category\":\"all\"}}'",
        ],
        "alternatives": "AWS CloudWatch Logs for SageMaker, Azure Monitor for Azure AI",
    },
    "A9.3-02": {
        "title": "Enforce MFA for all users",
        "steps": [
            "Navigate to OCI Console → Identity → Authentication Settings",
            "Enable MFA for all users or at minimum AI administrator groups",
        ],
        "alternatives": "Any IdP with MFA support (Okta, Azure AD, Google Workspace)",
    },
}


def _load_standard_ref() -> dict:
    """Load the ISO 42001 standard reference data."""
    ref_file = Path(__file__).parent / "config" / "standard_reference.json"
    if ref_file.exists():
        return json.loads(ref_file.read_text())
    return {}


def _enrich_checks_with_standard(results: dict, ref: dict):
    """Add ISO standard requirement text, guidance, and OCI mapping to each check."""
    # Build a lookup: check_id -> {requirement, guidance, oci_mapping, control_objective}
    check_lookup = {}
    for clause_id, clause in ref.get("clauses", {}).items():
        for sec_id, sec in clause.get("sections", {}).items():
            for cid in sec.get("checks", []):
                check_lookup[cid] = {
                    "iso_clause": f"Clause {clause_id}",
                    "iso_section": sec_id,
                    "iso_section_title": sec.get("title", ""),
                    "iso_requirement": sec.get("requirement", ""),
                    "oci_mapping": sec.get("oci_mapping", ""),
                }
    for annex_id, annex in ref.get("annex_a", {}).items():
        for ctrl_id, ctrl in annex.get("controls", {}).items():
            for cid in ctrl.get("checks", []):
                check_lookup[cid] = {
                    "iso_clause": f"Annex A",
                    "iso_section": ctrl_id,
                    "iso_section_title": ctrl.get("topic", ""),
                    "iso_control": ctrl.get("control", ""),
                    "iso_guidance": ctrl.get("implementation_guidance", ""),
                    "oci_mapping": ctrl.get("oci_mapping", ""),
                    "control_objective": annex.get("objective", ""),
                }
    for check in results.get("checks", []):
        cid = check.get("check_id", "")
        if cid in check_lookup:
            check["standard_ref"] = check_lookup[cid]


def _generate_executive_summary(results: dict) -> dict:
    """Generate an executive summary from scan results."""
    checks = results.get("checks", [])
    score = results.get("score", 0)
    req_passed = results.get("requirements_passed", 0)
    req_total = results.get("requirements_total", 0)
    failed_high = [c for c in checks if c.get("compliant") == "No" and c.get("severity") == "high"]
    failed_medium = [c for c in checks if c.get("compliant") == "No" and c.get("severity") == "medium"]

    # Risk level
    if score >= 80:
        risk_level, risk_color = "LOW", "#4ade80"
    elif score >= 50:
        risk_level, risk_color = "MODERATE", "#fbbf24"
    else:
        risk_level, risk_color = "HIGH", "#f87171"

    # Top 5 critical findings
    critical_findings = []
    for c in sorted(failed_high, key=lambda x: x.get("section", "")):
        critical_findings.append({
            "check_id": c["check_id"],
            "title": c["title"],
            "section": c["section"],
            "detail": c.get("detail", ""),
            "oci_service": c.get("oci_service", ""),
        })

    # Section-level summary
    sections = results.get("by_section", {})
    weakest = sorted(sections.items(), key=lambda x: x[1]["pass"] / max(x[1]["total"], 1))[:3]
    strongest = sorted(sections.items(), key=lambda x: x[1]["pass"] / max(x[1]["total"], 1), reverse=True)[:3]

    # Severity distribution
    severity_dist = {"high": 0, "medium": 0, "low": 0}
    for c in checks:
        if c.get("compliant") == "No":
            sev = c.get("severity", "medium")
            severity_dist[sev] = severity_dist.get(sev, 0) + 1

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan_date": results.get("scan_date"),
        "overall_score": score,
        "risk_level": risk_level,
        "risk_color": risk_color,
        "requirements": {"passed": req_passed, "total": req_total},
        "total_checks": len(checks),
        "passed": results.get("passed", 0),
        "failed": results.get("failed", 0),
        "severity_distribution": severity_dist,
        "critical_findings": critical_findings[:10],
        "critical_findings_count": len(failed_high),
        "medium_findings_count": len(failed_medium),
        "weakest_areas": [{"section": s, "pass": v["pass"], "total": v["total"],
                           "pct": round(v["pass"] / max(v["total"], 1) * 100)} for s, v in weakest],
        "strongest_areas": [{"section": s, "pass": v["pass"], "total": v["total"],
                             "pct": round(v["pass"] / max(v["total"], 1) * 100)} for s, v in strongest],
        "recommended_actions": [
            f"Address {len(failed_high)} high-severity findings as priority",
            "Establish AI-specific IAM policies and compartments" if any(c["check_id"].startswith("A2") or c["check_id"] == "CL5-02" for c in failed_high) else None,
            "Enable audit log retention >= 365 days" if any(c["check_id"] in ("CL9-01", "A8.4-04") for c in failed_high) else None,
            "Implement KMS encryption with customer-managed keys" if any(c["check_id"] in ("A7.5-01", "A6.5-02") for c in failed_high) else None,
            "Enforce MFA for all users" if any(c["check_id"] == "A9.3-02" for c in failed_high) else None,
            "Enable bucket versioning for data provenance" if any(c["check_id"] in ("A6.5-01", "A7.5-01a") for c in failed_high) else None,
        ],
    }


def _generate_risk_matrix(results: dict) -> dict:
    """Generate a severity x section risk matrix."""
    checks = results.get("checks", [])
    matrix = {}
    for c in checks:
        section = c.get("section", "Other")
        sev = c.get("severity", "medium")
        if section not in matrix:
            matrix[section] = {"high": {"pass": 0, "fail": 0}, "medium": {"pass": 0, "fail": 0}, "low": {"pass": 0, "fail": 0}}
        status = "pass" if c.get("compliant") == "Yes" else "fail"
        matrix[section][sev][status] += 1

    # Calculate risk scores per section (weighted: high=3, medium=2, low=1)
    risk_scores = []
    for section, sevs in sorted(matrix.items()):
        weighted_risk = sevs["high"]["fail"] * 3 + sevs["medium"]["fail"] * 2 + sevs["low"]["fail"]
        total = sum(s["pass"] + s["fail"] for s in sevs.values())
        risk_scores.append({
            "section": section,
            "high_fail": sevs["high"]["fail"],
            "medium_fail": sevs["medium"]["fail"],
            "low_fail": sevs["low"]["fail"],
            "total_pass": sum(s["pass"] for s in sevs.values()),
            "total_fail": sum(s["fail"] for s in sevs.values()),
            "total": total,
            "weighted_risk": weighted_risk,
            "risk_level": "critical" if weighted_risk >= 6 else "high" if weighted_risk >= 3 else "medium" if weighted_risk >= 1 else "low",
        })

    return {
        "matrix": matrix,
        "risk_scores": sorted(risk_scores, key=lambda x: -x["weighted_risk"]),
        "total_weighted_risk": sum(r["weighted_risk"] for r in risk_scores),
        "max_possible_risk": len(checks) * 3,
    }


def _run_scan():
    """Run a full scan in background thread."""
    global _latest_results, _scan_running
    try:
        scanner = ISO42001Scanner(_client)
        results = scanner.run_all()

        # Always include all v2 features
        results["cross_framework"] = CrossFrameworkEngine.map_results(results)
        results["certification_roadmap"] = CertificationRoadmap.calculate_progress(results)
        results["gap_analysis"] = GapAnalysisEngine.analyze(results)
        results["statement_of_applicability"] = GapAnalysisEngine.generate_soa(results)
        results["evidence_register"] = EvidenceRegister.create_register(results)
        results["eu_ai_act_enforcement"] = EUAIActRiskEngine.get_enforcement_status()

        # Enrich checks with standard reference data
        ref = _load_standard_ref()
        if ref:
            _enrich_checks_with_standard(results, ref)

        # Generate executive summary and risk matrix
        results["executive_summary"] = _generate_executive_summary(results)
        results["risk_matrix"] = _generate_risk_matrix(results)

        _latest_results = results

        # Persist to disk (latest + timestamped history)
        _results_dir.mkdir(parents=True, exist_ok=True)
        out = _results_dir / "latest.json"
        out.write_text(json.dumps(results, indent=2))

        ts = results.get("scan_timestamp", datetime.now(timezone.utc).isoformat())
        hist_file = _results_dir / f"scan_{ts[:19].replace(':', '-')}.json"
        hist_file.write_text(json.dumps(results, indent=2))

        # Update in-memory history
        _scan_history.append({
            "scan_date": results.get("scan_date"),
            "scan_timestamp": ts,
            "score": results.get("score"),
            "passed": results.get("passed"),
            "total": results.get("total"),
            "requirements_passed": results.get("requirements_passed"),
            "requirements_total": results.get("requirements_total"),
        })
        # Keep only the last N entries
        while len(_scan_history) > MAX_HISTORY:
            _scan_history.pop(0)

        print(f"[Server] Scan complete. {results['total']} checks, score={results['score']}%")
    except Exception as e:
        print(f"[Server] Scan error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        with _scan_lock:
            _scan_running = False


def _load_cached():
    """Load most recent scan results from disk."""
    global _latest_results
    cached = _results_dir / "latest.json"
    if cached.exists():
        try:
            _latest_results = json.loads(cached.read_text())
            print(f"[Server] Loaded cached results from {cached}")
            # Seed history from cached
            if _latest_results:
                _scan_history.append({
                    "scan_date": _latest_results.get("scan_date"),
                    "scan_timestamp": _latest_results.get("scan_timestamp"),
                    "score": _latest_results.get("score"),
                    "passed": _latest_results.get("passed"),
                    "total": _latest_results.get("total"),
                    "requirements_passed": _latest_results.get("requirements_passed"),
                    "requirements_total": _latest_results.get("requirements_total"),
                })
        except Exception:
            pass


class ScannerHandler(BaseHTTPRequestHandler):
    """HTTP request handler for scanner API."""

    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        print(f"[API] {args[0]} {args[1]}")

    def _send_json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html, status=200):
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, msg, status=500):
        self._send_json({"error": msg}, status)

    def do_OPTIONS(self):
        self._send_json({})

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        params = parse_qs(parsed.query)

        # Health / Root
        if path in ("", "/", "/health", "/api/health"):
            return self._send_json({
                "status": "ok",
                "scanner": f"oci-iso42001-scanner v{VERSION}",
                "has_results": _latest_results is not None,
                "scan_running": _scan_running,
                "tenancy": _client.tenancy if _client else "",
                "last_scan": _latest_results.get("scan_timestamp") if _latest_results else None,
            })

        # ── ISO 42001 Endpoints ──

        if path == "/api/iso42001/summary":
            if not _latest_results:
                return self._send_json({"error": "No scan results. POST /api/iso42001/scan first."}, 404)
            summary = {k: v for k, v in _latest_results.items()
                       if k not in ("cross_framework", "certification_roadmap",
                                    "gap_analysis", "statement_of_applicability",
                                    "evidence_register", "eu_ai_act_enforcement")}
            return self._send_json(summary)

        if path == "/api/iso42001/checks":
            if not _latest_results:
                return self._send_json({"error": "No scan results"}, 404)
            checks = _latest_results.get("checks", [])
            # Filter by query params
            severity = params.get("severity", [None])[0]
            status_filter = params.get("status", [None])[0]  # "failed" or "passed"
            section = params.get("section", [None])[0]
            check_type = params.get("type", [None])[0]  # "requirement" or "recommendation"
            if severity:
                checks = [c for c in checks if c.get("severity") == severity]
            if status_filter == "failed":
                checks = [c for c in checks if c.get("compliant") == "No"]
            elif status_filter == "passed":
                checks = [c for c in checks if c.get("compliant") == "Yes"]
            if section:
                checks = [c for c in checks if section.lower() in c.get("section", "").lower()]
            if check_type:
                checks = [c for c in checks if c.get("check_type") == check_type]
            return self._send_json({
                "checks": checks,
                "total": len(checks),
                "filters": {"severity": severity, "status": status_filter,
                             "section": section, "type": check_type},
            })

        if path == "/api/iso42001/remediation":
            check_id = params.get("check_id", [None])[0]
            if check_id and check_id in REMEDIATIONS:
                return self._send_json({"check_id": check_id, **REMEDIATIONS[check_id]})
            if check_id:
                return self._send_json({"error": f"No remediation for {check_id}"}, 404)
            # Return full catalog
            return self._send_json({
                "catalog": REMEDIATIONS,
                "total": len(REMEDIATIONS),
            })

        if path == "/api/iso42001/executive-summary":
            if not _latest_results:
                return self._send_json({"error": "No scan results"}, 404)
            return self._send_json(
                _latest_results.get("executive_summary", _generate_executive_summary(_latest_results)))

        if path == "/api/iso42001/risk-matrix":
            if not _latest_results:
                return self._send_json({"error": "No scan results"}, 404)
            return self._send_json(
                _latest_results.get("risk_matrix", _generate_risk_matrix(_latest_results)))

        if path == "/api/iso42001/standard":
            # Serve the full ISO 42001 standard reference with OCI mapping
            ref_file = Path(__file__).parent / "config" / "standard_reference.json"
            if ref_file.exists():
                return self._send_json(json.loads(ref_file.read_text()))
            return self._send_json({"error": "Standard reference not available"}, 404)

        if path.startswith("/api/iso42001/standard/"):
            # Serve specific clause or annex: /api/iso42001/standard/A.7 or /api/iso42001/standard/5
            ref_file = Path(__file__).parent / "config" / "standard_reference.json"
            if not ref_file.exists():
                return self._send_json({"error": "Standard reference not available"}, 404)
            ref = json.loads(ref_file.read_text())
            key = path.split("/api/iso42001/standard/")[1]
            if key in ref.get("clauses", {}):
                return self._send_json(ref["clauses"][key])
            if key in ref.get("annex_a", {}):
                return self._send_json(ref["annex_a"][key])
            return self._send_json({"error": f"Section '{key}' not found"}, 404)

        if path == "/api/iso42001/trend":
            if len(_scan_history) < 2:
                return self._send_json({"error": "Need at least 2 scans for trend analysis"}, 404)
            current = _scan_history[-1]
            previous = _scan_history[-2]
            score_delta = (current.get("score", 0) or 0) - (previous.get("score", 0) or 0)
            passed_delta = (current.get("passed", 0) or 0) - (previous.get("passed", 0) or 0)
            return self._send_json({
                "current": current,
                "previous": previous,
                "score_delta": score_delta,
                "passed_delta": passed_delta,
                "direction": "improving" if score_delta > 0 else "declining" if score_delta < 0 else "stable",
                "total_scans": len(_scan_history),
                "trend_data": [{"date": s.get("scan_date"), "score": s.get("score")} for s in _scan_history],
            })

        if path == "/api/iso42001/history":
            return self._send_json({
                "scans": _scan_history,
                "total": len(_scan_history),
            })

        if path == "/api/iso42001/roadmap":
            if not _latest_results:
                return self._send_json({"error": "No scan results"}, 404)
            return self._send_json(
                _latest_results.get("certification_roadmap", {"error": "Roadmap not generated"}))

        if path == "/api/iso42001/gaps":
            if not _latest_results:
                return self._send_json({"error": "No scan results"}, 404)
            return self._send_json(
                _latest_results.get("gap_analysis", {"error": "Gap analysis not generated"}))

        if path == "/api/iso42001/frameworks":
            if not _latest_results:
                return self._send_json({"error": "No scan results"}, 404)
            data = _latest_results.get("cross_framework", {})
            data["eu_ai_act_enforcement"] = _latest_results.get("eu_ai_act_enforcement", {})
            return self._send_json(data)

        if path == "/api/iso42001/soa":
            if not _latest_results:
                return self._send_json({"error": "No scan results"}, 404)
            return self._send_json({
                "statement_of_applicability": _latest_results.get("statement_of_applicability", []),
                "total_controls": len(_latest_results.get("statement_of_applicability", [])),
            })

        if path == "/api/iso42001/evidence":
            if not _latest_results:
                return self._send_json({"error": "No scan results"}, 404)
            register = _latest_results.get("evidence_register", [])
            return self._send_json({
                "evidence_register": register,
                "total": len(register),
                "automated": sum(1 for e in register if e["evidence_type"] == "automated"),
                "manual": sum(1 for e in register if e["evidence_type"] == "manual"),
                "verified": sum(1 for e in register if e["status"] == "verified"),
                "pending": sum(1 for e in register if e["status"] == "pending"),
                "findings_open": sum(1 for e in register if e["status"] == "finding_open"),
            })

        if path == "/api/iso42001/scan/status":
            return self._send_json({
                "running": _scan_running,
                "has_results": _latest_results is not None,
                "last_scan": _latest_results.get("scan_timestamp") if _latest_results else None,
                "score": _latest_results.get("score") if _latest_results else None,
            })

        if path == "/api/iso42001/report":
            if not _latest_results:
                return self._send_error("No scan results. POST /api/iso42001/scan first.", 404)
            return self._send_html(self._generate_html_report(_latest_results))

        # ── Legacy CIS endpoints (passthrough for backward compat) ──

        if path == "/api/summary":
            if _latest_results:
                return self._send_json({
                    "score": _latest_results.get("score"),
                    "passed": _latest_results.get("passed"),
                    "total": _latest_results.get("total"),
                    "scan_date": _latest_results.get("scan_date"),
                    "framework": "ISO_42001_2023",
                })
            return self._send_json({"error": "No results"}, 404)

        if path == "/api/scan/status":
            return self._send_json({"running": _scan_running})

        self._send_error(f"Unknown endpoint: {path}", 404)

    def _generate_html_report(self, results: dict) -> str:
        """Generate an HTML compliance report in Oracle Redwood style."""
        from html import escape

        checks = results.get("checks", [])
        score = results.get("score", 0)
        scan_date = results.get("scan_date", "N/A")
        scan_ts = results.get("scan_timestamp", "")
        passed = results.get("passed", 0)
        failed = results.get("failed", 0)
        total = results.get("total", 0)
        req_passed = results.get("requirements_passed", 0)
        req_total = results.get("requirements_total", 0)

        # Risk level
        if score >= 80:
            risk_level, risk_color = "LOW", "#4ade80"
        elif score >= 50:
            risk_level, risk_color = "MODERATE", "#fbbf24"
        else:
            risk_level, risk_color = "HIGH", "#f87171"

        # Severity distribution of failures
        sev_dist = {"high": 0, "medium": 0, "low": 0}
        for c in checks:
            if c.get("compliant") == "No":
                sev_dist[c.get("severity", "medium")] = sev_dist.get(c.get("severity", "medium"), 0) + 1

        # Section breakdown
        by_section = results.get("by_section", {})
        section_rows = ""
        for sec_name in sorted(by_section.keys()):
            sec = by_section[sec_name]
            s_pass = sec.get("pass", 0)
            s_fail = sec.get("fail", 0)
            s_total = sec.get("total", 0)
            s_pct = round(s_pass / s_total * 100) if s_total > 0 else 0
            bar_color = "#4ade80" if s_pct >= 80 else "#fbbf24" if s_pct >= 50 else "#f87171"
            section_rows += f"""<tr>
                <td>{escape(sec_name)}</td>
                <td style="text-align:center">{s_pass}</td>
                <td style="text-align:center">{s_fail}</td>
                <td style="text-align:center">{s_total}</td>
                <td><div style="background:#e5e7eb;border-radius:4px;overflow:hidden;height:20px">
                    <div style="background:{bar_color};height:100%;width:{s_pct}%;min-width:2px"></div>
                </div><span style="font-size:0.85em">{s_pct}%</span></td>
            </tr>\n"""

        # Critical findings (failed + high severity)
        critical = [c for c in checks if c.get("compliant") == "No" and c.get("severity") == "high"]
        critical_rows = ""
        for c in sorted(critical, key=lambda x: x.get("check_id", "")):
            critical_rows += f"""<tr>
                <td><code>{escape(c.get('check_id', ''))}</code></td>
                <td>{escape(c.get('title', ''))}</td>
                <td>{escape(c.get('section', ''))}</td>
                <td>{escape(c.get('detail', ''))}</td>
            </tr>\n"""

        # All checks table
        all_checks_rows = ""
        for c in checks:
            compliant = c.get("compliant", "N/A")
            badge_color = "#4ade80" if compliant == "Yes" else "#f87171" if compliant == "No" else "#9ca3af"
            sev = c.get("severity", "medium")
            sev_color = "#f87171" if sev == "high" else "#fbbf24" if sev == "medium" else "#60a5fa"
            all_checks_rows += f"""<tr>
                <td><code>{escape(c.get('check_id', ''))}</code></td>
                <td>{escape(c.get('title', ''))}</td>
                <td>{escape(c.get('section', ''))}</td>
                <td><span style="background:{sev_color};color:#fff;padding:2px 8px;border-radius:10px;font-size:0.8em">{escape(sev)}</span></td>
                <td><span style="background:{badge_color};color:#fff;padding:2px 8px;border-radius:10px;font-size:0.8em">{escape(compliant)}</span></td>
                <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="{escape(c.get('detail', ''))}">{escape(c.get('detail', ''))}</td>
            </tr>\n"""

        # Cross-framework
        cf = results.get("cross_framework", {})
        eu_ai = cf.get("eu_ai_act", {})
        nist = cf.get("nist_ai_rmf", {})
        eu_readiness = eu_ai.get("readiness_pct", "N/A")
        nist_scores = nist.get("function_scores", {})
        nist_rows = ""
        for func, func_score in nist_scores.items():
            nist_rows += f"<tr><td>{escape(func)}</td><td>{func_score}%</td></tr>\n"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ISO/IEC 42001:2023 Compliance Report</title>
<link rel="stylesheet" href="https://www.oracle.com/asset/web/css/redwood-base.css">
<link rel="stylesheet" href="https://www.oracle.com/asset/web/css/redwood-styles.css">
<style>
  body {{ font-family: 'Oracle Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
         margin: 0; padding: 0; background: #f9fafb; color: #1a1a1a; }}
  .report-header {{ background: linear-gradient(135deg, #312e81 0%, #1e1b4b 100%); color: #fff;
                     padding: 40px 48px; }}
  .report-header h1 {{ margin: 0 0 8px 0; font-size: 1.75em; font-weight: 600; }}
  .report-header .meta {{ opacity: 0.85; font-size: 0.95em; }}
  .score-badge {{ display: inline-block; background: rgba(255,255,255,0.15); border-radius: 12px;
                   padding: 12px 24px; margin-top: 16px; font-size: 1.3em; font-weight: 700; }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 32px 24px; }}
  .card {{ background: #fff; border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.08);
            padding: 24px 28px; margin-bottom: 24px; }}
  .card h2 {{ margin: 0 0 16px 0; font-size: 1.25em; color: #312e81; border-bottom: 2px solid #e5e7eb;
              padding-bottom: 8px; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; }}
  .summary-item {{ text-align: center; padding: 16px; background: #f8f9fa; border-radius: 8px; }}
  .summary-item .value {{ font-size: 1.8em; font-weight: 700; color: #312e81; }}
  .summary-item .label {{ font-size: 0.85em; color: #6b7280; margin-top: 4px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.9em; }}
  th {{ background: #f1f5f9; text-align: left; padding: 10px 12px; font-weight: 600;
        color: #475569; border-bottom: 2px solid #e2e8f0; }}
  td {{ padding: 8px 12px; border-bottom: 1px solid #f1f5f9; }}
  tr:hover {{ background: #f8fafc; }}
  code {{ background: #f1f5f9; padding: 2px 6px; border-radius: 4px; font-size: 0.9em; }}
  .footer {{ text-align: center; padding: 24px; color: #9ca3af; font-size: 0.8em; border-top: 1px solid #e5e7eb; margin-top: 32px; }}
</style>
</head>
<body>

<div class="report-header">
  <h1>ISO/IEC 42001:2023 AI Management System &mdash; Compliance Report</h1>
  <div class="meta">Scan Date: {escape(scan_date)} &bull; Generated: {escape(datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'))}</div>
  <div class="score-badge" style="color:{risk_color}">{score}% &mdash; Risk: {risk_level}</div>
</div>

<div class="container">

  <!-- Executive Summary -->
  <div class="card">
    <h2>Executive Summary</h2>
    <div class="summary-grid">
      <div class="summary-item">
        <div class="value" style="color:{risk_color}">{score}%</div>
        <div class="label">Compliance Score</div>
      </div>
      <div class="summary-item">
        <div class="value">{risk_level}</div>
        <div class="label">Risk Level</div>
      </div>
      <div class="summary-item">
        <div class="value">{req_passed}/{req_total}</div>
        <div class="label">Requirements Passed</div>
      </div>
      <div class="summary-item">
        <div class="value">{passed}/{total}</div>
        <div class="label">Checks Passed</div>
      </div>
      <div class="summary-item">
        <div class="value" style="color:#f87171">{sev_dist['high']}</div>
        <div class="label">High Severity Failures</div>
      </div>
      <div class="summary-item">
        <div class="value" style="color:#fbbf24">{sev_dist['medium']}</div>
        <div class="label">Medium Severity Failures</div>
      </div>
      <div class="summary-item">
        <div class="value" style="color:#60a5fa">{sev_dist['low']}</div>
        <div class="label">Low Severity Failures</div>
      </div>
    </div>
  </div>

  <!-- Section Breakdown -->
  <div class="card">
    <h2>Section Breakdown</h2>
    <table>
      <thead><tr><th>Section</th><th style="text-align:center">Pass</th><th style="text-align:center">Fail</th><th style="text-align:center">Total</th><th>Compliance</th></tr></thead>
      <tbody>{section_rows}</tbody>
    </table>
  </div>

  <!-- Critical Findings -->
  <div class="card">
    <h2>Critical Findings ({len(critical)} high-severity failures)</h2>
    {"<p style='color:#4ade80;font-weight:600'>No critical findings.</p>" if not critical else f'''<table>
      <thead><tr><th>Check ID</th><th>Title</th><th>Section</th><th>Detail</th></tr></thead>
      <tbody>{critical_rows}</tbody>
    </table>'''}
  </div>

  <!-- All Checks -->
  <div class="card">
    <h2>All Checks ({total})</h2>
    <table>
      <thead><tr><th>Check ID</th><th>Title</th><th>Section</th><th>Severity</th><th>Status</th><th>Detail</th></tr></thead>
      <tbody>{all_checks_rows}</tbody>
    </table>
  </div>

  <!-- Cross-Framework Mapping -->
  <div class="card">
    <h2>Cross-Framework Mapping</h2>
    <div class="summary-grid">
      <div class="summary-item">
        <div class="value">{eu_readiness}{"%" if isinstance(eu_readiness, (int, float)) else ""}</div>
        <div class="label">EU AI Act Readiness</div>
      </div>
    </div>
    {"" if not nist_rows else f'''<h3 style="margin-top:16px;font-size:1em;color:#475569">NIST AI RMF Function Scores</h3>
    <table>
      <thead><tr><th>Function</th><th>Score</th></tr></thead>
      <tbody>{nist_rows}</tbody>
    </table>'''}
  </div>

  <div class="footer">
    <p>OCI ISO/IEC 42001:2023 Scanner v{VERSION} &bull; {escape(scan_ts)}</p>
    <p>ISO/IEC 42001:2023 is published by ISO. This report is generated by automated tooling and does not constitute
    official certification. &copy; ISO/IEC 2023. All rights reserved.</p>
  </div>

</div>
</body>
</html>"""
        return html

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path in ("/api/iso42001/scan", "/api/scan"):
            global _scan_running
            with _scan_lock:
                if _scan_running:
                    return self._send_json({"message": "Scan already running"}, 409)
                _scan_running = True

            thread = threading.Thread(target=_run_scan, daemon=True)
            thread.start()
            return self._send_json({
                "message": "ISO 42001 v2 scan triggered",
                "checks": f"{_latest_results['total']} checks" if _latest_results else "~78 checks",
                "estimated_time": "2-5 minutes",
            })

        if path == "/api/iso42001/classify":
            content_len = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(content_len)) if content_len > 0 else {}
            result = EUAIActRiskEngine.classify(body)
            return self._send_json(result)

        self._send_error(f"Unknown POST endpoint: {path}", 404)


def main():
    global _client

    parser = argparse.ArgumentParser(
        description="OCI ISO 42001 Scanner HTTP API Server")
    parser.add_argument("--profile", default="DEFAULT")
    parser.add_argument("--auth", default="instance_principal",
                        choices=["config", "instance_principal"])
    parser.add_argument("--tenancy", required=True, help="Tenancy OCID")
    parser.add_argument("--region", default="")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--scan-on-start", action="store_true",
                        help="Run a scan immediately on startup")
    args = parser.parse_args()

    _client = OCIClient(
        auth=args.auth, profile=args.profile,
        tenancy=args.tenancy, region=args.region,
    )

    # Load cached results
    _load_cached()

    # Optional: scan on start
    if args.scan_on_start:
        print("[Server] Running initial scan...")
        global _scan_running
        _scan_running = True
        thread = threading.Thread(target=_run_scan, daemon=True)
        thread.start()

    server = HTTPServer((args.host, args.port), ScannerHandler)
    print(f"[Server] ISO 42001 Scanner API v{VERSION} listening on {args.host}:{args.port}")
    print(f"[Server] Tenancy: {args.tenancy}")
    print(f"[Server] Auth: {args.auth}")
    print(f"[Server] Endpoints:")
    print(f"  GET  /api/iso42001/summary       — Scan results overview")
    print(f"  GET  /api/iso42001/checks        — Filterable check results (?severity=high&status=failed)")
    print(f"  GET  /api/iso42001/remediation    — Remediation guidance (?check_id=A6.5-01)")
    print(f"  GET  /api/iso42001/history        — Scan history with score trending")
    print(f"  GET  /api/iso42001/roadmap        — 12-step certification roadmap")
    print(f"  GET  /api/iso42001/gaps           — Gap analysis (12 domains)")
    print(f"  GET  /api/iso42001/frameworks     — EU AI Act + NIST AI RMF mapping")
    print(f"  GET  /api/iso42001/soa            — Statement of Applicability")
    print(f"  GET  /api/iso42001/evidence        — Evidence register")
    print(f"  GET  /api/iso42001/report          — HTML compliance report")
    print(f"  GET  /api/iso42001/scan/status    — Scan status")
    print(f"  POST /api/iso42001/scan           — Trigger new scan")
    print(f"  POST /api/iso42001/classify       — EU AI Act risk tier classification")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[Server] Shutting down.")
        server.shutdown()


if __name__ == "__main__":
    main()
