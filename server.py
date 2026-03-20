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
