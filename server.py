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

    # With all features enabled
    python server.py --auth instance_principal --tenancy <OCID> --all-features
"""
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

        # Persist to disk
        _results_dir.mkdir(parents=True, exist_ok=True)
        out = _results_dir / "latest.json"
        out.write_text(json.dumps(results, indent=2))
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
        except Exception:
            pass


class ScannerHandler(BaseHTTPRequestHandler):
    """HTTP request handler for scanner API."""

    def log_message(self, format, *args):
        # Quieter logging
        print(f"[API] {args[0]} {args[1]}")

    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

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
            })

        # ── ISO 42001 Endpoints ──

        if path == "/api/iso42001/summary":
            if not _latest_results:
                return self._send_json({"error": "No scan results. POST /api/iso42001/scan first."}, 404)
            # Return top-level summary (without heavy nested data)
            summary = {k: v for k, v in _latest_results.items()
                       if k not in ("cross_framework", "certification_roadmap",
                                    "gap_analysis", "statement_of_applicability",
                                    "evidence_register", "eu_ai_act_enforcement")}
            return self._send_json(summary)

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
            })

        # ── Legacy CIS endpoints (passthrough for backward compat) ──

        if path == "/api/summary":
            # Return CIS summary if available, else ISO 42001 summary
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
                "checks": "73 (20 clauses + 53 annex)",
                "estimated_time": "2-5 minutes",
            })

        if path == "/api/iso42001/classify":
            # Read JSON body
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
    print(f"  GET  /api/iso42001/summary     — Scan results overview")
    print(f"  GET  /api/iso42001/roadmap      — 12-step certification roadmap")
    print(f"  GET  /api/iso42001/gaps         — Gap analysis (12 domains)")
    print(f"  GET  /api/iso42001/frameworks   — EU AI Act + NIST AI RMF mapping")
    print(f"  GET  /api/iso42001/soa          — Statement of Applicability")
    print(f"  GET  /api/iso42001/evidence     — Evidence register")
    print(f"  GET  /api/iso42001/scan/status  — Scan status")
    print(f"  POST /api/iso42001/scan         — Trigger new scan")
    print(f"  POST /api/iso42001/classify     — EU AI Act risk tier classification")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[Server] Shutting down.")
        server.shutdown()


if __name__ == "__main__":
    main()
