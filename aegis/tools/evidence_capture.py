"""
Evidence capture system for Aegis pentesting.

Handles:
- Automatic screenshot capture
- HTTP request/response logging
- Evidence organization per vulnerability
- Timestamp metadata
"""

import os
import json
import time
import hashlib
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime

from aegis.redaction import redact_sensitive_data, redact_sensitive_text


class EvidenceCapture:
    """Captures and organizes evidence for vulnerabilities."""
    
    def __init__(self, scan_dir: str):
        self.scan_dir = Path(scan_dir)
        self.evidence_dir = self.scan_dir / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.evidence_dir.chmod(0o700)
    
    def create_vuln_evidence_dir(self, vuln_id: str) -> Path:
        """Create evidence directory for a vulnerability."""
        vuln_dir = self.evidence_dir / vuln_id
        vuln_dir.mkdir(parents=True, exist_ok=True)
        (vuln_dir / "screenshots").mkdir(exist_ok=True)
        (vuln_dir / "requests").mkdir(exist_ok=True)
        vuln_dir.chmod(0o700)
        (vuln_dir / "screenshots").chmod(0o700)
        (vuln_dir / "requests").chmod(0o700)
        return vuln_dir
    
    def save_screenshot(self, vuln_id: str, screenshot_data: bytes, 
                        filename: str, description: str = "") -> str:
        """Save a screenshot with metadata."""
        vuln_dir = self.create_vuln_evidence_dir(vuln_id)
        screenshot_path = vuln_dir / "screenshots" / filename
        
        # Save screenshot
        with open(screenshot_path, "wb") as f:
            f.write(screenshot_data)
        
        # Save metadata
        metadata = {
            "filename": filename,
            "description": description,
            "timestamp": datetime.now().isoformat(),
            "size_bytes": len(screenshot_data),
            "hash_sha256": hashlib.sha256(screenshot_data).hexdigest(),
        }
        
        meta_path = screenshot_path.with_suffix(".json")
        with open(meta_path, "w") as f:
            json.dump(metadata, f, indent=2)
        
        return str(screenshot_path)
    
    def save_http_evidence(self, vuln_id: str, request: Dict[str, Any], 
                           response: Dict[str, Any], description: str = "") -> str:
        """Save HTTP request/response evidence in professional format."""
        vuln_dir = self.create_vuln_evidence_dir(vuln_id)
        request = redact_sensitive_data(request)
        response = redact_sensitive_data(response)
        description = redact_sensitive_text(description)
        
        # Microseconds prevent paired positive/control exchanges from
        # overwriting each other when saved in the same second.
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        filename = f"request_{timestamp}.txt"
        evidence_path = vuln_dir / "requests" / filename
        
        # Build request section
        req_method = request.get('method', 'GET')
        req_url = request.get('url', '')
        req_headers = request.get('headers', {})
        req_body = request.get('body', '')
        
        # Build response section
        resp_status = response.get('status_code', '')
        resp_status_text = response.get('status_text', '')
        resp_headers = response.get('headers', {})
        resp_body = response.get('body', '')[:5000]
        
        # Format as professional raw HTTP traffic
        lines = []
        lines.append("=" * 70)
        lines.append("HTTP REQUEST/RESPONSE EVIDENCE")
        lines.append("=" * 70)
        lines.append(f"Timestamp:  {datetime.now().isoformat()}")
        if description:
            lines.append(f"Description: {description}")
        lines.append("")
        
        # Request section
        lines.append("-" * 70)
        lines.append("REQUEST")
        lines.append("-" * 70)
        lines.append(f"{req_method} {req_url} HTTP/1.1")
        if req_headers:
            for k, v in req_headers.items():
                lines.append(f"{k}: {v}")
        else:
            lines.append("(no request headers captured)")
        if req_body:
            lines.append("")
            lines.append(req_body)
        lines.append("")
        
        # Response section
        lines.append("-" * 70)
        lines.append("RESPONSE")
        lines.append("-" * 70)
        lines.append(f"HTTP/1.1 {resp_status} {resp_status_text}".rstrip())
        if resp_headers:
            for k, v in resp_headers.items():
                lines.append(f"{k}: {v}")
        else:
            lines.append("(no response headers captured)")
        if resp_body:
            lines.append("")
            lines.append(resp_body)
        lines.append("")
        lines.append("=" * 70)
        
        evidence = "\n".join(lines)
        
        with open(evidence_path, "w") as f:
            f.write(evidence)
        evidence_path.chmod(0o600)
        
        # Save metadata
        metadata = {
            "filename": filename,
            "description": description,
            "timestamp": datetime.now().isoformat(),
            "request_url": request.get("url"),
            "request_method": request.get("method"),
            "response_status": response.get("status_code"),
            "request_headers_count": len(req_headers),
            "response_headers_count": len(resp_headers),
            "request_body_length": len(req_body),
            "response_body_length": len(resp_body),
            "hash_sha256": hashlib.sha256(evidence.encode()).hexdigest(),
        }
        
        meta_path = evidence_path.with_suffix(".json")
        with open(meta_path, "w") as f:
            json.dump(metadata, f, indent=2)
        meta_path.chmod(0o600)
        
        return str(evidence_path)
    
    def save_poc(self, vuln_id: str, poc_code: str, poc_type: str = "python") -> str:
        """Save proof of concept code."""
        vuln_dir = self.create_vuln_evidence_dir(vuln_id)
        poc_code = redact_sensitive_text(poc_code)
        
        if poc_type == "python":
            poc_path = vuln_dir / "poc.py"
        elif poc_type == "bash":
            poc_path = vuln_dir / "poc.sh"
        else:
            poc_path = vuln_dir / "poc.txt"
        
        with open(poc_path, "w") as f:
            f.write(poc_code)
        poc_path.chmod(0o600)
        
        # Save metadata
        metadata = {
            "type": poc_type,
            "timestamp": datetime.now().isoformat(),
            "hash_sha256": hashlib.sha256(poc_code.encode()).hexdigest(),
        }
        
        meta_path = poc_path.with_suffix(".json")
        with open(meta_path, "w") as f:
            json.dump(metadata, f, indent=2)
        meta_path.chmod(0o600)
        
        return str(poc_path)
    
    def save_mobile_evidence(self, vuln_id: str, evidence_type: str,
                              data: Any, metadata: Optional[Dict[str, Any]] = None) -> str:
        """Save mobile-specific evidence: APK hash, manifest dump, Frida logs, etc.

        Args:
            vuln_id: Vulnerability ID (e.g., vuln-0001).
            evidence_type: Type of evidence (apk_hash, manifest, decompiled_source,
                          frida_log, device_screenshot, traffic_dump).
            data: The evidence data (string, bytes, or dict).
            metadata: Optional additional metadata.
        """
        vuln_dir = self.create_vuln_evidence_dir(vuln_id)
        mobile_dir = vuln_dir / "mobile"
        mobile_dir.mkdir(exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        meta = metadata or {}

        if evidence_type == "apk_hash":
            filename = f"apk_info_{timestamp}.json"
            if isinstance(data, dict):
                path = mobile_dir / filename
                with open(path, "w") as f:
                    json.dump({"apk_info": data, "metadata": meta, "timestamp": timestamp}, f, indent=2)

        elif evidence_type == "manifest":
            filename = f"manifest_{timestamp}.xml"
            path = mobile_dir / filename
            if isinstance(data, str):
                path.write_text(data)

        elif evidence_type == "decompiled_source":
            filename = f"decompiled_{timestamp}.txt"
            path = mobile_dir / filename
            if isinstance(data, str):
                path.write_text(data[:10000])

        elif evidence_type == "frida_log":
            filename = f"frida_{timestamp}.log"
            path = mobile_dir / filename
            if isinstance(data, str):
                path.write_text(data)

        elif evidence_type == "device_screenshot":
            filename = f"device_{timestamp}.png"
            path = mobile_dir / filename
            if isinstance(data, bytes):
                with open(path, "wb") as f:
                    f.write(data)

        elif evidence_type == "traffic_dump":
            filename = f"traffic_{timestamp}.txt"
            path = mobile_dir / filename
            if isinstance(data, str):
                path.write_text(data)

        else:
            filename = f"{evidence_type}_{timestamp}.json"
            path = mobile_dir / filename
            with open(path, "w") as f:
                json.dump({"data": data, "metadata": meta, "timestamp": timestamp}, f, indent=2)

        # Save metadata
        meta_path = path.with_suffix(".json") if path.suffix != ".json" else path
        if path != meta_path:
            metadata_record = {
                "filename": path.name,
                "evidence_type": evidence_type,
                "timestamp": timestamp,
                "metadata": meta,
            }
            with open(meta_path, "w") as f:
                json.dump(metadata_record, f, indent=2)

        return str(path)

    def save_findings_summary(self, vuln_id: str, findings: Dict[str, Any]) -> str:
        """Save findings summary."""
        vuln_dir = self.create_vuln_evidence_dir(vuln_id)
        summary_path = vuln_dir / "findings.json"
        findings = redact_sensitive_data(findings)
        findings["timestamp"] = datetime.now().isoformat()
        findings["evidence_dir"] = str(vuln_dir)
        
        with open(summary_path, "w") as f:
            json.dump(findings, f, indent=2)
        summary_path.chmod(0o600)
        
        return str(summary_path)
    
    def get_evidence_list(self, vuln_id: str) -> List[Dict[str, Any]]:
        """List all evidence for a vulnerability."""
        vuln_dir = self.evidence_dir / vuln_id
        if not vuln_dir.exists():
            return []
        
        evidence = []
        
        # Screenshots
        screenshots_dir = vuln_dir / "screenshots"
        if screenshots_dir.exists():
            for f in screenshots_dir.glob("*.png"):
                meta = f.with_suffix(".json")
                if meta.exists():
                    with open(meta) as mf:
                        evidence.append({"type": "screenshot", "path": str(f), **json.load(mf)})
        
        # Requests
        requests_dir = vuln_dir / "requests"
        if requests_dir.exists():
            for f in requests_dir.glob("*.txt"):
                meta = f.with_suffix(".json")
                if meta.exists():
                    with open(meta) as mf:
                        evidence.append({"type": "http_request", "path": str(f), **json.load(mf)})
        
        # PoC
        for ext in ["py", "sh", "txt"]:
            for f in vuln_dir.glob(f"poc.{ext}"):
                meta = f.with_suffix(".json")
                if meta.exists():
                    with open(meta) as mf:
                        evidence.append({"type": "poc", "path": str(f), **json.load(mf)})
        
        return sorted(evidence, key=lambda x: x.get("timestamp", ""))
    
    def calculate_evidence_hash(self, vuln_id: str) -> str:
        """Calculate hash of all evidence for a vulnerability."""
        evidence_list = self.get_evidence_list(vuln_id)
        combined_hash = hashlib.sha256()
        
        for item in evidence_list:
            if "hash_sha256" in item:
                combined_hash.update(item["hash_sha256"].encode())
        
        return combined_hash.hexdigest()


# Global evidence capture instance
_evidence_capture: Optional[EvidenceCapture] = None


def get_evidence_capture(scan_dir: str) -> EvidenceCapture:
    """Get or create evidence capture instance."""
    global _evidence_capture
    if _evidence_capture is None or str(_evidence_capture.scan_dir) != scan_dir:
        _evidence_capture = EvidenceCapture(scan_dir)
    return _evidence_capture
