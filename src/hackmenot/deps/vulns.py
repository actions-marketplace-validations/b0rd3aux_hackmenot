"""Vulnerability checking via OSV API."""

import json
import time
import urllib.request
from http.client import HTTPException
from urllib.error import HTTPError, URLError

from hackmenot.core.constants import (
    OSV_API_URL,
    OSV_BATCH_API_URL,
    OSV_MAX_RETRIES,
    OSV_RETRY_DELAY,
    OSV_TIMEOUT,
)
from hackmenot.core.models import Finding, Severity
from hackmenot.deps.parser import Dependency


class OSVClient:
    """Client for querying Open Source Vulnerabilities (OSV) API.

    Includes rate limiting with exponential backoff for reliability.
    """

    def _ecosystem_name(self, ecosystem: str) -> str:
        """Convert our ecosystem name to OSV ecosystem name."""
        return {"pypi": "PyPI", "npm": "npm"}.get(ecosystem, ecosystem)

    def _severity_from_cvss(self, score: float) -> Severity:
        """Map CVSS score to severity level."""
        if score >= 9.0:
            return Severity.CRITICAL
        elif score >= 7.0:
            return Severity.HIGH
        elif score >= 4.0:
            return Severity.MEDIUM
        return Severity.LOW

    def _make_request(self, url: str, data: dict) -> dict | None:
        """Make an HTTP request with retry and exponential backoff.

        Args:
            url: The API endpoint URL.
            data: The JSON data to send.

        Returns:
            Parsed JSON response, or None if all retries failed.
        """
        delay = OSV_RETRY_DELAY
        for attempt in range(OSV_MAX_RETRIES):
            try:
                req = urllib.request.Request(
                    url,
                    data=json.dumps(data).encode(),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=OSV_TIMEOUT) as response:
                    return json.loads(response.read())
            except HTTPError as e:
                # Rate limited (429) or server error (5xx) - retry with backoff
                if e.code == 429 or e.code >= 500:
                    if attempt < OSV_MAX_RETRIES - 1:
                        time.sleep(delay)
                        delay *= 2  # Exponential backoff
                        continue
                return None
            except (URLError, TimeoutError, HTTPException, json.JSONDecodeError, OSError):
                # Network or parsing error - retry with backoff
                if attempt < OSV_MAX_RETRIES - 1:
                    time.sleep(delay)
                    delay *= 2
                    continue
                return None
        return None

    def check(self, dep: Dependency) -> list[Finding]:
        """Check a single dependency for vulnerabilities."""
        if dep.version is None:
            return []
        query = {
            "package": {"name": dep.name, "ecosystem": self._ecosystem_name(dep.ecosystem)},
            "version": dep.version,
        }
        data = self._make_request(OSV_API_URL, query)
        if data is None:
            return []
        return self._parse_vulns(dep, data.get("vulns", []))

    def check_batch(self, deps: list[Dependency]) -> list[Finding]:
        """Check multiple dependencies in one request."""
        deps_with_versions = [d for d in deps if d.version is not None]
        if not deps_with_versions:
            return []
        queries = [
            {
                "package": {"name": d.name, "ecosystem": self._ecosystem_name(d.ecosystem)},
                "version": d.version,
            }
            for d in deps_with_versions
        ]
        data = self._make_request(OSV_BATCH_API_URL, {"queries": queries})
        if data is None:
            return []
        findings = []
        for dep, result in zip(deps_with_versions, data.get("results", [])):
            findings.extend(self._parse_vulns(dep, result.get("vulns", [])))
        return findings

    def _parse_vulns(self, dep: Dependency, vulns: list[dict]) -> list[Finding]:
        """Parse OSV vulnerability data into Findings."""
        findings = []
        for vuln in vulns:
            vuln_id = vuln.get("id", "Unknown")
            summary = vuln.get("summary", "No description available")
            severity = Severity.MEDIUM
            for sev in vuln.get("severity", []):
                if sev.get("type") == "CVSS_V3":
                    try:
                        score = float(sev.get("score", "0").split("/")[0])
                        severity = self._severity_from_cvss(score)
                    except (ValueError, IndexError):
                        pass
            fix_version = None
            for affected in vuln.get("affected", []):
                for range_info in affected.get("ranges", []):
                    for event in range_info.get("events", []):
                        if "fixed" in event:
                            fix_version = event["fixed"]
            if fix_version:
                fix_suggestion = f"Upgrade to version {fix_version}"
            else:
                fix_suggestion = "Check for patches"
            findings.append(
                Finding(
                    rule_id="DEP003",
                    rule_name="vulnerable-dependency",
                    severity=severity,
                    message=f"Vulnerability {vuln_id} in {dep.name}@{dep.version}: {summary}",
                    file_path=dep.source_file,
                    line_number=0,
                    column=0,
                    code_snippet=f"{dep.name}=={dep.version}",
                    fix_suggestion=fix_suggestion,
                    education="This dependency has a known vulnerability. Update to a patched version.",
                )
            )
        return findings
