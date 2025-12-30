import csv
import io
import html2text
import re

from dojo.models import Finding, Endpoint


class DerScannerDastParser:

    """DAST scanner for Dersecure"""

    def get_scan_types(self):
        return ["Derscanner DAST"]

    def get_label_for_scan_types(self, scan_type):
        return "DerScanner DAST"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Derscanner report file can be imported in CSV format "
            "from Analysis_Results.csv."
        )

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication
        in the DerScanner Parser.

        Fields:
        - title: Set to the title outputted by the DerScanner Scanner.
        - cwe: Set to cwe from scanner output if present.
        - severity: Set to severity from DerScanner Scanner
        """
        return [
            "title",
            "cwe",
            "severity",
        ]

    MAPPING_CONFIDENCE = {
        "0": 10,  # CONFIDENCE_LOW => Tentative
        "1": 8,   # CONFIDENCE_LOW => Tentative
        "2": 6,   # CONFIDENCE_LOW => Tentative
        "3": 4,   # CONFIDENCE_MEDIUM => Firm
        "4": 2,   # CONFIDENCE_HIGH => Certain
        "5": 1    # CONFIDENCE_HIGH => Certain
    }

    def _parse_cwe(self, cwe_raw: str) -> int | None:
        """
        Parse a raw CWE string, returning the first valid CWE ID as an integer.
        Returns None if input is empty or no valid CWE found.
        """
        if not cwe_raw or 'CWE-' not in cwe_raw:
            return None

        match = re.search(r'CWE-(\d+)', cwe_raw)
        if match:
            return int(match.group(1))
        return None

    def _invert_conf(self, raw_conf) -> int | None:
        """
        Inverts confidence from scanner scale (high=5, low=0)
         to DefectDojo's scale (low=10, high=1).
        Returns None if value is missing or invalid.
        """
        try:
            value = int(raw_conf.strip())
            value = max(0, min(5, value))
            return self.MAPPING_CONFIDENCE.get(str(value))
        except (ValueError, AttributeError):
            return None

    def _extract_endpoint_from_request(
            self, request_text: str
    ) -> Endpoint | None:
        """
        Extracts an Endpoint object from raw HTTP request text.
        """
        if not request_text:
            return None

        match = re.search(
            r'^(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+(http[^\s]+)',
            request_text,
            re.IGNORECASE | re.MULTILINE
        )
        if match:
            full_url = match.group(2)
            try:
                endpoint = Endpoint.from_uri(full_url)
                return endpoint
            except Exception:
                return None

        return None

    def _format_description(self, row):
        """
        Formats a Finding description from a parsed data row.
        """
        desc = row.get("Description", "").strip()
        classification = row.get("Classifications", "").strip()
        status = row.get("Status", "").strip()
        parts = []
        if desc:
            parts.append(f"### Description\n{desc}")
        if classification:
            parts.append(f"**Classification:** {classification}")
        if status:
            parts.append(f"**Status:** {status}")

        return "\n\n".join(parts)

    def get_findings(self, filename, test):
        if not filename:
            return ()

        content = filename.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8")

        reader = csv.DictReader(
            io.StringIO(content),
            delimiter=",",
            quotechar='"'
        )

        items = []
        for row in reader:
            cwe = self._parse_cwe(row.get("Classifications"))
            description_md = self._format_description(row)
            confidence = self._invert_conf(row.get("Confidence"))

            finding = Finding(
                test=test,
                title=row.get("Vulnerability"),
                description=description_md,
                severity=row.get("Severity Level", "Info"),
                mitigation=row.get("Recommendations"),
                references=html2text.html2text(row.get("Links", "")),
                cwe=cwe,
                unique_id_from_tool=row.get("ID"),
                static_finding=False,
                dynamic_finding=True,
                param=row.get("Parameter"),
                payload=row.get("Attack"),
                scanner_confidence=confidence
            )
            request = (
                    (row.get("Request Header") or "") +
                    "\n\n" +
                    (row.get("Request Body") or "")
            )
            response = (
                    (row.get("Response Header") or "") +
                    "\n\n" +
                    (row.get("Response Body") or "")
            )
            endpoint = self._extract_endpoint_from_request(request)

            finding.unsaved_endpoints = []
            finding.unsaved_request = request
            finding.unsaved_response = response

            if endpoint:
                finding.unsaved_endpoints.append(endpoint)

            items.append(finding)

        return items
