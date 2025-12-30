import csv
import io
import re

from dojo.models import Finding


class DerScannerOsaParser:

    """OSA scanner for Dersecure"""

    def get_scan_types(self):
        return ["Derscanner OSA"]

    def get_label_for_scan_types(self, scan_type):
        return "DerScanner OSA"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Derscanner report file can be imported in CSV format "
            "from Analysis_Results.csv."
        )

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication
        in the DerScanner OSA Parser.

        Fields:
        - severity: Severity converted from DerScanner format into DD format.
        - component_name: Set to name returned from DerScanner.
        - component_version: Set to version returned from DerScanner.
        """
        return [
            "severity",
            "component_name",
            "component_version",
        ]

    def _parse_cwe(self, cwe_raw: str) -> int | None:
        """
        Parse a raw CWE string, returning the first valid CWE ID as an integer.
        Returns None if input is empty or no valid CWE found.
        """
        if not cwe_raw or 'CWE:' not in cwe_raw:
            return None

        match = re.search(
            r'CWE:\s*https://cwe\.mitre\.org/data/definitions/(\d+)\.html',
            cwe_raw
        )
        if match:
            return int(match.group(1))
        return None

    def _parse_component_name(self, component_name: str) -> str | None:
        """
        Extracts the base name of a component from a versioned string.
        """
        if not component_name:
            return None

        parts = component_name.strip().split()
        if parts:
            return parts[0]
        return None

    def _parse_cvss(self, raw_cvss) -> float | None:
        """
        Parse CVSS v3.x score from CSV.
        Returns float or None.
        """
        if not raw_cvss:
            return None

        try:
            value = float(str(raw_cvss).strip())
            if 0.0 <= value <= 10.0:
                return value
        except ValueError:
            pass

        return None

    def _parse_epss(self, raw) -> float | None:
        """
        Parse EPSS score from CSV.
        Returns float or None.
        """
        if not raw:
            return None

        try:
            value = float(str(raw).strip())
            if 0.0 <= value <= 1.0:
                return value
        except ValueError:
            pass

        return None

    def _has_trace(self, raw: str | None) -> bool:
        """
        Returns True if trace field contains meaningful data.
        Handles cases like """""", empty strings, or whitespace.
        """
        if not raw:
            return False

        cleaned = raw.strip().strip('"').strip()
        return bool(cleaned)

    def _split_trace_sections(self, raw: str) -> list[tuple[str, str]]:
        """
        Split trace into (header, content) sections.
        """
        if not raw:
            return []

        raw = raw.strip().strip('"')

        pattern = re.compile(
            r'([^\[]+):\s*\[(.*?)\](?=\s*[^\[]+:|\s*$)', re.DOTALL
        )
        matches = pattern.findall(raw)

        sections = []
        for header, content in matches:
            header = header.strip()
            content = content.strip()
            sections.append((header, content))

        return sections

    def _format_single_section(self, header: str, content: str) -> str:
        """
        Format one section as markdown with file, line, and code.
        """
        parts = [p.strip() for p in content.split(';')]

        md = [f"**{header}:**"]

        for i in range(0, len(parts), 3):
            file = parts[i] if i < len(parts) and parts[i] else "unknown"
            line = parts[i+1] if i+1 < len(parts) and parts[i+1] else "?"
            code = parts[i+2] if i+2 < len(parts) else ""

            md.append(f"  File: `{file}`")
            md.append(f"  Line: `{line}`")
            if code:
                md.append("```")
                md.append(code)
                md.append("```")

        return "\n".join(md)

    def _format_trace_block(self, raw: str) -> str:
        """
        Format full trace in markdown, combining all sections.
        """
        sections = self._split_trace_sections(raw)
        if not sections:
            return ""

        formatted = []
        for header, content in sections:
            formatted.append(self._format_single_section(header, content))

        return "\n\n".join(formatted)

    def _format_classification(self, raw: str) -> str:
        """
        Split classification string into separate sources
        without breaking URLs.
        """
        if not raw:
            return ""

        sources = [
            "CVE:", "CWE:", "GitHub Security Advisory:",
            "Go Vulnerability Database:",
            "Python Packaging Advisory Database:",
            "RustSec Advisory Database:"
        ]

        parts = []
        for source in sources:
            pattern = (
                rf"{re.escape(source)}\s*(.*?)(?="
                rf"\s*(?:{'|'.join(map(re.escape, sources))})|$)"
            )
            match = re.search(pattern, raw, re.DOTALL)
            if match:
                value = match.group(1).strip()
                if value and value != "-":
                    parts.append(f"**{source}** {value}")

        return "\n".join(parts)

    def _format_description(self, row):
        """
        Formats a Finding description from a parsed data row.
        """
        desc = row.get("Description", "").strip()
        raw_classification = row.get("Classification Identifier", "")
        classification = self._format_classification(raw_classification)
        status = row.get("Status", "").strip()
        call_trace = row.get("Call Trace")
        import_trace = row.get("Import Trace")
        reachability = (
                self._has_trace(call_trace)
                or self._has_trace(import_trace)
        )

        parts = []
        if desc:
            parts.append(f"### Description\n{desc}")
        if classification:
            parts.append(f"**Classification:**\n{classification}")
        if status:
            parts.append(f"**Status:** {status}")
        if reachability:
            parts.append("#### Result of reachability analysis: Reachable")

            if self._has_trace(import_trace):
                parts.append("**Import Trace:**")
                parts.append(self._format_trace_block(import_trace))

            if self._has_trace(call_trace):
                parts.append("**Call Trace:**")
                parts.append(self._format_trace_block(call_trace))

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
            component_name = row.get("Dependency")
            vulnerability = row.get("Vulnerability")
            title = f"{component_name} has {vulnerability}"
            cwe = self._parse_cwe(row.get("Classification Identifier"))
            description_md = self._format_description(row)
            cvssv3_score = self._parse_cvss(row.get("CVSS v3.1"))
            epss = self._parse_epss(row.get("EPSS"))

            finding = Finding(
                test=test,
                title=title,
                description=description_md,
                severity=row.get("Severity Level", "Info"),
                mitigation=row.get("Recommendations"),
                references=row.get("Links"),
                cwe=cwe,
                cve=vulnerability,
                cvssv3_score=cvssv3_score,
                epss_score=epss,
                component_name=self._parse_component_name(component_name),
                component_version=row.get("Version"),
                unique_id_from_tool=row.get("ID"),
                static_finding=True,
                dynamic_finding=False,

            )

            items.append(finding)

        return items
