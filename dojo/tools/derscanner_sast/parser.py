import csv
import io
import re

from dojo.models import Finding


class DerScannerSastParser:

    """SAST scanner for Dersecure"""

    def get_scan_types(self):
        return ["Derscanner SAST"]

    def get_label_for_scan_types(self, scan_type):
        return "DerScanner SAST"

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
        - line: Set to line from DerScanner Scanner.
        - file_path: Set to filepath from DerScanner Scanner.
        - description: Custom description made from DerScanner Scanner.
        """
        return [
            "title",
            "line",
            "file_path",
            "description",
        ]

    MAPPING_CONFIDENCE = {
        "0": 10,  # CONFIDENCE_LOW => Tentative
        "1": 8,   # CONFIDENCE_LOW => Tentative
        "2": 6,   # CONFIDENCE_LOW => Tentative
        "3": 4,   # CONFIDENCE_MEDIUM => Firm
        "4": 2,   # CONFIDENCE_HIGH => Certain
        "5": 1    # CONFIDENCE_HIGH => Certain
    }

    def _parse_line(self, line_str) -> int | None:
        """
        Parses a line number from a string,
        handling ranges by taking the first number.
        Returns None if input is invalid or cannot be converted to int.
        """
        if not line_str:
            return None
        if not line_str.isdigit():
            line_str = line_str.split("-")[0]
        try:
            return int(line_str)
        except (ValueError, TypeError):
            return None

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

    def _extract_code_only(self, raw: str) -> str:
        """
        Returns source code only.
        Drops file path and line info.
        """
        if not raw or raw.strip() == "-":
            return ""

        text = raw.strip().strip('"')
        lines = text.splitlines()

        if not lines:
            return ""

        if ';' in lines[0]:
            lines = lines[1:]

        return "\n".join(lines).rstrip()

    def _extract_first_trace_entry(
            self, raw: str
    ) -> tuple[str, str, str] | None:
        """
        Extract first (file, line, code) from trace.
        """
        if not raw:
            return None, None, None

        text = raw.strip().strip('"')

        first_block = re.split(r'\n-', text, maxsplit=1)[0]
        first_block = first_block.strip().lstrip('[').rstrip(']')

        lines = first_block.splitlines()
        if not lines:
            return None, None, None

        match = re.match(r'([^:]+):(\d+)', lines[0])
        if not match:
            return None, None, None

        file_path = match.group(1).strip()
        line_no = match.group(2).strip()

        code = "\n".join(lines[1:]).rstrip()

        return file_path, int(line_no), code

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

    def _format_description(self, row):
        """
        Formats a Finding description from a parsed data row.
        """
        desc = row.get("Description", "").strip()
        language = row.get("Language", "").strip()
        classification = row.get("Classifications", "").strip()
        status = row.get("Status", "").strip()
        sink_file = row.get("File", "").strip()
        line = self._parse_line(row.get("Line", ""))
        trace = row.get("Trace", "")
        code = row.get("Source code", "")
        sink_code = self._extract_code_only(code)
        (
            source_file,
            source_line,
            source_code,
        ) = self._extract_first_trace_entry(trace)
        der_codefix = row.get("DerCodeFix", "").strip()
        der_triage = row.get("DerTriage", "").strip()
        correlation_dast = row.get("Correlation with DAST", "").strip()

        parts = []
        if desc:
            parts.append(f"### Description\n{desc}")
        if language:
            parts.append(f"**Language:** {language}")
        if classification:
            parts.append(f"**Classification:** {classification}")
        if status:
            parts.append(f"**Status:** {status}")
        if source_file and source_line and source_code:
            parts.append(f"**Source file:** `{source_file}`:{source_line}")
            parts.append(f"```\n{source_code}\n```")
        if sink_file and line and sink_code:
            parts.append(f"**Sink file:** `{sink_file}`:{line}")
            parts.append(f"```\n{sink_code}\n```")
        if der_codefix:
            parts.append(f"**DerCodeFix:** {der_codefix}")
        if der_triage:
            parts.append(f"**DerTriage:** {der_triage}")
        if correlation_dast:
            parts.append(f"**Correlation with DAST:** {correlation_dast}")
        if trace and trace != "-":
            parts.append(f"**Trace:**\n{trace}")

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
            trace = row.get("Trace")
            (
                source_file,
                source_line,
                source_code,
            ) = self._extract_first_trace_entry(trace)

            cwe = self._parse_cwe(row.get("Classifications"))
            line = self._parse_line(row.get("Line"))
            description_md = self._format_description(row)
            confidence = self._invert_conf(row.get("Confidence"))

            finding = Finding(
                test=test,
                title=row.get("Vulnerability"),
                description=description_md,
                severity=row.get("Severity Level", "Info"),
                mitigation=row.get("Recommendations"),
                references=row.get("Links", "").replace(",", "\n"),
                cwe=cwe,
                file_path=row.get("File"),
                line=line,
                sast_source_file_path=source_file,
                sast_source_line=source_line,
                unique_id_from_tool=row.get("Vulnerability UUID"),
                static_finding=True,
                dynamic_finding=False,
                scanner_confidence=confidence
            )

            items.append(finding)

        return items
