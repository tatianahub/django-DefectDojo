from dojo.models import Test
from dojo.tools.derscanner_sast.parser import DerScannerSastParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestDerScannerSastParser(DojoTestCase):

    def test_derscanner_sast_parser_with_no_vuln_has_no_findings(self):
        testfile_path = (
                get_unit_tests_scans_path("derscanner_sast") /
                "derscanner_sast_no_vul.csv"
        )
        with testfile_path.open(encoding="utf-8") as testfile:
            parser = DerScannerSastParser()
            findings = parser.get_findings(testfile, Test())

        self.assertEqual(0, len(findings))

    def test_derscanner_sast_parser_with_one_vuln_has_one_findings(self):
        parser = DerScannerSastParser()
        file_path = (
                get_unit_tests_scans_path("derscanner_sast") /
                "derscanner_sast_one_vul.csv"
        )

        with file_path.open(encoding="utf-8") as testfile:
            findings = parser.get_findings(testfile, Test())

        finding = findings[0]
        self.assertEqual(1, len(findings))
        self.assertEqual("Reflected XSS", finding.title)
        self.assertEqual("Medium", finding.severity)
        self.assertEqual("myproject/min.js", finding.file_path)
        self.assertEqual(36, finding.line)
        self.assertEqual("myproject/min.js", finding.sast_source_file_path)
        self.assertEqual(35, finding.sast_source_line)

    def test_derscanner_sast_parser_with_many_vuln_has_many_findings(self):
        parser = DerScannerSastParser()
        file_path = (
                get_unit_tests_scans_path("derscanner_sast") /
                "derscanner_sast_many_vul.csv"
        )

        with file_path.open(encoding="utf-8") as testfile:
            findings = parser.get_findings(testfile, Test())

        finding = findings[0]
        self.assertEqual(3, len(findings))
        self.assertEqual("Reflected XSS", finding.title)
        self.assertEqual("Medium", finding.severity)
        self.assertEqual("myproject/min.js", finding.file_path)
        self.assertEqual(36, finding.line)
        self.assertEqual("myproject/min.js", finding.sast_source_file_path)
        self.assertEqual(35, finding.sast_source_line)

        finding = findings[1]
        self.assertEqual(
            "Server-Side Request Forgery (SSRF)",
            finding.title
        )
        self.assertEqual("Medium", finding.severity)
        self.assertEqual("bad/api_list.py", finding.file_path)
        self.assertEqual(10, finding.line)
        self.assertEqual("bad/api_list.py", finding.sast_source_file_path)
        self.assertEqual(10, finding.sast_source_line)

        finding = findings[2]
        self.assertEqual("Hardcoded encryption key", finding.title)
        self.assertEqual("Critical", finding.severity)
        self.assertEqual("bad/vulpy-ssl.py", finding.file_path)
        self.assertEqual(13, finding.line)
        self.assertEqual("bad/vulpy-ssl.py", finding.sast_source_file_path)
        self.assertEqual(13, finding.sast_source_line)
