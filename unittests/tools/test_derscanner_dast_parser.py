from dojo.models import Test
from dojo.tools.derscanner_dast.parser import DerScannerDastParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestDerScannerDastParser(DojoTestCase):

    def test_derscanner_dast_parser_with_no_vuln_has_no_findings(self):
        testfile = (
                get_unit_tests_scans_path("derscanner_dast")
                / "derscanner_dast_no_vul.csv"
        ).open(encoding="utf-8")
        parser = DerScannerDastParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_derscanner_dast_parser_with_one_vuln_has_one_findings(self):
        parser = DerScannerDastParser()
        file_path = (
                get_unit_tests_scans_path("derscanner_dast")
                / "derscanner_dast_one_vul.csv"
        )

        with file_path.open(encoding="utf-8") as testfile:
            findings = parser.get_findings(testfile, Test())
            finding = findings[0]

            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()

            self.assertEqual(1, len(findings))
            self.assertEqual(
                "X-Content-Type-Options Header Missing", finding.title
            )
            self.assertEqual("Low", finding.severity)
            self.assertEqual("x-content-type-options", finding.param)

            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual(
                str(endpoint),
                "http://vampi.derscanner.com/users/v1/register"
            )

    def test_derscanner_dast_parser_with_many_vuln_has_many_findings(self):
        parser = DerScannerDastParser()
        file_path = (
                get_unit_tests_scans_path("derscanner_dast")
                / "derscanner_dast_many_vul.csv"
        )

        with file_path.open(encoding="utf-8") as testfile:
            findings = parser.get_findings(testfile, Test())
            finding = findings[0]

            self.assertEqual(3, len(findings))
            self.assertEqual(
                "X-Content-Type-Options Header Missing", finding.title
            )
            self.assertEqual("Low", finding.severity)
            self.assertEqual("x-content-type-options", finding.param)
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual(
                str(endpoint),
                "http://vampi.derscanner.com/users/v1/register"
            )

            finding = findings[1]
            self.assertEqual(
                "Application Error Disclosure", finding.title
            )
            self.assertEqual("Low", finding.severity)
            self.assertEqual("", finding.param)
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual(
                str(endpoint),
                "http://vampi.derscanner.com/books/v1"
            )

            finding = findings[2]
            self.assertEqual(
                "Information Disclosure - Suspicious Comments", finding.title
            )
            self.assertEqual("Info", finding.severity)
            self.assertEqual("", finding.param)
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual(
                str(endpoint),
                "http://vampi.derscanner.com/books/v1"
            )
