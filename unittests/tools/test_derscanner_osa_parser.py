from dojo.models import Test
from dojo.tools.derscanner_osa.parser import DerScannerOsaParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestDerScannerOsaParser(DojoTestCase):

    def test_derscanner_osa_parser_with_no_vuln_has_no_findings(self):
        testfile = (
                get_unit_tests_scans_path("derscanner_osa") /
                "derscanner_osa_no_vul.csv"
        ).open(encoding="utf-8")
        parser = DerScannerOsaParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_derscanner_osa_parser_with_one_vuln_has_one_findings(self):
        parser = DerScannerOsaParser()
        file_path = (
                get_unit_tests_scans_path("derscanner_osa") /
                "derscanner_osa_one_vul.csv"
        )

        with file_path.open(encoding="utf-8") as testfile:
            findings = parser.get_findings(testfile, Test())

            finding = findings[0]
            self.assertEqual(1, len(findings))
            self.assertEqual(
                "Pillow 9.4.0 HPND has CVE-2023-50447",
                finding.title
            )
            self.assertEqual("Critical", finding.severity)
            self.assertEqual(94, finding.cwe)
            self.assertEqual("CVE-2023-50447", finding.cve)
            self.assertEqual("Pillow", finding.component_name)
            self.assertEqual("9.4.0", finding.component_version)

    def test_derscanner_osa_parser_with_many_vuln_has_many_findings(self):
        parser = DerScannerOsaParser()
        file_path = (
                get_unit_tests_scans_path("derscanner_osa") /
                "derscanner_osa_many_vul.csv"
        )

        with file_path.open(encoding="utf-8") as testfile:
            findings = parser.get_findings(testfile, Test())

            finding = findings[0]
            self.assertEqual(3, len(findings))
            self.assertEqual(
                "Pillow 9.4.0 HPND has CVE-2023-50447",
                finding.title
            )
            self.assertEqual("Critical", finding.severity)
            self.assertEqual(94, finding.cwe)
            self.assertEqual("CVE-2023-50447", finding.cve)
            self.assertEqual("Pillow", finding.component_name)
            self.assertEqual("9.4.0", finding.component_version)

            finding = findings[1]
            self.assertEqual(
                "zipp 3.8.0 MIT has CVE-2024-5569",
                finding.title
            )
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(835, finding.cwe)
            self.assertEqual("CVE-2024-5569", finding.cve)
            self.assertEqual("zipp", finding.component_name)
            self.assertEqual("3.8.0", finding.component_version)

            finding = findings[2]
            self.assertEqual(
                "sqlparse 0.3.1 BSD-3-Clause has CVE-2023-30608",
                finding.title
            )
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(1333, finding.cwe)
            self.assertEqual("CVE-2023-30608", finding.cve)
            self.assertEqual("sqlparse", finding.component_name)
            self.assertEqual("0.3.1", finding.component_version)
