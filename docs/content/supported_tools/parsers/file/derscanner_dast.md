---
title: "DerScanner DAST"
toc_hide: true
---
DerScanner DAST report file can be imported in CSV format from **Analysis_Results.csv**. When exporting a report from DerScanner, make sure to select the Detailed Results option to generate the correct CSV format required for import.

### Sample Scan Data
Sample DerScanner DAST Scan scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/derscanner_dast).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- cwe
- severity
