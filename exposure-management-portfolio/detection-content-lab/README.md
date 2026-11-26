# Vulnerability Detection Content Lab

Offline assessment of supplied host inventory and network service banners for CVE-2021-41773 and CVE-2021-42013. Two versioned rules, five synthetic assets, ten asset/CVE evaluations and 28 labeled regression cases. No live scanning or exploit validation.

```sh
python detect.py
```

Run from this folder, or `python detection-content-lab/detect.py` from the portfolio folder. JSON and CSV output appear in `reports/`; `efficacy.json` contains the corpus results and binary precision/recall for determinate host cases. Unknown and banner cases are tested separately and excluded from binary denominators.

## Detection decisions

| State | Meaning |
| --- | --- |
| affected_version | Host inventory matches affected upstream version; patch provenance/configuration still require review |
| potential | Banner matches; authenticate inventory before concluding exposure |
| unknown | Missing/ambiguous version or unsubstantiated patch assertion |
| not_affected | Outside this CVE's range or referenced host patch evidence; does not mean vulnerability-free |
| not_applicable | Different product |

Vendor-suffixed packages are deliberately unknown because distribution backports cannot be inferred safely from upstream version strings. Patch references in fixtures are synthetic assertions, not independently verified attestations. Each finding includes original evidence, SHA-256, rule revision, advisory and remediation guidance.

The 2.4.50 boundary is a regression test: it addressed CVE-2021-41773 but remained affected by CVE-2021-42013. Historical 2.4.51 is a fix boundary, not a current deployment recommendation. Configuration and CGI affect exploitability. See [Apache's vendor advisory](https://httpd.apache.org/security/vulnerabilities_24.html). Advisory facts were checked on 2026-11-26.

## Content release workflow

Research advisory -> revise `rules.json` -> add affected/unaffected/unknown fixtures -> run regression tests -> inspect efficacy -> peer review -> release content revision. New version families and vendor package semantics require new evidence and tests; this lab does not implement a general CPE, RPM, Debian, Windows KB or NVD matching engine.
