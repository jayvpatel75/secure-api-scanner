# Engineering notes and interview guide

## Acceptance criteria

- CVE rules preserve vendor provenance and distinguish the incomplete-fix boundary.
- Inventory and banner evidence produce different confidence states.
- Unparseable vendor versions remain unknown instead of silently becoming safe.
- Efficacy reports disclose dataset, denominators, false positives and false negatives.
- Every exported item has a matching reviewed plan, original evidence and a reviewer.
- Model advice cannot mutate risk decisions or bypass human review.
- Stale intelligence and uncertain findings stay in evidence collection.

## Tradeoffs

Small exact-version rule sets make content review transparent but cover only two historical Apache CVEs. Neither platform labels nor synthetic fixture results demonstrate deployed Linux/Windows detection coverage. Inventory metadata is caller-supplied; digests detect accidental changes, not malicious provenance. Current patch recommendations must come from maintained vendor sources. No impact is inferred from CVSS without considering business context. Real feed integration, caching, rate limiting, retry behavior and supply-chain verification are future work.

## Roadmap

1. Add read-only NVD, CISA KEV and FIRST EPSS ingestion with retrieval timestamps and contract fixtures.
2. Add Linux package-version/backport adapters and Windows KB supersedence before claiming platform support.
3. Add authenticated evidence collection in an owned lab and independent ground-truth validation.
4. Evaluate a real local model against a blinded analyst rubric for correctness and source fidelity.
5. Add authenticated reviewer identity, immutable audit storage and a signed detection-content release process.

## Five-minute interview demonstration

1. Run tests and detection; explain the 2.4.50 incomplete fix.
2. Compare a banner finding with a host finding and a vendor-suffixed unknown.
3. Open the risk plan and explain each scoring term and synthetic data limitation.
4. Try export without approval; explain the failure. Review a test plan, then show changed evidence invalidates approval.
5. Explain why prompt injection in model advice does not authorize actions, and what a production deployment would require.

These projects were built with AI assistance. Only claim work you understand and have personally reviewed; test results establish lab behavior, not years of professional vulnerability management experience.
