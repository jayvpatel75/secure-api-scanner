"""Offline, evidence-aware Apache HTTP Server detection content. Python 3.11+."""
import argparse
import csv
import hashlib
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load_rules():
    rules = json.loads((HERE / 'rules.json').read_text())
    if len({r['cve'] for r in rules}) != len(rules):
        raise ValueError('Duplicate CVE rule')
    return rules


def evaluate(asset, rule):
    """An affected version is evidence of exposure, never proof of exploitation."""
    for key in ('asset_id', 'product', 'source'):
        if not isinstance(asset.get(key), str) or not asset[key].strip():
            raise ValueError(f'Missing {key}')
    if asset['source'] not in ('host_inventory', 'network_banner'):
        raise ValueError('Unsupported evidence source')
    version = asset.get('version', '')
    if not isinstance(version, str):
        raise ValueError('Version must be a string')
    state, reason = 'unknown', 'Unparseable, missing, or vendor-suffixed version; verify vendor advisory'
    if asset['product'].lower() not in ('apache http server', 'httpd', 'apache2'):
        state, reason = 'not_applicable', 'Product does not match the rule'
    elif re.fullmatch(r'\d+\.\d+\.\d+', version):
        if version not in rule['affected_versions']:
            state, reason = 'not_affected', 'Version outside this CVE rule; other CVEs may still apply'
        elif asset.get('vendor_patch_status') == 'fixed' and asset.get('patch_reference') and asset['source'] == 'host_inventory':
            state, reason = 'not_affected', 'Host inventory records vendor fix; retain patch reference for review'
        elif asset.get('vendor_patch_status') == 'fixed':
            state, reason = 'unknown', 'Patch assertion lacks host evidence or a patch reference'
        elif asset['source'] == 'network_banner':
            state, reason = 'potential', 'Banner matches affected version; authenticate host inventory to validate'
        else:
            state, reason = 'affected_version', 'Host inventory matches affected version; validate configuration and patch provenance'
    evidence = {k: asset[k] for k in sorted(asset)}
    digest = hashlib.sha256(json.dumps(evidence, sort_keys=True).encode()).hexdigest()
    return dict(finding_id=f"{asset['asset_id']}:{rule['cve']}", asset_id=asset['asset_id'],
                cve=rule['cve'], state=state, reason=reason, evidence=evidence,
                evidence_sha256=digest, rule_revision=rule['revision'],
                advisory=rule['advisory'], remediation=rule['remediation'],
                configuration_note=rule['configuration_note'])


def assess(assets, rules=None):
    if len({a['asset_id'] for a in assets}) != len(assets):
        raise ValueError('Duplicate asset ID; resolve conflicting inventory before assessment')
    return [evaluate(a, r) for a in assets for r in (rules or load_rules())]


def benchmark(cases):
    rules = {r['cve']: r for r in load_rules()}
    results = []
    for case in cases:
        actual = evaluate(case['asset'], rules[case['cve']])['state']
        results.append(dict(case=case['name'], expected=case['expected'], actual=actual,
                            passed=actual == case['expected']))
    # Binary efficacy uses only determinate host cases, not banners or unknowns.
    positive = 'affected_version'
    eligible = [r for r in results if r['expected'] in (positive, 'not_affected')]
    tp = sum(r['expected'] == positive and r['actual'] == positive for r in eligible)
    fp = sum(r['expected'] != positive and r['actual'] == positive for r in eligible)
    fn = sum(r['expected'] == positive and r['actual'] != positive for r in eligible)
    return dict(dataset='synthetic fixtures; not production efficacy', cases=len(results),
                passed=sum(r['passed'] for r in results), true_positives=tp,
                false_positives=fp, false_negatives=fn,
                precision=tp / (tp + fp) if tp + fp else None,
                recall=tp / (tp + fn) if tp + fn else None, results=results)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--inventory', type=Path, default=HERE / 'inventory.json')
    p.add_argument('--out', type=Path, default=HERE / 'reports')
    args = p.parse_args()
    findings = assess(json.loads(args.inventory.read_text()))
    metrics = benchmark(json.loads((HERE / 'fixtures.json').read_text()))
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'findings.json').write_text(json.dumps(findings, indent=2) + '\n')
    (args.out / 'efficacy.json').write_text(json.dumps(metrics, indent=2) + '\n')
    with (args.out / 'findings.csv').open('w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['finding_id', 'state', 'reason', 'advisory'])
        writer.writeheader()
        writer.writerows({k: row[k] for k in writer.fieldnames} for row in findings)
    print(json.dumps({k: v for k, v in metrics.items() if k != 'results'}, indent=2))
    if metrics['passed'] != metrics['cases']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
