"""Regenerate the documented synthetic dataset; no live inventory is collected."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def main():
    cases = []
    for cve, affected in [('CVE-2021-41773', ['2.4.49']), ('CVE-2021-42013', ['2.4.49', '2.4.50'])]:
        for version in ['2.4.9', '2.4.48', '2.4.49', '2.4.50', '2.4.51', '2.4.100']:
            cases.append(dict(name=f'{cve}-host-{version}', cve=cve,
                              asset=dict(asset_id='test-host', product='httpd', source='host_inventory', version=version),
                              expected='affected_version' if version in affected else 'not_affected'))
        variations = [
            ('banner', dict(source='network_banner'), 'potential'),
            ('missing', dict(version=''), 'unknown'),
            ('vendor-suffix', dict(version='2.4.49-ubuntu1'), 'unknown'),
            ('prerelease', dict(version='2.4.49-rc1'), 'unknown'),
            ('vendor-fixed', dict(vendor_patch_status='fixed', patch_reference='synthetic-vendor-advisory-001'), 'not_affected'),
            ('unproven-fix', dict(vendor_patch_status='fixed'), 'unknown'),
            ('other-product', dict(product='nginx'), 'not_applicable'),
            ('spoofed-patch-banner', dict(source='network_banner', vendor_patch_status='fixed', patch_reference='untrusted-banner'), 'unknown'),
        ]
        for name, overrides, expected in variations:
            asset = dict(asset_id='test-host', product='httpd', source='host_inventory', version='2.4.49')
            asset.update(overrides)
            cases.append(dict(name=f'{cve}-{name}', cve=cve, asset=asset, expected=expected))
    write(ROOT / 'detection-content-lab/fixtures.json', cases)
    inventory = [
        dict(asset_id='web-public', product='httpd', version='2.4.49', source='host_inventory', platform='Linux'),
        dict(asset_id='web-banner', product='Apache HTTP Server', version='2.4.50', source='network_banner', platform='unknown'),
        dict(asset_id='web-fixed', product='httpd', version='2.4.51', source='host_inventory', platform='Windows'),
        dict(asset_id='web-vendor', product='apache2', version='2.4.49-ubuntu1', source='host_inventory', platform='Linux'),
        dict(asset_id='web-backport', product='httpd', version='2.4.49', source='host_inventory', platform='Linux', vendor_patch_status='fixed', patch_reference='synthetic-vendor-advisory-001'),
    ]
    write(ROOT / 'detection-content-lab/inventory.json', inventory)
    write(ROOT / 'ai-vulnerability-triage/asset-context.json', {
        a['asset_id']: dict(criticality=5 if a['asset_id'] == 'web-public' else 2,
                            internet_exposed=a['asset_id'] in ('web-public', 'web-banner')) for a in inventory})
    write(ROOT / 'ai-vulnerability-triage/intelligence.json', {
        cve: dict(cvss=9.8, epss=0.9 if cve.endswith('42013') else 0.8, kev=True,
                  as_of='2026-11-26', data_kind='synthetic demonstration, not a downloaded feed',
                  sources=['https://www.first.org/epss/', 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'])
        for cve in ('CVE-2021-41773', 'CVE-2021-42013')})


if __name__ == '__main__':
    main()
