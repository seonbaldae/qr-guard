"""Offline container entry point; wraps, never edits, the team's analyze-brand.py.

Only operator-installed model/catalog files are hashed or loaded. No target I/O.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', required=True)
    args = parser.parse_args()
    incoming = Path(args.input)
    work = Path('/tmp/qr-brand') / incoming.name
    work.mkdir(parents=True, exist_ok=True)
    # Work in private tmpfs: the host mounts and input artifacts stay read-only.
    for name in ['shot.png', 'info.txt']:
        (work / name).write_bytes((incoming / name).read_bytes())
    spec = importlib.util.spec_from_file_location('team_brand', '/opt/phishpedia/analyze-brand.py')
    team = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(team)
    sys.argv = ['analyze-brand.py', '--input', str(work)]
    code = team.main()
    if code != 0:
        raise RuntimeError('brand_inference_failed')
    result = json.loads((work / 'brand-analysis.json').read_text())
    from phishpedia import PhishpediaWrapper
    model = PhishpediaWrapper()
    digest = hashlib.sha256()
    # Version the actual catalog and model-bound feature arrays, not a fabricated label.
    for path in [Path(model.DOMAIN_MAP_PATH), Path('/opt/phishpedia/LOGO_FEATS.npy'), Path('/opt/phishpedia/LOGO_FILES.npy')]:
        with path.open('rb') as file:
            for block in iter(lambda: file.read(1024 * 1024), b''):
                digest.update(block)
    result['provenance'] = {'engine':'phishpedia', 'similarityThreshold':float(model.SIAMESE_THRE),
                            'referenceVersion':digest.hexdigest()}
    # The parent only accepts this marked envelope, not the model's console messages.
    print('QR_BRAND_RESULT ' + json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
