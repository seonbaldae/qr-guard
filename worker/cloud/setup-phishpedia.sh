#!/usr/bin/env bash
# Run as the non-root build user after installing git/build-essential/unzip/libgl1.
# This builds the reference feature cache; it does not scan sites or test samples.
set -euo pipefail
export UV_PYTHON_INSTALL_DIR=/opt/phishpedia/python
export UV_CACHE_DIR=/tmp/qr-phishpedia-uv-cache
export OMP_NUM_THREADS=4 MKL_NUM_THREADS=4 MAX_JOBS=4
export CUDA_VISIBLE_DEVICES="" KMP_DUPLICATE_LIB_OK=TRUE
cd /opt/phishpedia
git init -q .
git remote add origin https://github.com/lindsey98/Phishpedia.git
git fetch -q --depth 1 origin d030779aad0aebd224f2cb60ed1c1603a8efcb1f
git checkout -q --detach FETCH_HEAD
git apply /tmp/qr-phishpedia/logo_matching.patch
cp /tmp/qr-phishpedia/analyze-brand.py /tmp/qr-phishpedia/run-phishpedia.py .
cp /tmp/qr-phishpedia/cache-phishpedia.py qr-cache-reference.py
uv python install 3.10.22
uv venv --seed --python 3.10.22 .venv
uv pip install --python .venv/bin/python 'torch==2.2.2+cpu' 'torchvision==0.17.2+cpu' --index-url https://download.pytorch.org/whl/cpu
uv pip install --python .venv/bin/python 'numpy==1.23.5' 'Pillow==9.5.0' 'opencv-python-headless==4.8.1.78' 'tldextract==5.1.3' 'gdown==5.2.0' 'PyYAML==6.0.2' 'tqdm==4.67.1' 'matplotlib==3.7.5' 'setuptools==69.5.1' wheel ninja
uv pip install --python .venv/bin/python --no-build-isolation 'git+https://github.com/facebookresearch/detectron2.git@92ae9f0b92aba5867824b4f12aa06a22a60a45d3'
mkdir -p models
.venv/bin/gdown 1tE2Mu5WC8uqCxei3XqAd7AWaP5JTmVWH -O models/rcnn_bet365.pth
.venv/bin/gdown 1Q6lqjpl4exW7q_dPbComcj0udBMDl8CW -O models/faster_rcnn.yaml
.venv/bin/gdown 1H0Q_DbdKPLFcZee8I14K62qV7TTy7xvS -O models/resnetv2_rgb_new.pth.tar
.venv/bin/gdown 1fr5ZxBKyDiNZ_1B6rRAfZbAHBBoUjZ7I -O models/expand_targetlist.zip
.venv/bin/gdown 1qSdkSSoCYUkZMKs44Rup_1DPBxHnEKl1 -O models/domain_map.pkl
unzip -q models/expand_targetlist.zip -d models/expand_targetlist
if [ -d models/expand_targetlist/expand_targetlist ]; then
  mv models/expand_targetlist/expand_targetlist/* models/expand_targetlist/
  rm -rf models/expand_targetlist/expand_targetlist
fi
# Model installation includes precomputing the protected reference logo features.
.venv/bin/python -u qr-cache-reference.py --root /opt/phishpedia --batch-size 8 --threads 4
.venv/bin/python - <<'PY'
import hashlib, json, pathlib, subprocess
root = pathlib.Path('/opt/phishpedia')
names = ['models/rcnn_bet365.pth', 'models/faster_rcnn.yaml', 'models/resnetv2_rgb_new.pth.tar', 'models/domain_map.pkl', 'LOGO_FEATS.npy', 'LOGO_FILES.npy']
manifest = {'sourceRevision': 'd030779aad0aebd224f2cb60ed1c1603a8efcb1f', 'detectronRevision': '92ae9f0b92aba5867824b4f12aa06a22a60a45d3', 'files': {}}
for name in names:
    path = root / name
    digest = hashlib.sha256()
    with path.open('rb') as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b''): digest.update(chunk)
    manifest['files'][name] = {'bytes': path.stat().st_size, 'sha256': digest.hexdigest()}
(root / 'runtime-manifest.json').write_text(json.dumps(manifest, indent=2))
(root / 'runtime-requirements.txt').write_bytes(subprocess.check_output([str(root / '.venv/bin/python'), '-m', 'pip', 'freeze']))
PY
rm -rf .git /tmp/qr-phishpedia-uv-cache
printf 'Phishpedia runtime and reference cache prepared.\n'
