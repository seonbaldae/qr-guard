"""Verify real brand matching and production domain comparison without a frontend."""
import importlib.util
import json
from pathlib import Path
import runpy

root = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("brand_analyzer", root / "analyze-brand.py")
analyzer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(analyzer)

runpy.run_path(str(root / "run-phishpedia.py"), run_name="verification_setup")
from phishpedia import PhishpediaWrapper
from logo_matching import pred_brand
from PIL import Image
from utils import brand_converter
import pickle

model = PhishpediaWrapper()
with open(model.DOMAIN_MAP_PATH, "rb") as handle:
    domain_map = pickle.load(handle)

# Select an installed reference logo, preferring PayPal if available.
paths = [Path(str(item)) for item in model.LOGO_FILES]
paths.sort(key=lambda item: str(brand_converter(item.parent.name)).casefold() != "paypal")
selected = next((item for item in paths if item.is_file() and domain_map.get(brand_converter(item.parent.name))), None)
if selected is None:
    raise RuntimeError("No usable installed brand reference logo found")

with Image.open(selected) as image:
    width, height = image.size

brand, domains, similarity = pred_brand(
    model=model.SIAMESE_MODEL,
    domain_map=domain_map,
    logo_feat_list=model.LOGO_FEATS,
    file_name_list=model.LOGO_FILES,
    shot_path=str(selected),
    gt_bbox=[0, 0, width, height],
    similarity_threshold=model.SIAMESE_THRE,
    grayscale=False,
    do_resolution_alignment=False,
    do_aspect_ratio_check=False,
)
if brand is None or not domains:
    raise AssertionError("The model did not identify a reference logo above its threshold")
if isinstance(domains, str):
    domains = [domains]
officials = sorted({analyzer.hostname(value) for value in domains})
official = officials[0]

cases = [
    ("official", f"https://{official}/", "match"),
    ("official_subdomain", f"https://verification.{official}/", "match"),
    ("uppercase_and_port", f"https://{official.upper()}:443/", "match"),
    ("unrelated", "https://brand-verification.invalid/", "mismatch"),
    ("suffix_trick", f"https://{official}.attacker.invalid/", "mismatch"),
    ("prefix_trick", f"https://fake-{official}/", "mismatch"),
    ("userinfo_trick", f"https://{official}@attacker.invalid/", "mismatch"),
]
results = []
for name, url, expected in cases:
    actual = analyzer.hostname(url)
    matched = next((value for value in officials if analyzer.is_same_domain(actual, value)), None)
    status = "match" if matched else "mismatch"
    if status != expected:
        raise AssertionError(f"{name}: expected {expected}, got {status}")
    results.append({"case": name, "url": url, "status": status, "matchedReferenceDomain": matched})

print(json.dumps({
    "status": "passed",
    "identifiedBrand": str(brand),
    "referenceDomains": officials,
    "rawSimilarity": float(similarity),
    "passedCount": len(results),
    "cases": results,
    "scope": "Reference-logo recognition and production hostname comparison; not screenshot logo detection or real-site accuracy evaluation.",
}, ensure_ascii=False, indent=2))
