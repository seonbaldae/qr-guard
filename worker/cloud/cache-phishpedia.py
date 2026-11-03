"""Prepare reference embeddings in batches; never inspect a user's page.

Preprocessing and file selection follow pinned Phishpedia's
cache_reference_list/get_embedding. GroupNorm, feature extraction and row-wise
L2 normalization do not mix samples. CPU batch kernels can still introduce
small floating-point differences; bit-for-bit equivalence is not claimed.
Upstream source and models.py license notices remain in the prepared runtime.
"""

import argparse
import os
from pathlib import Path
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default="/opt/phishpedia")
    parser.add_argument("--batch-size", type=int, choices=(1, 2, 4, 8, 16), default=8)
    parser.add_argument("--threads", type=int, choices=(1, 2, 4), default=4)
    args = parser.parse_args()

    root = Path(args.root).resolve()
    sys.path.insert(0, str(root))

    import numpy as np
    from PIL import Image, ImageOps
    import torch
    from torchvision import transforms
    import yaml

    from logo_matching import load_model_weights
    from utils import l2_norm

    torch.set_num_threads(args.threads)
    with (root / "configs.yaml").open(encoding="utf-8") as handle:
        settings = yaml.safe_load(handle)["SIAMESE_MODEL"]

    # Match configs.py's absolute-path and targetlist-directory construction.
    weights_path = os.path.abspath(os.path.join(str(root), settings["WEIGHTS_PATH"]))
    targetlist_zip = os.path.abspath(os.path.join(str(root), settings["TARGETLIST_PATH"]))
    targetlist_path = os.path.join(
        os.path.dirname(targetlist_zip),
        os.path.basename(targetlist_zip).split(".zip")[0],
    )
    model = load_model_weights(
        num_classes=settings["NUM_CLASSES"], weights_path=weights_path,
    )
    if model.training:
        raise RuntimeError("Reference embedding model must be in evaluation mode")
    device = "cuda" if torch.cuda.is_available() else "cpu"
    transform = transforms.Compose([
        transforms.ToTensor(),
        transforms.Normalize(mean=[0.5, 0.5, 0.5], std=[0.5, 0.5, 0.5]),
    ])

    features, filenames = [], []
    pending_tensors, pending_paths = [], []

    def remember(rows, paths):
        if rows.ndim != 2 or rows.shape != (len(paths), 2048):
            raise ValueError("Unexpected reference embedding shape")
        if not np.isfinite(rows).all():
            raise ValueError("Reference embeddings contain non-finite values")
        features.extend(rows)
        filenames.extend(paths)

    def flush():
        if not pending_tensors:
            return
        with torch.no_grad():
            try:
                batch = torch.stack(pending_tensors).to(device)
                rows = l2_norm(model.features(batch)).cpu().numpy()
            except OSError:
                # Retain the upstream per-image OSError skip rule if an I/O
                # error unexpectedly occurs during batch feature extraction.
                for tensor, filename in zip(pending_tensors, pending_paths):
                    try:
                        row = l2_norm(model.features(tensor[None, ...].to(device))).cpu().numpy()
                    except OSError:
                        print(f"Error opening image: {filename}", flush=True)
                        continue
                    remember(row, [filename])
            else:
                remember(rows, pending_paths)
        pending_tensors.clear()
        pending_paths.clear()
        print(f"Prepared {len(filenames)} reference logo embeddings", flush=True)

    # Preserve upstream os.listdir order, extension spelling and prefix rules.
    for target in os.listdir(targetlist_path):
        if target.startswith("."):
            continue
        for logo_path in os.listdir(os.path.join(targetlist_path, target)):
            if not any(logo_path.endswith(ext) for ext in (".png", "PNG", ".jpeg", ".jpg", ".JPG", ".JPEG")):
                continue
            if any(logo_path.startswith(prefix) for prefix in ("loginpage", "homepage")):
                continue
            filename = str(os.path.join(targetlist_path, target, logo_path))
            try:
                with Image.open(filename) as source:
                    image = source.convert("RGB")
                    # Keep upstream's floor padding, including its odd-size
                    # behavior. ImageOps.pad/contain would change the pixels.
                    image = ImageOps.expand(image, (
                        (max(image.size) - image.size[0]) // 2,
                        (max(image.size) - image.size[1]) // 2,
                        (max(image.size) - image.size[0]) // 2,
                        (max(image.size) - image.size[1]) // 2,
                    ), fill=(255, 255, 255))
                    image = image.resize((128, 128))
                    tensor = transform(image)
            except OSError:
                print(f"Error opening image: {filename}", flush=True)
                continue
            pending_tensors.append(tensor)
            pending_paths.append(filename)
            if len(pending_tensors) >= args.batch_size:
                flush()
    flush()

    if not features or len(features) != len(filenames):
        raise ValueError("Reference list is empty or inconsistent")
    # np.asarray preserves the upstream float feature dtype and infers a
    # Unicode filename dtype of sufficient width, just as np.save(list) does.
    arrays = {"LOGO_FEATS.npy": np.asarray(features), "LOGO_FILES.npy": np.asarray(filenames)}
    temporary = []
    try:
        for name, array in arrays.items():
            staging = root / (name + ".preparing")
            with staging.open("wb") as handle:
                np.save(handle, array, allow_pickle=False)
            temporary.append((staging, root / name))
        # No live request uses this build VM. Publish only after both complete.
        for staging, destination in temporary:
            os.replace(staging, destination)
    finally:
        for staging, _ in temporary:
            staging.unlink(missing_ok=True)
    print(f"Saved {len(filenames)} reference logo embeddings", flush=True)


if __name__ == "__main__":
    main()
