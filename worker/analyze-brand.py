import argparse
import json
import math
import pickle
from pathlib import Path
import runpy
import sys
from urllib.parse import urlsplit


def number(value):
    if value is None:
        return None
    value = float(value)
    return value if math.isfinite(value) else None


def hostname(value):
    value = str(value).strip()
    parsed = urlsplit(value if "://" in value else "//" + value)
    host = parsed.hostname

    if not host:
        raise ValueError(f"도메인 형식 오류: {value}")

    return host.rstrip(".").encode("idna").decode("ascii").lower()


def is_same_domain(actual, official):
    # paypal.com, www.paypal.com은 일치.
    # fakepaypal.com, paypal.com.evil.example은 불일치.
    return actual == official or actual.endswith("." + official)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    args = parser.parse_args()

    directory = Path(args.input)
    output = directory / "brand-analysis.json"

    result = {
        "scanId": directory.name,
        "finalUrl": None,
        "brandAnalysis": {
            "engine": "phishpedia",
            "status": "failed",
            "signal": "unknown",
        },
    }

    try:
        url = (directory / "info.txt").read_text(
            encoding="utf-8"
        ).strip()

        if urlsplit(url).scheme not in ("http", "https"):
            raise ValueError("HTTP(S) URL이 아닙니다.")

        actual_host = hostname(url)
        result["finalUrl"] = url

        screenshot = directory / "shot.png"
        if not screenshot.is_file():
            raise FileNotFoundError("shot.png가 없습니다.")

        # 기존 오프라인 설정과 배열 변환 적용
        runpy.run_path(
            str(Path(__file__).with_name("run-phishpedia.py")),
            run_name="phishpedia_runtime_setup",
        )

        from phishpedia import PhishpediaWrapper
        from logo_recog import pred_rcnn
        from logo_matching import pred_brand

        model = PhishpediaWrapper()

        with open(model.DOMAIN_MAP_PATH, "rb") as file:
            domain_map = pickle.load(file)

        # 1. 화면에서 로고 위치 탐지
        boxes = pred_rcnn(str(screenshot), model.ELE_MODEL)

        if boxes is None:
            raise ValueError("스크린샷을 읽어 로고를 분석하지 못했습니다.")

        boxes = boxes.detach().cpu().numpy()

        candidates = []
        scores = []

        # 2. 최대 3개 로고 영역에서 브랜드 식별
        # 이 함수는 방문 도메인을 받지 않으므로,
        # 공식 도메인과 같아도 브랜드 정보를 지우지 않습니다.
        for box in boxes[:3]:
            brand, domains, similarity = pred_brand(
                model=model.SIAMESE_MODEL,
                domain_map=domain_map,
                logo_feat_list=model.LOGO_FEATS,
                file_name_list=model.LOGO_FILES,
                shot_path=str(screenshot),
                gt_bbox=box,
                similarity_threshold=model.SIAMESE_THRE,
                grayscale=False,
                do_resolution_alignment=False,
                do_aspect_ratio_check=False,
            )

            score = number(similarity)
            if score is not None:
                scores.append(score)

            if brand is not None:
                if not domains or score is None:
                    raise ValueError("식별 브랜드의 기준 자료가 불완전합니다.")

                candidates.append({
                    "brand": str(brand),
                    "domains": domains,
                    "similarity": score,
                })

        analysis = {
            "engine": "phishpedia",
            "status": "completed",
            "signal": "brand_unidentified",
            "candidateBrand": None,
            "referenceDomains": [],
            "rawSimilarity": max(scores) if scores else None,
            "detectedLogoCount": len(boxes),
            "domainComparison": {
                "status": "not_evaluated",
                "actualHost": actual_host,
                "matchedReferenceDomain": None,
            },
        }

        if candidates:
            # 식별된 후보 중 유사도가 가장 높은 브랜드 사용
            selected = max(
                candidates,
                key=lambda item: item["similarity"],
            )

            domains = selected["domains"]
            if isinstance(domains, str):
                domains = [domains]

            official_domains = sorted({
                hostname(domain) for domain in domains
            })

            if not official_domains:
                raise ValueError("비교 가능한 공식 도메인이 없습니다.")

            # 3. 실제 도메인과 공식 도메인 비교
            matched = next(
                (
                    official
                    for official in official_domains
                    if is_same_domain(actual_host, official)
                ),
                None,
            )

            analysis.update({
                "signal": (
                    "brand_domain_match"
                    if matched
                    else "brand_domain_inconsistency"
                ),
                "candidateBrand": selected["brand"],
                "referenceDomains": official_domains,
                "rawSimilarity": selected["similarity"],
                "domainComparison": {
                    "status": "match" if matched else "mismatch",
                    "actualHost": actual_host,
                    "matchedReferenceDomain": matched,
                },
            })

        result["brandAnalysis"] = analysis

    except Exception as error:
        result["brandAnalysis"] = {
            "engine": "phishpedia",
            "status": "failed",
            "signal": "unknown",
            "error": {
                "type": type(error).__name__,
                "message": str(error),
            },
        }

    output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print(f"JSON 저장: {output}", flush=True)
    return 0 if result["brandAnalysis"]["status"] == "completed" else 1


if __name__ == "__main__":
    sys.exit(main())

