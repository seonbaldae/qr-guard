"""Phishpedia 실행 어댑터. 분석 오류는 그대로 호출자에게 전달합니다."""

from pathlib import Path
import runpy

import numpy as np
import tldextract
import logo_matching


# 외부 다운로드 없이 패키지에 포함된 도메인 목록 사용
offline_extract = tldextract.TLDExtract(
    suffix_list_urls=(),
    fallback_to_snapshot=True,
)

logo_matching.tldextract.extract = offline_extract

# 이전에 수정된 소스에서도 같은 오프라인 분석기를 사용
logo_matching._offline_extract = offline_extract


# 첫 실행에서 list로 반환되는 로고 특징을 NumPy 배열로 변환
original_chunked_dot = logo_matching.chunked_dot


def safe_chunked_dot(logo_feat_list, img_feat, chunk_size=128):
    features = np.asarray(logo_feat_list, dtype=np.float32)

    if features.ndim != 2 or features.shape[0] == 0:
        raise ValueError("기준 로고 특징 배열이 비어 있거나 형식이 잘못됐습니다.")

    return original_chunked_dot(
        features,
        img_feat,
        chunk_size=chunk_size,
    )


logo_matching.chunked_dot = safe_chunked_dot

if __name__ == "__main__":
    print("오프라인 도메인 분석 및 로고 배열 변환 적용", flush=True)

    runpy.run_path(
        str(Path(__file__).with_name("phishpedia.py")),
        run_name="__main__",
    )
