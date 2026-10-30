"""Pure normalization of actual analyzer observations; missing data stays unknown."""
from dataclasses import dataclass
from datetime import datetime
import math
import re
from urllib.parse import urlsplit

from app.models import DomainAnalysis, Evidence, LogoAnalysis, SandboxResult
from app.precheck.url_rules import parse


@dataclass(frozen=True)
class BrandAssessment:
    reliable: bool = False
    official_domains: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()


def domain_of(host: str) -> str | None:
    if not isinstance(host, str) or not re.fullmatch(r'[A-Za-z0-9._-]{1,255}', host):
        return None
    return parse('https://' + host).registered_domain


def normalize_brand(raw: dict | None, sandbox: SandboxResult, *, scan_id: str,
                    observed_at: datetime) -> tuple[BrandAssessment, list[Evidence]]:
    """Consume only a trusted runner envelope, never the legacy block/allow verdict."""
    sandbox.logo_analysis = LogoAnalysis(status='not_available', method='phishpedia')
    sandbox.domain_analysis = DomainAnalysis(status='unknown')
    unknown = BrandAssessment(), []
    try:
        if not raw or raw['scanId'] != scan_id or raw['finalUrl'] != sandbox.final_url:
            return unknown
        a, p = raw['brandAnalysis'], raw['provenance']
        if a['status'] != 'completed' or a['engine'] != 'phishpedia' or p['engine'] != 'phishpedia':
            return unknown
        brand = a['candidateBrand']
        score, threshold = a['rawSimilarity'], p['similarityThreshold']
        if (brand is None and a['signal'] == 'brand_unidentified'
                and re.fullmatch(r'[a-f0-9]{64}', p['referenceVersion'])
                and type(threshold) in (int,float) and math.isfinite(threshold) and 0 < threshold <= 1
                and (score is None or (type(score) in (int,float) and math.isfinite(score) and 0 <= score <= 1))):
            sandbox.logo_analysis = LogoAnalysis(status='unknown',similarity_score=score,method='phishpedia',
                                                 reference_version=p['referenceVersion'])
            item = Evidence(id=f'{scan_id}-brand-unidentified',kind='logo_observation',source='phishpedia',
                observed_at=observed_at,summary='Phishpedia 추론은 완료했지만 신뢰 가능한 브랜드를 식별하지 못했습니다.',
                data={'identified':False,'similarity':score,'referenceVersion':p['referenceVersion']})
            return BrandAssessment(), [item]
        if (not isinstance(brand, str) or not re.fullmatch(r'[\w .&()/-]{1,100}', brand)
                or type(score) not in (float, int) or type(threshold) not in (float, int)
                or not math.isfinite(score) or not math.isfinite(threshold) or score < threshold
                or not 0 < threshold <= 1 or not 0 <= score <= 1
                or not re.fullmatch(r'[a-f0-9]{64}', p['referenceVersion'])):
            return unknown
        refs = a['referenceDomains']
        if not isinstance(refs, list) or not 1 <= len(refs) <= 100:
            return unknown
        domains = [domain_of(h) for h in refs]
        if not domains or any(h is None for h in domains):
            return unknown
        official = tuple(sorted({h for h in domains if h is not None}))
        host = urlsplit(sandbox.final_url).hostname
        observed = domain_of(host)
        comparison = a['domainComparison']
        if not observed or comparison['actualHost'] != host:
            return unknown
        mismatch = observed not in official
        if comparison['status'] != ('mismatch' if mismatch else 'match'):
            return unknown
        if a['signal'] != ('brand_domain_inconsistency' if mismatch else 'brand_domain_match'):
            return unknown
        sandbox.logo_analysis = LogoAnalysis(status='completed', detected_brand=brand, similarity_score=score,
                                             method='phishpedia', reference_version=p['referenceVersion'])
        sandbox.domain_analysis = DomainAnalysis(status='completed', official_domain=official[0] if mismatch else observed,
                                                 observed_domain=observed, domain_mismatch=mismatch)
        ids = (f'{scan_id}-brand-logo', f'{scan_id}-brand-domain')
        evidence = [Evidence(id=ids[0],kind='logo_observation',source='phishpedia',observed_at=observed_at,
                             summary='모델의 실제 임계값을 충족한 브랜드 식별입니다.', data={'brand':brand,'similarity':score,'referenceVersion':p['referenceVersion']}),
                    Evidence(id=ids[1],kind='brand_domain_comparison',source='phishpedia',observed_at=observed_at,
                             summary='동일 작업의 실제 도착 도메인과 검증된 기준 도메인을 비교했습니다.',
                             data={'observedDomain':observed,'officialDomain':sandbox.domain_analysis.official_domain,'mismatch':mismatch})]
        return BrandAssessment(True, official, ids), evidence
    except (KeyError, TypeError, ValueError, AttributeError):
        return unknown
