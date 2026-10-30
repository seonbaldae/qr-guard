"""Evidence-backed rules. Pure function: no HTTP, files, clocks or model calls."""
from app.models import ScanReport, StaticAnalysisResult, VerdictResult
from app.normalization import BrandAssessment
from app.precheck.url_rules import parse


def correlate(report: ScanReport, *, brand: BrandAssessment = BrandAssessment(),
              final_static: StaticAnalysisResult | None = None) -> VerdictResult:
    evidence = {item.id: item for item in report.evidence}
    providers = [p for stage in [report.static_analysis, final_static] if stage for p in stage.providers]
    matches = [key for key, item in evidence.items()
               if item.kind == 'known_threat_match' and item.source == 'google_safe_browsing']
    if matches and any(p.name == 'google_safe_browsing' and p.status == 'checked' and p.matched is True for p in providers):
        return VerdictResult(level='malicious', reasons=['Google Safe Browsing에서 알려진 위협이 발견되었습니다.'],
                             evidence_ids=matches, limitations=['위협 조회의 일치는 실제 정보 유출의 증거가 아닙니다.'])
    sandbox = report.sandbox_analysis
    logo, domain, dom = sandbox.logo_analysis, sandbox.domain_analysis, sandbox.dom_analysis
    network, redirect = sandbox.network_analysis, sandbox.redirect_analysis
    by_kind = lambda kind: [key for key, item in evidence.items() if item.kind == kind]
    if report.status in {'queued', 'running'}:
        return VerdictResult(level='unknown', reasons=['분석이 진행 중입니다.'])
    ids = list(dict.fromkeys([*brand.evidence_ids, *[key for key, item in evidence.items() if item.kind == 'dom_observation']]))
    if (brand.reliable and brand.evidence_ids and all(key in evidence for key in ids)
            and any(evidence[key].kind == 'dom_observation' for key in ids)
            and logo and logo.status == 'completed' and logo.detected_brand
            and domain and domain.status == 'completed' and domain.domain_mismatch is True
            and dom and (dom.password_field_count > 0 or 'otp' in dom.sensitive_field_types)):
        reasons = ['신뢰 가능한 브랜드 식별·공식 도메인 불일치와 민감정보 입력 필드가 함께 관찰되었습니다.']
        outside = {f.action_host for f in dom.forms if f.action_host and
                   parse('https://' + f.action_host).registered_domain not in brand.official_domains}
        if outside:
            reasons.append('관찰된 폼 목적지도 검증된 공식 브랜드 도메인 밖에 있습니다. 실제 제출은 확인하지 않았습니다.')
            if network and outside.intersection(network.request_hosts) and by_kind('network_observation'):
                ids.extend(by_kind('network_observation'))
                reasons.append('폼 목적지 호스트가 네트워크 요청 시도 관찰에도 나타납니다. 성공한 전송의 증거는 아닙니다.')
        if redirect and redirect.redirected and any(not e.blocked for e in redirect.redirect_chain) and by_kind('redirect_observation'):
            ids.extend(by_kind('redirect_observation'))
            reasons.append('로그인 페이지까지 실제 페이지 이동도 관찰되었습니다.')
        return VerdictResult(level='suspicious', reasons=reasons, evidence_ids=list(dict.fromkeys(ids)),
                             limitations=['폼 목적지와 입력 필드 관찰은 실제 제출·정보 유출의 증거가 아닙니다.', *sandbox.limitations])
    checked = lambda stage: bool(stage and stage.status == 'completed' and any(
        p.name == 'google_safe_browsing' and p.status == 'checked' and p.matched is False for p in stage.providers))
    static_only = report.mode == 'static'
    complete = report.status == 'completed' and checked(report.static_analysis)
    if not static_only:
        complete = bool(complete and checked(final_static) and sandbox.status == 'completed'
            and sandbox.screenshot.status == 'ready' and sandbox.screenshot.available
            and sandbox.final_url and dom and network and redirect and redirect.final_url == sandbox.final_url
            and network.blocked_request_count == 0 and not any(e.blocked for e in redirect.redirect_chain)
            and not sandbox.limitations and brand.reliable and brand.evidence_ids
            and all(key in evidence for key in brand.evidence_ids)
            and logo and logo.status == 'completed' and logo.detected_brand
            and domain and domain.status == 'completed' and domain.domain_mismatch is False
            and all(by_kind(kind) for kind in ['dom_observation', 'network_observation', 'redirect_observation']))
    limits = list(dict.fromkeys(['검사 범위 내 위협 미탐지는 안전 보증이 아닙니다.', *sandbox.limitations]))
    if static_only:
        limits.append('페이지 내용은 검사하지 않았습니다.')
    if complete:
        return VerdictResult(level='no_known_threat', reasons=['필수 검사 범위에서 알려진 위협이나 의심 조합이 발견되지 않았습니다.'],
            evidence_ids=list(evidence), limitations=limits)
    return VerdictResult(level='unknown', reasons=['필수 분석의 누락·실패 또는 신뢰할 수 없는 관찰로 결론을 내리지 못했습니다.'],
                         limitations=limits + ['미확인 분석은 정상 결과나 위험 신호 0건을 뜻하지 않습니다.'])
