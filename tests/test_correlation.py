"""Deterministic correlation fixtures, never real target visits."""
from datetime import datetime, timezone
import importlib
import importlib.util

from app.models import Evidence, ScanReport, StaticAnalysisResult, ProviderResult
import pytest


def report():
    now = datetime.now(timezone.utc)
    return ScanReport(scan_id='correlation', status='completed', mode='sandbox',
                      requested_url='https://demo.example.test/', updated_at=now,
                      static_analysis=StaticAnalysisResult(status='completed', registered_domain='example.test',
                          providers=[ProviderResult(name='google_safe_browsing', status='checked', matched=True, checked_at=now)]),
                      evidence=[Evidence(id='gsb', kind='known_threat_match', source='google_safe_browsing',
                                         observed_at=now, summary='Known threat')])


def test_known_threat_has_priority_and_real_evidence():
    spec = importlib.util.find_spec('app.correlation')
    assert spec is not None, 'pure correlation engine missing'
    from app.correlation import correlate
    r = report()
    verdict = correlate(r)
    assert verdict.level == 'malicious'
    assert verdict.evidence_ids == ['gsb']
    assert r.verdict is None


def test_brand_mismatch_and_password_require_typed_completed_observations():
    from app.correlation import correlate
    from app import models
    assert hasattr(models, 'DomAnalysis'), 'v0.3 analysis models missing'
    from app.models import DomAnalysis, LogoAnalysis, DomainAnalysis, SandboxResult
    from app.normalization import BrandAssessment
    r = report()
    r.static_analysis.providers[0].matched = False
    r.evidence = []
    for key, kind in [('logo', 'logo_observation'), ('domain', 'brand_domain_comparison'), ('dom', 'dom_observation')]:
        r.evidence.append(Evidence(id=key, kind=kind, source='browser', observed_at=r.updated_at, summary=kind))
    r.sandbox_analysis = SandboxResult(status='completed', final_url=r.requested_url,
        logo_analysis=LogoAnalysis(status='completed', detected_brand='Controlled Brand', similarity_score=0.95,
                                   method='phishpedia', reference_version='fixture-v1'),
        domain_analysis=DomainAnalysis(status='completed', official_domain='official.test',
                                       observed_domain='example.test', domain_mismatch=True),
        dom_analysis=DomAnalysis(page_title='Login', password_field_count=1, sensitive_field_types=['password'], forms=[]))
    trusted = BrandAssessment(reliable=True, official_domains=('official.test',), evidence_ids=('logo', 'domain'))
    v = correlate(r, brand=trusted)
    assert v.level == 'suspicious'
    assert set(v.evidence_ids) == {'logo', 'domain', 'dom'}
    assert correlate(r).level == 'unknown', 'raw similarity must not establish trust'


def complete():
    from app.models import SandboxResult, DomAnalysis, NetworkAnalysis, RedirectAnalysis, LogoAnalysis, DomainAnalysis, ScreenshotState
    from app.normalization import BrandAssessment
    r = report()
    r.static_analysis.providers[0].matched = False
    r.evidence = [Evidence(id=k, kind=v, source='browser', observed_at=r.updated_at, summary=v)
                  for k, v in [('logo','logo_observation'),('domain','brand_domain_comparison'),('dom','dom_observation'),
                               ('network','network_observation'),('redirect','redirect_observation')]]
    r.sandbox_analysis = SandboxResult(status='completed', final_url=r.requested_url, http_status=200,
        screenshot=ScreenshotState(status='ready', available=True),
        dom_analysis=DomAnalysis(page_title='Ordinary login', password_field_count=1, sensitive_field_types=['password'], forms=[]),
        network_analysis=NetworkAnalysis(request_hosts=['cdn.other.test'],request_count=2,blocked_request_count=0),
        redirect_analysis=RedirectAnalysis(redirected=False, final_url=r.requested_url, redirect_chain=[]),
        logo_analysis=LogoAnalysis(status='completed',detected_brand='Brand', similarity_score=.95,method='phishpedia',reference_version='test'),
        domain_analysis=DomainAnalysis(status='completed',official_domain='example.test',observed_domain='example.test',domain_mismatch=False))
    return r, BrandAssessment(reliable=True,official_domains=('example.test',), evidence_ids=('logo','domain'))


def test_completed_login_and_external_cdn_are_not_individually_suspicious():
    from app.correlation import correlate
    r, trust = complete()
    final = r.static_analysis.model_copy(deep=True)
    assert correlate(r, brand=trust, final_static=final).level == 'no_known_threat'


@pytest.mark.parametrize('missing', ['dom_analysis','network_analysis','redirect_analysis','logo_analysis','domain_analysis'])
def test_missing_required_data_never_means_clear(missing):
    from app.correlation import correlate
    r, trust = complete()
    setattr(r.sandbox_analysis, missing, None)
    assert correlate(r,brand=trust,final_static=r.static_analysis).level == 'unknown'


@pytest.mark.parametrize('mode', ['gsb_failed','logo_failed','unidentified','blocked','incomplete','running'])
def test_failed_limited_or_unfinished_observations_are_unknown(mode):
    from app.correlation import correlate
    r, trust = complete()
    if mode == 'gsb_failed':
        r.static_analysis.providers[0].status='failed'; r.static_analysis.providers[0].matched=None
    elif mode == 'logo_failed': r.sandbox_analysis.logo_analysis.status='failed'
    elif mode == 'unidentified': r.sandbox_analysis.logo_analysis.detected_brand=None
    elif mode == 'blocked': r.sandbox_analysis.network_analysis.blocked_request_count=1
    elif mode == 'incomplete': r.sandbox_analysis.limitations=['DOM inspection incomplete']
    else: r.status='running'
    assert correlate(r,brand=trust,final_static=r.static_analysis).level == 'unknown'


def test_real_redirect_alone_is_not_suspicious_and_blocked_attempt_is_not_final():
    from app.correlation import correlate
    from app.models import RedirectEdge
    r, trust=complete()
    redir=r.sandbox_analysis.redirect_analysis
    redir.redirected=True
    redir.redirect_chain=[RedirectEdge(**{'from':'https://start.example.test/', 'to':r.requested_url,
        'type':'http','blocked':False,'statusCode':302})]
    assert correlate(r,brand=trust,final_static=r.static_analysis).level=='no_known_threat'
    redir.redirect_chain.append(RedirectEdge(**{'from':r.requested_url,'to':'https://blocked.test/',
        'type':'unknown','blocked':True,'statusCode':None}))
    assert correlate(r,brand=trust,final_static=r.static_analysis).level=='unknown'
    assert redir.final_url==r.requested_url


def test_suspicious_cross_domain_form_and_network_correlation_deduplicates_evidence():
    from app.correlation import correlate
    from app.models import FormObservation
    from app.normalization import BrandAssessment
    r,_=complete()
    r.sandbox_analysis.domain_analysis.domain_mismatch=True
    r.sandbox_analysis.domain_analysis.official_domain='official.test'
    r.sandbox_analysis.dom_analysis.forms=[FormObservation(method='post',action_host='collect.other.test')]
    r.sandbox_analysis.network_analysis.request_hosts=['collect.other.test']
    trust=BrandAssessment(reliable=True,official_domains=('official.test',),evidence_ids=('logo','domain','logo'))
    v=correlate(r,brand=trust,final_static=r.static_analysis)
    assert v.level=='suspicious'
    assert {'dom','network','logo','domain'}<=set(v.evidence_ids)
    assert len(v.evidence_ids)==len(set(v.evidence_ids))
    r.evidence=[e for e in r.evidence if e.id!='domain']
    assert correlate(r,brand=trust,final_static=r.static_analysis).level=='unknown'


def test_final_known_threat_overrides_other_signals():
    from app.correlation import correlate
    r,trust=complete()
    final=r.static_analysis.model_copy(deep=True)
    final.providers[0].matched=True
    r.evidence.append(Evidence(id='final-gsb',kind='known_threat_match',source='google_safe_browsing',observed_at=r.updated_at,summary='Final threat'))
    assert correlate(r,brand=trust,final_static=final).level=='malicious'


def test_missing_required_screenshot_is_not_clear():
    from app.correlation import correlate
    r, trust=complete()
    r.sandbox_analysis.screenshot.available=False
    assert correlate(r,brand=trust,final_static=r.static_analysis).level=='unknown'


def test_failed_static_report_cannot_become_clear_from_a_negative_provider():
    from app.correlation import correlate
    r,_=complete()
    r.mode='static';r.status='failed'
    assert correlate(r).level=='unknown'
