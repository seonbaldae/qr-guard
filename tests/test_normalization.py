from datetime import datetime, timezone
import pytest
from app.models import SandboxResult


def envelope(**changes):
    value={'scanId':'scan','finalUrl':'https://demo.example.test/login',
           'brandAnalysis':{'engine':'phishpedia','status':'completed','signal':'brand_domain_inconsistency',
                            'candidateBrand':'Brand','referenceDomains':['official.test'], 'rawSimilarity':.94,
                            'domainComparison':{'status':'mismatch','actualHost':'demo.example.test','matchedReferenceDomain':None}},
           'provenance':{'referenceVersion':'a'*64,'similarityThreshold':.9,'engine':'phishpedia'}}
    value.update(changes)
    return value


def test_actual_brand_shape_normalizes_with_provenance_and_evidence():
    import app.normalization as n
    assert hasattr(n,'normalize_brand'), 'brand normalizer missing'
    s=SandboxResult(status='completed',final_url='https://demo.example.test/login')
    assessment,evidence=n.normalize_brand(envelope(),s,scan_id='scan',observed_at=datetime.now(timezone.utc))
    assert assessment.reliable and s.domain_analysis.domain_mismatch is True
    assert s.logo_analysis.similarity_score==.94
    assert set(assessment.evidence_ids)=={e.id for e in evidence}


@pytest.mark.parametrize('case',['wrong_scan','wrong_url','no_provenance','low_score','unidentified','wrong_comparison'])
def test_brand_results_without_trust_cannot_establish_reliable_identity(case):
    import app.normalization as n
    raw=envelope()
    if case=='wrong_scan':raw['scanId']='other'
    elif case=='wrong_url':raw['finalUrl']='https://elsewhere.test/'
    elif case=='no_provenance':raw.pop('provenance')
    elif case=='low_score':raw['brandAnalysis']['rawSimilarity']=.3
    elif case=='unidentified':raw['brandAnalysis']['candidateBrand']=None
    else:raw['brandAnalysis']['domainComparison']['actualHost']='other.test'
    s=SandboxResult(status='completed',final_url='https://demo.example.test/login')
    assessment,_=n.normalize_brand(raw,s,scan_id='scan',observed_at=datetime.now(timezone.utc))
    assert assessment.reliable is False


def test_completed_but_unidentified_model_is_unknown_not_unavailable():
    from app.normalization import normalize_brand
    raw=envelope()
    raw['brandAnalysis'].update(candidateBrand=None,signal='brand_unidentified',referenceDomains=[],rawSimilarity=.75)
    s=SandboxResult(status='completed',final_url=raw['finalUrl'])
    assessment,evidence=normalize_brand(raw,s,scan_id='scan',observed_at=datetime.now(timezone.utc))
    assert assessment.reliable is False
    assert s.logo_analysis.status=='unknown'
    assert s.logo_analysis.similarity_score==.75
    assert any(e.source=='phishpedia' for e in evidence)
