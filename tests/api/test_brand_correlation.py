import asyncio
import json
import httpx
from app.main import create_app
from .support import fake_google, google_result
from .test_jobs_v03 import snapshot, settings
from .test_scans import png_bytes


def application(threat_check):
    scan_id = None
    def worker(req):
        nonlocal scan_id
        if req.method=='POST':
            scan_id=json.loads(req.content)['scanId']
            return httpx.Response(202,json={'scanId':scan_id,'status':'queued','acceptedAt':snapshot()['acceptedAt']})
        if req.url.path.endswith('screenshot'):
            return httpx.Response(200,content=png_bytes(),headers={'content-type':'image/png'})
        return httpx.Response(200,json=snapshot(scan_id,domAnalysis={
            'pageTitle':'Login','passwordFieldCount':1,'sensitiveFieldTypes':['otp','password'],
            'forms':[{'method':'post','actionHost':'other.test'}]}))
    return create_app(settings(),worker_transport=httpx.MockTransport(worker),threat_check=threat_check)


def test_trusted_brand_result_reaches_correlation_without_mapping_worker_block():
    async def run():
        app=application(fake_google())
        async def brand(scan,final_url,png):
            return {'scanId':scan,'finalUrl':final_url,'brandAnalysis':{'engine':'phishpedia','status':'completed',
                'signal':'brand_domain_inconsistency','candidateBrand':'Test Brand','rawSimilarity':.95,
                'referenceDomains':['official.test'],'domainComparison':{'status':'mismatch','actualHost':'demo.example.test'}},
                'provenance':{'engine':'phishpedia','similarityThreshold':.9,'referenceVersion':'a'*64}}
        app.state.scans.brand.analyze=brand
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://public') as client:
            c=await client.post('/api/scans',json={'url':'https://demo.example.test/','mode':'sandbox'})
            r=(await client.get('/api/scans/'+c.json()['scanId'])).json()
            assert r['verdict']['level']=='suspicious'
            assert r['sandboxAnalysis']['logoAnalysis']['status']=='completed'
            assert r['sandboxAnalysis']['domainAnalysis']['domainMismatch'] is True
            assert len(r['verdict']['evidenceIds'])==len(set(r['verdict']['evidenceIds']))
            assert set(r['verdict']['evidenceIds'])<={e['id'] for e in r['evidence']}
    asyncio.run(run())


def test_final_google_match_survives_unavailable_brand_runtime():
    async def run():
        count=0
        def check(url):
            nonlocal count
            count+=1
            return google_result(matched=count>1)
        app=application(check)
        async def forbidden_brand(*args):
            raise RuntimeError('brand must not be necessary for verified Google match')
        app.state.scans.brand.analyze=forbidden_brand
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://public') as client:
            c=await client.post('/api/scans',json={'url':'https://demo.example.test/','mode':'sandbox'})
            r=(await client.get('/api/scans/'+c.json()['scanId'])).json()
            assert r['verdict']['level']=='malicious'
            assert r['sandboxAnalysis']['screenshot']['available']
    asyncio.run(run())


def test_screenshot_from_earlier_page_is_not_attached_to_later_brand_destination():
    async def run():
        from app.worker import WorkerJob
        app=application(fake_google())
        async def moved(scan,url,*,on_progress):
            initial=WorkerJob.model_validate(snapshot(scan,status='running'))
            await on_progress(initial,png_bytes())
            final=WorkerJob.model_validate(snapshot(scan,finalUrl='https://demo.example.test/next',redirectAnalysis={
                'redirected':True,'finalUrl':'https://demo.example.test/next','redirectChain':[
                    {'from':url,'to':'https://demo.example.test/next','type':'client_navigation','blocked':False,'statusCode':None}]}))
            return final,png_bytes()
        async def forbidden(*args):raise AssertionError('wrong-page screenshot must not feed brand comparison')
        app.state.scans.worker.analyze=moved
        app.state.scans.brand.analyze=forbidden
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://public') as client:
            c=await client.post('/api/scans',json={'url':'https://demo.example.test/','mode':'sandbox'})
            r=(await client.get('/api/scans/'+c.json()['scanId'])).json()
            assert r['status']=='completed'
            assert r['verdict']['level']=='unknown'
            assert r['sandboxAnalysis']['finalUrl']=='https://demo.example.test/next'
            assert r['sandboxAnalysis']['screenshot']['available']
    asyncio.run(run())
