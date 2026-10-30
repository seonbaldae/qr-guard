"""Reviewer regressions: private lookup URLs must not use public redaction."""
import asyncio
import json
import httpx
from app.main import create_app
from .support import fake_google, google_result
from .test_jobs_v03 import snapshot, settings
from .test_scans import png_bytes


def test_final_query_sensitive_google_match_uses_private_url_not_public_redaction():
    async def run():
        final='https://demo.example.test/login?token=private-sentinel'
        seen=[];scan_id=None
        def check(url):
            seen.append(url)
            return google_result(matched=url==final)
        def handler(req):
            nonlocal scan_id
            if req.method=='POST':
                scan_id=json.loads(req.content)['scanId']
                return httpx.Response(202,json={'scanId':scan_id,'status':'queued','acceptedAt':snapshot()['acceptedAt']})
            if req.url.path.endswith('screenshot'):
                return httpx.Response(200,content=png_bytes(),headers={'content-type':'image/png'})
            return httpx.Response(200,json=snapshot(scan_id,finalUrl=final,redirectAnalysis={
                'redirected':True,'finalUrl':final,'redirectChain':[]}))
        app=create_app(settings(),worker_transport=httpx.MockTransport(handler),threat_check=check)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://public') as c:
            created=await c.post('/api/scans',json={'url':'https://demo.example.test/','mode':'sandbox'})
            report=(await c.get('/api/scans/'+created.json()['scanId'])).json()
            assert final in seen
            assert report['verdict']['level']=='malicious'
            assert 'private-sentinel' not in json.dumps(report)
    asyncio.run(run())


def test_query_only_change_does_not_bind_old_png_to_new_destination():
    async def run():
        first='https://demo.example.test/login?token=first-private'
        last='https://demo.example.test/login?token=last-private'
        scan_id=None;polls=0;brand_calls=[]
        def handler(req):
            nonlocal scan_id,polls
            if req.method=='POST':
                scan_id=json.loads(req.content)['scanId']
                return httpx.Response(202,json={'scanId':scan_id,'status':'queued','acceptedAt':snapshot()['acceptedAt']})
            if req.url.path.endswith('screenshot'):
                return httpx.Response(200,content=png_bytes(),headers={'content-type':'image/png'})
            polls+=1
            url=first if polls==1 else last
            # A future transport may omit transition metadata; full destinations still differ.
            return httpx.Response(200,json=snapshot(scan_id,status='running' if polls==1 else 'completed',
                finalUrl=url,redirectAnalysis={'redirected':False,'finalUrl':url,'redirectChain':[]}))
        app=create_app(settings(),worker_transport=httpx.MockTransport(handler),threat_check=fake_google())
        async def brand(*args):brand_calls.append(args);return None
        app.state.scans.brand.analyze=brand
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://public') as c:
            created=await c.post('/api/scans',json={'url':'https://demo.example.test/','mode':'sandbox'})
            report=(await c.get('/api/scans/'+created.json()['scanId'])).json()
            assert not brand_calls
            assert report['verdict']['level']=='unknown'
            assert 'first-private' not in json.dumps(report) and 'last-private' not in json.dumps(report)
    asyncio.run(run())


def test_private_destination_is_not_serialized_and_inconsistent_raw_urls_are_rejected():
    async def run():
        from app.worker import WorkerClient, WorkerError
        import pytest
        for inconsistent in [False, True]:
            def handler(req):
                if req.method=='POST':return httpx.Response(202,json={'scanId':'job','status':'queued','acceptedAt':snapshot()['acceptedAt']})
                if req.url.path.endswith('screenshot'):return httpx.Response(200,content=png_bytes(),headers={'content-type':'image/png'})
                return httpx.Response(200,json=snapshot(finalUrl='https://demo.example.test/?token=one-private',redirectAnalysis={
                    'redirected':False,'finalUrl':'https://demo.example.test/?token=' + ('two-private' if inconsistent else 'one-private'),'redirectChain':[]}))
            c=WorkerClient(settings(),httpx.MockTransport(handler))
            if inconsistent:
                with pytest.raises(WorkerError):await c.analyze('job','https://demo.example.test/')
            else:
                job,_=await c.analyze('job','https://demo.example.test/')
                assert job._lookup_url.endswith('token=one-private')
                assert 'one-private' not in job.model_dump_json()
    asyncio.run(run())


def test_missing_redirect_metadata_cannot_authorize_brand_destination_binding():
    async def run():
        scan_id=None;brand_calls=[]
        def handler(req):
            nonlocal scan_id
            if req.method=='POST':
                scan_id=json.loads(req.content)['scanId']
                return httpx.Response(202,json={'scanId':scan_id,'status':'queued','acceptedAt':snapshot()['acceptedAt']})
            if req.url.path.endswith('screenshot'):
                return httpx.Response(200,content=png_bytes(),headers={'content-type':'image/png'})
            return httpx.Response(200,json=snapshot(scan_id,redirectAnalysis=None))
        app=create_app(settings(),worker_transport=httpx.MockTransport(handler),threat_check=fake_google())
        async def brand(*args):brand_calls.append(args);return None
        app.state.scans.brand.analyze=brand
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://public') as c:
            created=await c.post('/api/scans',json={'url':'https://demo.example.test/','mode':'sandbox'})
            report=(await c.get('/api/scans/'+created.json()['scanId'])).json()
            assert not brand_calls
            assert report['verdict']['level']=='unknown'
            assert report['sandboxAnalysis']['screenshot']['available'] is True
    asyncio.run(run())
