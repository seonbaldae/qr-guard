import asyncio
import httpx
from app.main import create_app
from app.models import ScanRequest
from .support import fake_google
from .test_jobs_v03 import snapshot, settings
from .test_scans import png_bytes


def test_public_png_ready_while_verdict_pending_and_failure_retains_it():
    async def run():
        release=asyncio.Event(); polls=0
        async def worker(req):
            nonlocal polls
            if req.method=='POST':return httpx.Response(202,json={'scanId':scan_id,'status':'queued','acceptedAt':snapshot()['acceptedAt']})
            if req.url.path.endswith('screenshot'):return httpx.Response(200,content=png_bytes(),headers={'content-type':'image/png'})
            polls+=1
            if polls>1:
                await release.wait()
                return httpx.Response(200,json=snapshot(scan_id,status='failed',errorCode='worker_timeout',domAnalysis=None))
            return httpx.Response(200,json=snapshot(scan_id,status='running'))
        app=create_app(settings(),worker_transport=httpx.MockTransport(worker),threat_check=fake_google())
        service=app.state.scans
        request=ScanRequest(url='https://demo.example.test/',mode='sandbox')
        scan_id=service.create(request).scan_id
        task=asyncio.create_task(service.run(scan_id,request))
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://public') as client:
            try:
                for _ in range(100):
                    if service.reports[scan_id].sandbox_analysis.screenshot.available:break
                    await asyncio.sleep(.005)
                report=(await client.get(f'/api/scans/{scan_id}')).json()
                assert report['status']=='running'
                assert report['verdict'] is None
                assert (await client.get(f'/api/scans/{scan_id}/screenshot')).status_code==200
            finally:
                release.set();await task
            final=(await client.get(f'/api/scans/{scan_id}')).json()
            assert final['verdict']['level']=='unknown'
            assert final['sandboxAnalysis']['screenshot']['available'] is True
            assert (await client.get(f'/api/scans/{scan_id}/screenshot')).status_code==200
    asyncio.run(run())


def test_final_worker_data_reaches_public_contract_and_missing_brand_is_unknown():
    async def run():
        def worker(req):
            if req.method=='POST':
                import json
                body=json.loads(req.content)
                worker.scan_id=body['scanId']
                return httpx.Response(202,json={'scanId':worker.scan_id,'status':'queued','acceptedAt':snapshot()['acceptedAt']})
            if req.url.path.endswith('screenshot'):return httpx.Response(200,content=png_bytes(),headers={'content-type':'image/png'})
            return httpx.Response(200,json=snapshot(worker.scan_id))
        app=create_app(settings(),worker_transport=httpx.MockTransport(worker),threat_check=fake_google())
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://public') as client:
            created=await client.post('/api/scans',json={'url':'https://demo.example.test/','mode':'sandbox'})
            r=(await client.get('/api/scans/'+created.json()['scanId'])).json()
            assert r['sandboxAnalysis']['domAnalysis']['passwordFieldCount']==0
            assert r['sandboxAnalysis']['networkAnalysis']['requestCount']==1
            assert r['sandboxAnalysis']['logoAnalysis']['status']=='not_available'
            assert r['verdict']['level']=='unknown'
            assert 'screenshotRef' not in str(r)
            ids={e['id'] for e in r['evidence']}
            assert set(r['verdict']['evidenceIds'])<=ids
    asyncio.run(run())
