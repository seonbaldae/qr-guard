"""v0.3 jobs wire tests. Local HTTP test doubles, never real target traffic."""
import asyncio
import json
from datetime import datetime, timezone
import httpx
import pytest
from app.config import Settings
from app.worker import WorkerClient, WorkerError
from tests.api.test_scans import png_bytes


def snapshot(scan_id='job', **changes):
    data={'scanId':scan_id,'status':'completed','acceptedAt':datetime.now(timezone.utc).isoformat(),
          'finalUrl':'https://demo.example.test/','httpStatus':200,'screenshotStatus':'ready',
          'screenshotRef':f'internal:{scan_id}:png','capturedAt':datetime.now(timezone.utc).isoformat(),
          'domAnalysis':{'pageTitle':'Demo','passwordFieldCount':0,'sensitiveFieldTypes':[],'forms':[]},
          'networkAnalysis':{'requestHosts':['demo.example.test'],'requestCount':1,'blockedRequestCount':0},
          'redirectAnalysis':{'redirected':False,'finalUrl':'https://demo.example.test/','redirectChain':[]},
          'signals':[],'evidence':[],'limitations':[],'errorCode':None}
    data.update(changes)
    return data


def settings(**kwargs):
    return Settings(worker_url='http://worker:8001',demo_origins=('https://demo.example.test',),worker_egress_verified=True,**kwargs)


def test_jobs_posts_once_and_retrieves_separate_png_before_completion():
    async def run():
        calls=[]; snapshots=0; published=[]
        def handler(req):
            nonlocal snapshots
            calls.append((req.method,req.url.path))
            if req.method=='POST':
                assert json.loads(req.content)['scanId']=='job'
                return httpx.Response(202,json={'scanId':'job','status':'queued','acceptedAt':snapshot()['acceptedAt']})
            if req.url.path.endswith('/screenshot'): return httpx.Response(200,content=png_bytes(),headers={'content-type':'image/png'})
            snapshots+=1
            return httpx.Response(200,json=snapshot(status='running' if snapshots==1 else 'completed'))
        async def progress(job,png): published.append((job.status,png))
        c=WorkerClient(settings(),httpx.MockTransport(handler))
        result,png=await c.analyze('job','https://demo.example.test/',on_progress=progress)
        assert result.dom_analysis.password_field_count==0
        assert png==png_bytes()
        assert published[0]==('running',png)
        assert calls.count(('POST','/internal/jobs'))==1
        assert calls.count(('GET','/internal/jobs/job/screenshot'))==1
    asyncio.run(run())


@pytest.mark.parametrize('change',[
    {'scanId':'wrong'}, {'redirectAnalysis':{'redirected':False,'finalUrl':'https://blocked.test/','redirectChain':[]}},
    {'finalUrl':'http://169.254.169.254/'}, {'networkAnalysis':{'requestHosts':[],'requestCount':0,'blockedRequestCount':2}},
    {'domAnalysis':{'pageTitle':None,'passwordFieldCount':-1,'sensitiveFieldTypes':[],'forms':[]}},
])
def test_invalid_jobs_fail_closed(change):
    async def run():
        def handler(req):
            return httpx.Response(202 if req.method=='POST' else 200,json=(
                {'scanId':'job','status':'queued','acceptedAt':snapshot()['acceptedAt']} if req.method=='POST' else snapshot(**change)))
        with pytest.raises(WorkerError):
            await WorkerClient(settings(),httpx.MockTransport(handler)).analyze('job','https://demo.example.test/')
    asyncio.run(run())


def test_failed_job_after_early_png_preserves_progress():
    async def run():
        seen=[]
        def handler(req):
            if req.method=='POST':return httpx.Response(202,json={'scanId':'job','status':'queued','acceptedAt':snapshot()['acceptedAt']})
            if req.url.path.endswith('screenshot'):return httpx.Response(200,content=png_bytes(),headers={'content-type':'image/png'})
            return httpx.Response(200,json=snapshot(status='failed',errorCode='worker_timeout',domAnalysis=None))
        async def progress(job,png):seen.append(png)
        result,png=await WorkerClient(settings(),httpx.MockTransport(handler)).analyze('job','https://demo.example.test/',on_progress=progress)
        assert result.status=='failed' and png==png_bytes() and seen==[png]
    asyncio.run(run())
