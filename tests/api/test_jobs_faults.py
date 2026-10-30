"""Fault injection for jobs polling, image bounds and destination privacy."""
import asyncio
from unittest.mock import patch
import httpx
import pytest
from app.worker import WorkerClient, WorkerError
from .test_jobs_v03 import settings, snapshot
from .test_scans import png_bytes


@pytest.mark.parametrize('case', ['wrong_id','no_redirect','wrong_content_type','corrupt_png','oversize','http_redirect','busy','missing','truncated','private_title','blank'])
def test_jobs_boundaries_and_sensitive_output(case):
    async def run():
        def handler(req):
            if req.method=='POST':
                if case=='busy':return httpx.Response(429)
                return httpx.Response(202,json={'scanId':'wrong' if case=='wrong_id' else 'job','status':'queued','acceptedAt':snapshot()['acceptedAt']})
            if req.url.path.endswith('screenshot'):
                if case=='http_redirect':return httpx.Response(302,headers={'location':'https://do-not-visit.test/'})
                content=b'bad' if case=='corrupt_png' else png_bytes()
                if case=='blank':
                    from io import BytesIO
                    from PIL import Image
                    blank=BytesIO();Image.new('RGB',(2,2),'white').save(blank,format='PNG');content=blank.getvalue()
                if case=='oversize':content=b'x'*(4*1024*1024+1)
                return httpx.Response(200,content=content,headers={'content-type':'text/html' if case=='wrong_content_type' else 'image/png'})
            if case=='missing':return httpx.Response(404)
            value=snapshot()
            if case=='no_redirect':value['redirectAnalysis']=None
            if case=='truncated':value['limitations']=['Request limit reached token=secret-sentinel']
            if case=='private_title':value['domAnalysis']['pageTitle']='token=secret-sentinel https://example.test/?secret=secret-sentinel'
            return httpx.Response(200,json=value)
        client=WorkerClient(settings(),httpx.MockTransport(handler))
        if case in {'no_redirect','truncated','private_title','blank'}:
            job,_=await client.analyze('job','https://demo.example.test/')
            if case=='no_redirect':assert job.redirect_analysis is None
            if case=='private_title':assert 'secret-sentinel' not in job.dom_analysis.page_title
            if case=='blank':assert any('blank' in reason.lower() for reason in job.limitations)
        else:
            with pytest.raises(WorkerError):await client.analyze('job','https://demo.example.test/')
    asyncio.run(run())


def test_poll_deadline_is_bounded_and_does_not_post_twice():
    async def run():
        calls=[]
        def handler(req):
            calls.append(req.method)
            if req.method=='POST':return httpx.Response(202,json={'scanId':'job','status':'queued','acceptedAt':snapshot()['acceptedAt']})
            return httpx.Response(200,json=snapshot(status='running',screenshotStatus='pending'))
        real_timeout=asyncio.timeout
        with patch('app.worker.asyncio.timeout', lambda _:real_timeout(.03)):
            with pytest.raises(WorkerError,match='worker_timeout'):
                await WorkerClient(settings(worker_poll_interval_ms=1),httpx.MockTransport(handler)).analyze('job','https://demo.example.test/')
        assert calls.count('POST')==1
    asyncio.run(run())
