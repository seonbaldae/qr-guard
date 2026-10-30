"""Live FastAPI -> Unix-socket HTTP -> network-none Docker Worker verification.

No target/GSB/brand results are fabricated: only Google is an explicit no-match TEST DOUBLE.
Actual Chromium renders the existing allowlisted harmless fixture; unavailable Phishpedia stays unknown.
"""
import asyncio
import argparse
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time

import httpx
from PIL import Image
import uvicorn

from app.config import Settings
from app.main import create_app
from tests.api.support import fake_google


async def main(*, live=False):
    workspace = Path(__file__).resolve().parents[3]
    runtime = workspace / '.backend-runtime'
    runtime.mkdir(exist_ok=True)
    worker_root = workspace / 'repos/qr-guard-docker-worker/worker'
    name = 'qr-guard-backend-live' if live else 'qr-guard-backend-api-review'
    with tempfile.TemporaryDirectory(prefix='http-', dir=runtime) as temp:
        sock_path = Path(temp) / 'worker.sock'
        proxy = """const http=require('node:http'),{spawn}=require('node:child_process');
const worker=spawn(process.execPath,['/app/worker.cjs'],{stdio:'inherit'});
http.createServer((req,res)=>{const up=http.request({host:'127.0.0.1',port:4000,path:req.url,method:req.method,headers:req.headers},r=>{res.writeHead(r.statusCode,r.headers);r.pipe(res)});up.on('error',()=>{res.writeHead(502);res.end()});req.pipe(up)}).listen('/review/worker.sock');
"""
        command = ['docker','run','--rm','-d','--name',name,'--network','none','--read-only',
                   '--user',f'{os.getuid()}:{os.getgid()}','--env','HOME=/tmp',
                   '--cap-drop','ALL','--cap-add','SYS_CHROOT','--security-opt','no-new-privileges',
                   '--security-opt',f'seccomp={worker_root / "seccomp_profile.json"}',
                   '--pids-limit','256','--memory','1g','--cpus','1','--tmpfs','/tmp:rw,nosuid,nodev,size=256m',
                   '--shm-size','128m','--init','--mount',f'type=bind,src={temp},dst=/review',
                   '--mount',f'type=bind,src={workspace / ".worker-review/node/node_modules"},dst=/review-deps,readonly',
                   '--env','NODE_PATH=/review-deps',
                   '--entrypoint','node','qr-guard-review-worker:analysis-v03','-e',proxy]
        subprocess.run(command,check=True,capture_output=True,text=True)
        public = None
        server = None
        try:
            config = json.loads(subprocess.check_output(['docker','inspect',name],text=True))[0]
            assert config['HostConfig']['NetworkMode']=='none'
            assert config['HostConfig']['ReadonlyRootfs'] is True
            assert config['HostConfig']['CapDrop']==['ALL']
            assert config['Config']['User'].split(':')[0] != '0'
            assert not config['HostConfig'].get('PortBindings')
            for _ in range(100):
                if sock_path.exists():
                    break
                await asyncio.sleep(.05)
            transport = httpx.AsyncHTTPTransport(uds=str(sock_path))
            settings = Settings(worker_url='http://worker:4000',
                                demo_origins=('http://127.0.0.1:4000',),worker_egress_verified=True,
                                brand_worker_directory=str(worker_root) if live else None)
            app = create_app(settings,worker_transport=transport,threat_check=None if live else fake_google())
            reserved = socket.socket()
            reserved.bind(('127.0.0.1',0))
            port = reserved.getsockname()[1]
            server = uvicorn.Server(uvicorn.Config(app,host='127.0.0.1',port=port,log_level='error',access_log=False))
            public = asyncio.create_task(server.serve(sockets=[reserved]))
            while not server.started:
                if public.done():
                    await public
                await asyncio.sleep(.01)
            async with httpx.AsyncClient(base_url=f'http://127.0.0.1:{port}',trust_env=False) as client:
                # Check actual C health through the exact UDS HTTP transport before creating any target job.
                async with httpx.AsyncClient(transport=httpx.AsyncHTTPTransport(uds=str(sock_path)),base_url='http://worker:4000') as c:
                    for _ in range(100):
                        health=await c.get('/internal/health')
                        if health.status_code==200:break
                        await asyncio.sleep(.05)
                    assert health.status_code==200, subprocess.check_output(['docker','logs',name],text=True,stderr=subprocess.STDOUT)
                response=await client.post('/api/scans',json={'url':'http://127.0.0.1:4000/demo/normal','mode':'sandbox'})
                assert response.status_code==202
                scan_id=response.json()['scanId']
                early=None; final=None; png=None
                for _ in range(10000 if live else 800):
                    report=(await client.get(f'/api/scans/{scan_id}')).json()
                    if report['status']=='running' and report['sandboxAnalysis']['screenshot']['available']:
                        assert report['verdict'] is None
                        image=await client.get(f'/api/scans/{scan_id}/screenshot')
                        assert image.status_code==200
                        png=image.content;early=report
                    if report['status'] in {'completed','failed'}:
                        final=report;break
                    await asyncio.sleep(.02)
                assert early is not None, 'real early PNG while report was running'
                assert final['status']=='completed', final
                assert final['verdict']['level']=='unknown', 'unidentified/unavailable brand must not be called clean'
                sandbox=final['sandboxAnalysis']
                assert sandbox['domAnalysis']['pageTitle']=='선발대 테스트'
                assert sandbox['networkAnalysis']['requestCount']==1
                assert sandbox['redirectAnalysis']['finalUrl']=='http://127.0.0.1:4000/demo/normal'
                if live:
                    assert final['staticAnalysis']['providers'][0]['status']=='checked', 'real Google lookup must succeed'
                    assert final['staticAnalysis']['providers'][0]['matched'] is False
                    assert sandbox['logoAnalysis']['status']=='unknown', 'actual unbranded fixture must complete inference without claiming identity'
                    assert sandbox['logoAnalysis']['referenceVersion'], 'actual model/catalog provenance'
                    assert any(e['source']=='phishpedia' for e in final['evidence']), 'real model evidence'
                else:
                    assert sandbox['logoAnalysis']['status']=='not_available'
                assert 'screenshotRef' not in json.dumps(final)
                image=Image.open(io.BytesIO(png));image.load()
                assert image.size==(390,844)
                ids={e['id'] for e in final['evidence']}
                assert len(ids)==len(final['evidence'])
                assert all(set(s['evidenceIds'])<=ids for s in sandbox['signals'])
                output=workspace/'.worker-review'/('live-backend' if live else 'backend-v03')
                output.mkdir(parents=True,exist_ok=True)
                (output/'report.json').write_text(json.dumps(final,ensure_ascii=False,indent=2)+'\n')
                (output/'running-report.json').write_text(json.dumps(early,ensure_ascii=False,indent=2)+'\n')
                (output/'preview.png').write_bytes(png)
                summary={'publicPost':202,'earlyScreenshot':200,'pngPixels':list(image.size),'finalStatus':final['status'],
                         'verdict':'unknown','google':'actual Safe Browsing v5' if live else 'explicit no-match TEST DOUBLE',
                         'brand':'actual Phishpedia inference: brand_unidentified' if live else 'runtime not installed',
                         'worker':'actual HTTP jobs and real sandboxed Chromium','networkMode':'none','publishedContainerPorts':False,
                         'output':str(output)}
                (output/'summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n')
                print(json.dumps(summary,ensure_ascii=False,indent=2))
                if live:
                    # Official reputation-test URL is queried through Google only; known positive must skip C.
                    known=await client.post('/api/scans',json={'url':'https://testsafebrowsing.appspot.com/s/phishing.html','mode':'sandbox'})
                    assert known.status_code==202
                    known_id=known.json()['scanId']
                    for _ in range(1000):
                        known_report=(await client.get(f'/api/scans/{known_id}')).json()
                        if known_report['status'] in {'completed','failed'}:break
                        await asyncio.sleep(.02)
                    assert known_report['verdict']['level']=='malicious'
                    assert known_report['sandboxAnalysis']['skipReason']=='known_malicious'
                    assert (await client.get(f'/api/scans/{known_id}/screenshot')).status_code==409
                    (output/'known-threat-report.json').write_text(json.dumps(known_report,ensure_ascii=False,indent=2)+'\n')
                    print(json.dumps({'case':'Google official threat-test reputation only','verdict':'malicious','workerSkipped':True}))
        finally:
            if server:
                server.should_exit=True
            if public:
                await public
            subprocess.run(['docker','stop','-t','2',name],check=True,capture_output=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--live',action='store_true',help='Use real Google and installed Phishpedia; no provider/model test doubles')
    asyncio.run(main(live=parser.parse_args().live))
