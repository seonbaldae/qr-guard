"""Optional offline Phishpedia connector. Unavailable runtime is explicitly unknown."""
import asyncio
import json
import os
from pathlib import Path
import re
import tempfile
from uuid import uuid4

from app.config import Settings


class BrandClient:
    def __init__(self, settings: Settings):
        self.settings = settings

    def command(self, name: str, directory: Path, image_id: str) -> list[str]:
        root = Path(self.settings.brand_worker_directory).resolve()
        mounts = [(root/'analyze-brand.py','/opt/phishpedia/analyze-brand.py'),
                  (root/'run-phishpedia.py','/opt/phishpedia/run-phishpedia.py'),
                  (root/'.cache/LOGO_FEATS.npy','/opt/phishpedia/LOGO_FEATS.npy'),
                  (root/'.cache/LOGO_FILES.npy','/opt/phishpedia/LOGO_FILES.npy'),
                  (Path(__file__).with_name('brand_runner.py'),'/opt/phishpedia/qr-brand-runner.py'),
                  (directory,'/input/job')]
        args = ['docker','run','--rm','--name',name,'--network','none','--read-only',
                '--user',f'{os.getuid()}:{os.getgid()}', '--env','HOME=/tmp','--env','XDG_CACHE_HOME=/tmp/.cache',
                '--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','256',
                '--memory','4g','--cpus','2','--tmpfs','/tmp:rw,nosuid,nodev,size=512m','--init',
                '--workdir','/opt/phishpedia','--env','PYTHONDONTWRITEBYTECODE=1']
        for source, target in mounts:
            args += ['--mount',f'type=bind,source={source},target={target},readonly']
        args += [image_id,'/opt/phishpedia/.pixi/envs/default/bin/python','-u','qr-brand-runner.py','--input','/input/job']
        return args

    async def analyze(self, scan_id: str, final_url: str, png: bytes) -> dict | None:
        if not self.settings.brand_worker_directory or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', scan_id):
            return None
        root = Path(self.settings.brand_worker_directory).resolve()
        required = ['analyze-brand.py','run-phishpedia.py','.cache/LOGO_FEATS.npy','.cache/LOGO_FILES.npy']
        if not all((root / name).is_file() for name in required):
            return None
        process = None
        name = 'qr-guard-brand-' + uuid4().hex
        async def bounded(args, limit=256*1024):
            nonlocal process
            process = await asyncio.create_subprocess_exec(*args,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.DEVNULL)
            data = bytearray()
            while True:
                chunk = await process.stdout.read(8192)
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > limit:
                    raise ValueError('brand_output_limit')
            await process.wait()
            if process.returncode != 0:
                raise ValueError('brand_execution_failed')
            return bytes(data)
        try:
            async with asyncio.timeout(self.settings.brand_timeout_ms / 1000):
                image = json.loads(await bounded(['docker','image','inspect',self.settings.brand_image,'--format','{{json .Id}}']))
                if not re.fullmatch(r'sha256:[a-f0-9]{64}', image):
                    return None
                runtime = Path(__file__).resolve().parents[3] / '.backend-runtime'
                runtime.mkdir(parents=True, exist_ok=True)
                with tempfile.TemporaryDirectory(prefix='brand-', dir=runtime) as temporary:
                    directory = Path(temporary)
                    (directory/'shot.png').write_bytes(png)
                    (directory/'info.txt').write_text(final_url)
                    raw = await bounded(self.command(name,directory,image))
                    lines = [line[len(b'QR_BRAND_RESULT '):] for line in raw.splitlines() if line.startswith(b'QR_BRAND_RESULT ')]
                    if len(lines) != 1:
                        return None
                    result = json.loads(lines[0])
                    # Wrapper reads private directory /tmp/qr-brand/job, but the transport's scan ID is authoritative.
                    if result.get('scanId') != 'job' or result.get('finalUrl') != final_url:
                        return None
                    result['scanId'] = scan_id
                    return result
        except (OSError, ValueError, TimeoutError):
            return None
        finally:
            if process and process.returncode is None:
                process.kill()
                await process.wait()
                # Stop only this owned --rm container; never shared model services.
                try:
                    stop = await asyncio.create_subprocess_exec('docker','stop','-t','1',name,
                        stdout=asyncio.subprocess.DEVNULL,stderr=asyncio.subprocess.DEVNULL)
                    async with asyncio.timeout(5):
                        await stop.wait()
                except (OSError, TimeoutError):
                    pass
