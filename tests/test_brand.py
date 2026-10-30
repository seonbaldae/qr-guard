import asyncio
from pathlib import Path
import importlib.util
import os
from app.config import Settings


def test_missing_brand_runtime_is_explicit_and_does_not_run_docker(tmp_path):
    assert importlib.util.find_spec('app.brand') is not None, 'brand connector missing'
    from app.brand import BrandClient
    async def run():
        assert await BrandClient(Settings()).analyze('job','https://demo.example.test/',b'png') is None
        assert await BrandClient(Settings(brand_worker_directory=str(tmp_path))).analyze('job','https://demo.example.test/',b'png') is None
    asyncio.run(run())


def test_brand_container_command_preserves_readonly_sources_and_no_network(tmp_path):
    from app.brand import BrandClient
    client=BrandClient(Settings(brand_worker_directory=str(tmp_path)))
    args=client.command('owned-job',tmp_path,'sha256:'+'a'*64)
    assert args[:2]==['docker','run']
    assert args[args.index('--network')+1]=='none'
    assert '--read-only' in args and '--cap-drop' in args
    assert not any('/var/run/docker.sock' in a for a in args)
    assert all('readonly' in args[i+1] for i,a in enumerate(args) if a=='--mount')
    assert args[-2:] == ['--input','/input/job']
    assert args[args.index('--user')+1] == f'{os.getuid()}:{os.getgid()}'
    assert '/opt/phishpedia/.pixi/envs/default/bin/python' in args
    assert 'pixi' not in args
