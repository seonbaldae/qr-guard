"""Relay policy and lifecycle tests. DNS and external sockets are test doubles."""

import asyncio
import base64
import json
import socket
from pathlib import Path
import shutil

import pytest

from app.egress_tunnel import (
    MAX_CONNECTION_BYTES, MAX_FRAME, MAX_TOTAL_BYTES, PublicEgressTunnel,
    public_address, target_hostname,
)


@pytest.mark.parametrize("address", [
    "127.0.0.1", "0.0.0.0", "10.0.0.1", "172.16.0.1", "192.168.1.1",
    "169.254.169.254", "168.63.129.16", "100.100.100.200", "224.0.0.1",
    "::1", "fc00::1", "fe80::1", "::ffff:127.0.0.1", "64:ff9b::7f00:1", "2002:7f00:1::",
])
def test_special_addresses_fail_closed(address):
    with pytest.raises(ValueError):
        public_address(address)


@pytest.mark.parametrize("host", [
    "localhost", "service.internal", "router.local", "127.1", "2130706433",
    "0x7f000001", "user@example.com", "example.com/path", "example.com%00", "::1",
])
def test_ambiguous_or_internal_hostnames_fail_closed(host):
    with pytest.raises(ValueError):
        target_hostname(host)


def test_every_dns_answer_is_checked_before_connecting(monkeypatch):
    async def scenario():
        async def resolve(*args, **kwargs):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
                (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 443, 0, 0)),
            ]
        monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", resolve)
        with pytest.raises(ValueError):
            await PublicEgressTunnel("worker")._resolve("example.com", 443)
    asyncio.run(scenario())


class Writer:
    def __init__(self):
        self.data = []
        self.closed = False

    def write(self, data):
        self.data.append(data)

    async def drain(self):
        pass

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


def test_connection_is_pinned_to_validated_ip_and_bytes_are_relayed(monkeypatch):
    async def scenario():
        async def resolve(*args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", resolve)
        relay = PublicEgressTunnel("worker")
        messages = []
        opened = []
        writer = Writer()
        reader = asyncio.StreamReader()
        reader.feed_data(b"encrypted-response")
        reader.feed_eof()

        async def send(message):
            messages.append(message)

        async def connect(address, port):
            opened.append((address, port))
            return reader, writer

        relay._send = send
        relay._open = connect
        await relay._connect("1", {"host": "example.com", "port": 443})
        assert opened == [("93.184.216.34", 443)]
        assert messages == [
            {"op": "connected", "id": "1"},
            {"op": "data", "id": "1", "data": base64.b64encode(b"encrypted-response").decode()},
            {"op": "end", "id": "1"},
        ]
        assert relay.blocked_count == 0 and writer.closed
    asyncio.run(scenario())


@pytest.mark.parametrize("target", [
    {"host": "127.0.0.1", "port": 443}, {"host": "example.com", "port": 22},
    {"host": "example.com", "port": True}, {"host": "168.63.129.16", "port": 80},
])
def test_blocked_connections_never_open_a_socket(target):
    async def scenario():
        relay = PublicEgressTunnel("worker")
        messages = []

        async def send(message):
            messages.append(message)

        async def forbidden(*args):
            raise AssertionError("Socket must not open")

        relay._send = send
        relay._open = forbidden
        await relay._connect("1", target)
        assert relay.blocked_count == 1
        assert messages == [{"op": "error", "id": "1"}]
    asyncio.run(scenario())


def test_byte_budgets_are_shared_across_both_directions():
    relay = PublicEgressTunnel("worker")
    relay._charge("1", MAX_CONNECTION_BYTES)
    with pytest.raises(ValueError):
        relay._charge("1", 1)
    relay._total_bytes = MAX_TOTAL_BYTES
    with pytest.raises(ValueError):
        relay._charge("2", 1)


def test_data_frames_validate_encoding_and_close_connections_at_budget():
    async def scenario():
        relay = PublicEgressTunnel("worker")
        messages = []
        writer = Writer()
        relay._writers["1"] = writer

        async def send(message):
            messages.append(message)

        relay._send = send
        with pytest.raises(OSError):
            await relay._receive_data("1", "invalid?")
        with pytest.raises(OSError):
            await relay._receive_data("1", "A" * MAX_FRAME)
        relay._bytes["1"] = MAX_CONNECTION_BYTES
        await relay._receive_data("1", base64.b64encode(b"x").decode())
        assert writer.closed and not writer.data
        assert messages == [{"op": "error", "id": "1"}]
        assert relay.blocked_count == 1
    asyncio.run(scenario())


class Process:
    def __init__(self):
        self.stdin = Writer()
        self.stdout = asyncio.StreamReader()
        self.stdout.feed_data(b'{"op":"ready"}\n')
        self.waited = False

    async def wait(self):
        self.waited = True
        return 0


def test_context_starts_fixed_command_without_server_secrets_and_closes_everything(monkeypatch):
    async def scenario():
        process = Process()
        commands = []

        async def start(*args, **kwargs):
            commands.append((args, kwargs))
            return process

        monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "test-key-must-not-leave-host")
        monkeypatch.setattr("app.egress_tunnel.shutil.which", lambda _: "/usr/bin/docker")
        monkeypatch.setattr(asyncio, "create_subprocess_exec", start)
        async with PublicEgressTunnel("test-worker") as relay:
            assert relay.blocked_count == 0
            writer = Writer()
            relay._writers["1"] = writer
        assert commands[0][0] == (
            "/usr/bin/docker", "exec", "-i", "test-worker", "node", "/app/egress-tunnel.cjs",
        )
        assert set(commands[0][1]["env"]) == {"PATH", "HOME"}
        assert "test-key-must-not-leave-host" not in str(commands)
        assert process.stdin.closed and process.waited and writer.closed
        assert json.loads(process.stdin.data[-1]) == {"op": "shutdown"}
        assert not relay._tasks and not relay._writers
    asyncio.run(scenario())


def test_bad_protocol_frame_fails_closed_and_cleans_up(monkeypatch):
    async def scenario():
        process = Process()
        process.stdout.feed_data(b'{"op":"connect","id":"../bad"}\n')
        relay = PublicEgressTunnel("worker")
        relay._process = process
        await relay._read_frames()
        assert relay._closed and relay.blocked_count == 1
        assert isinstance(relay._failure, OSError)
        assert process.stdin.closed and process.waited
    asyncio.run(scenario())


def test_deadline_stops_proxy_and_surfaces_timeout(monkeypatch):
    async def scenario():
        process = Process()

        async def start(*args, **kwargs):
            return process

        monkeypatch.setattr("app.egress_tunnel.shutil.which", lambda _: "/usr/bin/docker")
        monkeypatch.setattr(asyncio, "create_subprocess_exec", start)
        with pytest.raises(TimeoutError):
            async with PublicEgressTunnel("worker", timeout_seconds=0.01) as relay:
                await asyncio.sleep(0.03)
        assert relay._closed and relay.blocked_count == 1
        assert process.stdin.closed and process.waited
    asyncio.run(scenario())


@pytest.mark.skipif(shutil.which("node") is None, reason="Node is required for proxy handshake verification")
@pytest.mark.parametrize("connect", [True, False])
def test_node_proxy_handshake_and_shutdown_without_external_sockets(connect):
    async def scenario():
        script = Path(__file__).resolve().parents[2] / "worker" / "egress-tunnel.cjs"
        process = await asyncio.create_subprocess_exec(
            shutil.which("node"), str(script), stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        client = None

        async def message():
            return json.loads(await asyncio.wait_for(process.stdout.readline(), timeout=2))

        async def send(value):
            process.stdin.write(json.dumps(value).encode() + b"\n")
            await process.stdin.drain()

        try:
            assert await message() == {"op": "ready"}
            reader, client = await asyncio.open_connection("127.0.0.1", 3128)
            request = (b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
                       if connect else b"GET http://example.com/page?q=one HTTP/1.1\r\nHost: bad.invalid\r\nProxy-Authorization: secret-proxy-value\r\n\r\n")
            client.write(request)
            await client.drain()
            opened = await message()
            assert opened == {"op": "connect", "id": "1", "host": "example.com", "port": 443 if connect else 80}
            await send({"op": "connected", "id": "1"})
            if connect:
                assert await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2) == b"HTTP/1.1 200 Connection Established\r\n\r\n"
                client.write(b"client-tunnel-bytes")
                await client.drain()
                outbound = await message()
                assert base64.b64decode(outbound["data"]) == b"client-tunnel-bytes"
            else:
                outbound = await message()
                forwarded = base64.b64decode(outbound["data"])
                assert forwarded.startswith(b"GET /page?q=one HTTP/1.1\r\nHost: example.com\r\n")
                assert b"secret-proxy-value" not in forwarded
                assert b"bad.invalid" not in forwarded
                assert b"Connection: close" in forwarded
            await send({"op": "data", "id": "1", "data": base64.b64encode(b"relay-response").decode()})
            assert await asyncio.wait_for(reader.readexactly(14), 2) == b"relay-response"
            await send({"op": "shutdown"})
            assert await asyncio.wait_for(process.wait(), 2) == 0
            assert await asyncio.wait_for(reader.read(), 2) == b""
        finally:
            if client is not None:
                client.close()
                await client.wait_closed()
            if process.returncode is None:
                process.stdin.close()
                try:
                    await asyncio.wait_for(process.wait(), 2)
                except TimeoutError:
                    process.kill()
                    await process.wait()
    asyncio.run(scenario())
