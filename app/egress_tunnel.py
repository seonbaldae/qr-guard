"""Bounded TCP relay for a Chromium proxy in a network=none container.

The container gets no Docker socket or credentials. Every connection target is
untrusted: resolve all addresses, reject special/internal addresses, and connect
to one validated numeric IPv4 address. TLS stays end-to-end inside Chromium.
"""

import asyncio
import base64
import binascii
import ipaddress
import json
import os
import re
import shutil
import socket

MAX_FRAME = 65536
CHUNK = 32768
MAX_CONNECTIONS = 16
MAX_REQUESTS = 100
MAX_CONNECTION_BYTES = 5 * 1024 * 1024
MAX_TOTAL_BYTES = 25 * 1024 * 1024
_ID = re.compile(r"^[1-9][0-9]{0,5}$")
_CONTAINER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_SPECIAL_V4 = {ipaddress.ip_address("168.63.129.16")}
_V6_TRANSITION = tuple(ipaddress.ip_network(item) for item in (
    "64:ff9b::/96", "64:ff9b:1::/48", "2002::/16", "2001::/32",
))


def public_address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    address = ipaddress.ip_address(value)
    if (not address.is_global or address.is_multicast or address.is_reserved
            or address.is_loopback or address.is_link_local or address.is_unspecified
            or address in _SPECIAL_V4):
        raise ValueError("Target address is not allowed")
    if isinstance(address, ipaddress.IPv6Address):
        if (address.ipv4_mapped is not None or address.is_site_local
                or any(address in network for network in _V6_TRANSITION)):
            raise ValueError("Transition addresses are not allowed")
    return address


def target_hostname(value: object) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 253:
        raise ValueError("Invalid target hostname")
    if any(char.isspace() or char in "\\/@%\x00?#" for char in value):
        raise ValueError("Invalid target hostname")
    try:
        address = public_address(value)
    except ValueError:
        # Reject all colon spellings, including zone IDs and IPv6 literals. The
        # first implementation deliberately connects only using IPv4.
        if ":" in value or re.fullmatch(r"[0-9.]+", value):
            raise ValueError("Invalid or disallowed address") from None
    else:
        if not isinstance(address, ipaddress.IPv4Address):
            raise ValueError("IPv6-only connections are unsupported")
        return str(address)
    try:
        host = value.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ValueError("Invalid target hostname") from None
    if len(host) > 253 or "." not in host or not all(_LABEL.fullmatch(label) for label in host.split(".")):
        raise ValueError("Invalid target hostname")
    if host.endswith((".localhost", ".local", ".internal", ".lan", ".home")):
        raise ValueError("Internal hostname is not allowed")
    return host


class PublicEgressTunnel:
    def __init__(self, container_name: str, timeout_seconds: float = 30):
        if not _CONTAINER.fullmatch(container_name):
            raise ValueError("Invalid Worker container name")
        if not 0 < timeout_seconds <= 120:
            raise ValueError("Invalid relay timeout")
        self.container_name = container_name
        self.timeout_seconds = timeout_seconds
        self.blocked_count = 0
        self._process = None
        self._ready = asyncio.Event()
        self._is_ready = False
        self._closed = False
        self._failure = None
        self._write_lock = asyncio.Lock()
        self._tasks: dict[str, asyncio.Task] = {}
        self._writers: dict[str, asyncio.StreamWriter] = {}
        self._used_ids: set[str] = set()
        self._bytes: dict[str, int] = {}
        self._total_bytes = 0
        self._reader_task = None
        self._deadline_task = None

    async def __aenter__(self):
        executable = shutil.which("docker")
        if executable is None:
            raise OSError("Docker is unavailable")
        # Only command discovery and Docker Desktop's config location are
        # inherited. In particular, API keys and proxy variables are absent.
        environment = {"PATH": os.environ.get("PATH", os.defpath), "HOME": os.path.expanduser("~")}
        try:
            self._process = await asyncio.create_subprocess_exec(
                executable, "exec", "-i", self.container_name, "node", "/app/egress-tunnel.cjs",
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL, env=environment, limit=MAX_FRAME + 1,
            )
            self._reader_task = asyncio.create_task(self._read_frames())
            await asyncio.wait_for(self._ready.wait(), timeout=8)
            if not self._is_ready:
                raise OSError("Worker proxy did not start")
            self._deadline_task = asyncio.create_task(self._deadline())
            return self
        except BaseException:
            await self._shutdown()
            raise

    async def __aexit__(self, exc_type, exc, tb):
        await self._shutdown()
        if exc is None and self._failure is not None:
            raise self._failure

    async def _send(self, message: dict):
        if self._closed or self._process is None or self._process.stdin is None:
            raise OSError("Worker proxy is closed")
        encoded = json.dumps(message, separators=(",", ":")).encode("ascii") + b"\n"
        if len(encoded) > MAX_FRAME:
            raise OSError("Relay frame limit exceeded")
        async with self._write_lock:
            self._process.stdin.write(encoded)
            await asyncio.wait_for(self._process.stdin.drain(), timeout=3)

    async def _read_frames(self):
        try:
            while not self._closed:
                line = await self._process.stdout.readline()
                if not line:
                    raise OSError("Worker proxy ended unexpectedly")
                if len(line) > MAX_FRAME or not line.endswith(b"\n"):
                    raise OSError("Relay frame limit exceeded")
                try:
                    message = json.loads(line)
                except (ValueError, UnicodeError):
                    raise OSError("Invalid relay frame") from None
                if not isinstance(message, dict):
                    raise OSError("Invalid relay frame")
                operation = message.get("op")
                if operation == "ready" and not self._is_ready and set(message) == {"op"}:
                    self._is_ready = True
                    self._ready.set()
                    continue
                if not self._is_ready:
                    raise OSError("Unexpected relay startup frame")
                identifier = message.get("id")
                if not isinstance(identifier, str) or not _ID.fullmatch(identifier):
                    raise OSError("Invalid relay identifier")
                if operation == "connect":
                    if set(message) != {"op", "id", "host", "port"}:
                        raise OSError("Invalid relay connection frame")
                    if identifier in self._used_ids:
                        raise OSError("Duplicate relay identifier")
                    if len(self._used_ids) >= MAX_REQUESTS:
                        await self._reject(identifier)
                        raise OSError("Relay connection budget exceeded")
                    self._used_ids.add(identifier)
                    if len(self._tasks) >= MAX_CONNECTIONS:
                        await self._reject(identifier)
                        continue
                    self._bytes[identifier] = 0
                    self._tasks[identifier] = asyncio.create_task(self._connect(identifier, message))
                elif operation == "data":
                    if set(message) != {"op", "id", "data"}:
                        raise OSError("Invalid relay data frame")
                    await self._receive_data(identifier, message.get("data"))
                elif operation == "end" and set(message) == {"op", "id"}:
                    self._close_connection(identifier)
                else:
                    raise OSError("Unknown relay operation")
        except asyncio.CancelledError:
            raise
        except Exception:
            if not self._closed:
                self.blocked_count += 1
                self._failure = OSError("Worker relay protocol failed")
                self._ready.set()
                await self._shutdown()

    async def _resolve(self, host: str, port: int) -> str:
        results = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(
            host, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM,
        ), timeout=4)
        if not results:
            raise ValueError("No target addresses")
        addresses = [public_address(row[4][0]) for row in results]
        for address in addresses:
            if isinstance(address, ipaddress.IPv4Address):
                return str(address)
        raise ValueError("IPv6-only connections are unsupported")

    async def _open(self, address: str, port: int):
        return await asyncio.wait_for(asyncio.open_connection(
            host=address, port=port, family=socket.AF_INET,
        ), timeout=5)

    async def _connect(self, identifier: str, message: dict):
        writer = None
        try:
            port = message.get("port")
            if type(port) is not int or port not in {80, 443}:
                raise ValueError("Target port is not allowed")
            host = target_hostname(message.get("host"))
            address = await self._resolve(host, port)
            reader, writer = await self._open(address, port)
            self._writers[identifier] = writer
            await self._send({"op": "connected", "id": identifier})
            while True:
                data = await reader.read(CHUNK)
                if not data:
                    await self._send({"op": "end", "id": identifier})
                    return
                self._charge(identifier, len(data))
                await self._send({"op": "data", "id": identifier,
                                  "data": base64.b64encode(data).decode("ascii")})
        except asyncio.CancelledError:
            raise
        except Exception:
            if not self._closed:
                await self._reject(identifier)
        finally:
            self._writers.pop(identifier, None)
            self._tasks.pop(identifier, None)
            if writer is not None:
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=1)
                except Exception:
                    pass

    def _charge(self, identifier: str, size: int):
        used = self._bytes.get(identifier, 0) + size
        total = self._total_bytes + size
        if used > MAX_CONNECTION_BYTES or total > MAX_TOTAL_BYTES:
            raise ValueError("Relay byte budget exceeded")
        self._bytes[identifier] = used
        self._total_bytes = total

    async def _receive_data(self, identifier: str, encoded: object):
        if not isinstance(encoded, str) or len(encoded) > ((CHUNK + 2) // 3) * 4:
            raise OSError("Invalid relay data")
        try:
            data = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            raise OSError("Invalid relay data") from None
        if len(data) > CHUNK:
            raise OSError("Relay frame limit exceeded")
        writer = self._writers.get(identifier)
        if writer is None:
            # A late frame can race with remote closure; it must never reopen a
            # connection or select a different destination.
            return
        try:
            self._charge(identifier, len(data))
            writer.write(data)
            await asyncio.wait_for(writer.drain(), timeout=3)
        except Exception:
            await self._reject(identifier)
            self._close_connection(identifier)

    async def _reject(self, identifier: str):
        self.blocked_count += 1
        if not self._closed:
            await self._send({"op": "error", "id": identifier})

    def _close_connection(self, identifier: str):
        writer = self._writers.get(identifier)
        if writer is not None:
            writer.close()
        task = self._tasks.get(identifier)
        if task is not None and task is not asyncio.current_task():
            task.cancel()

    async def _deadline(self):
        await asyncio.sleep(self.timeout_seconds)
        if not self._closed:
            self.blocked_count += 1
            self._failure = TimeoutError("Worker relay time limit exceeded")
            await self._shutdown()

    async def _shutdown(self):
        if self._closed:
            return
        self._closed = True
        current = asyncio.current_task()
        tasks = [task for task in [self._reader_task, self._deadline_task, *self._tasks.values()]
                 if task is not None and task is not current]
        for task in tasks:
            task.cancel()
        for writer in self._writers.values():
            writer.close()
        process = self._process
        if process is not None:
            if process.stdin is not None:
                # EOF is handled inside the container, so killing the Docker
                # CLI does not leave an orphaned proxy listening on port 3128.
                try:
                    process.stdin.write(b'{"op":"shutdown"}\n')
                    await asyncio.wait_for(process.stdin.drain(), timeout=1)
                except Exception:
                    pass
                process.stdin.close()
            try:
                await asyncio.wait_for(process.wait(), timeout=3)
            except TimeoutError:
                process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), timeout=2)
                except TimeoutError:
                    process.kill()
                    await process.wait()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._tasks.clear()
        self._writers.clear()
