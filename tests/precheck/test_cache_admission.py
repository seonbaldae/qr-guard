"""Bounded admission must not evict Google results before their TTL expires."""

from concurrent.futures import ThreadPoolExecutor
import threading

from app.precheck import safebrowsing as sb


def test_cache_capacity_preserves_unexpired_entries(monkeypatch):
    monkeypatch.setattr(sb, "_CACHE_CAPACITY", 2)
    clock = [100.0]
    monkeypatch.setattr(sb.time, "monotonic", lambda: clock[0])
    calls = []

    def send(url, _key):
        calls.append(url)
        return 200, {"threats": [], "cacheDuration": "60s"}

    def check(name):
        return sb.check_safe_browsing(f"https://{name}.example/", api_key="unit-test-key", send=send)

    assert check("one").provider.status == "checked"
    assert check("two").provider.status == "checked"
    assert check("three").provider.status == "failed"
    assert check("one").provider.status == "checked"
    assert len(calls) == 2
    clock[0] = 160.0
    assert check("three").provider.status == "checked"
    assert len(calls) == 3


def test_inflight_reservations_count_toward_cache_capacity(monkeypatch):
    monkeypatch.setattr(sb, "_CACHE_CAPACITY", 1)
    entered, release = threading.Event(), threading.Event()
    calls = []

    def send(url, _key):
        calls.append(url)
        if url == "https://one.example/":
            entered.set()
            assert release.wait(3)
        return 200, {"threats": [], "cacheDuration": "60s"}

    def check(url):
        return sb.check_safe_browsing(url, api_key="unit-test-key", send=send)

    with ThreadPoolExecutor(max_workers=1) as executor:
        first = executor.submit(check, "https://one.example/")
        try:
            assert entered.wait(3)
            assert check("https://two.example/").provider.status == "failed"
            assert len(calls) == 1
        finally:
            release.set()
        assert first.result(timeout=3).provider.status == "checked"
    assert check("https://one.example/").provider.status == "checked"
    assert len(calls) == 1
