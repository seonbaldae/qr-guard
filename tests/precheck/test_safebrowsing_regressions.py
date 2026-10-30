"""Cache and failure regressions for the Google v5 adapter; no external traffic."""

import httpx
import pytest

from app.precheck import safebrowsing as sb


def test_cached_provider_cannot_be_mutated_by_another_call():
    calls = []

    def send(url, key):
        calls.append(url)
        return 200, {"threats": [], "cacheDuration": "60s"}

    first = sb.check_safe_browsing("https://cache.example/", api_key="unit-test-key", send=send)
    first.provider.matched = True
    second = sb.check_safe_browsing("https://cache.example/", api_key="unit-test-key", send=send)
    assert second.provider.matched is False
    second.provider.matched = True
    third = sb.check_safe_browsing("https://cache.example/", api_key="unit-test-key", send=send)
    assert third.provider.matched is False
    assert len(calls) == 1


@pytest.mark.parametrize("status", [401, 403, 404, 429, 500, 503])
def test_google_http_failure_is_not_clean(status):
    result = sb.check_safe_browsing(
        "https://example.test/", api_key="unit-test-key", send=lambda _url, _key: (status, {}),
    )
    assert result.provider.status == "failed"
    assert result.provider.matched is None
    assert result.provider.checkedAt is None


@pytest.mark.parametrize("error", [httpx.ReadTimeout("private"), httpx.ConnectError("private")])
def test_google_network_failure_does_not_echo_error(error):
    def send(_url, _key):
        raise error

    result = sb.check_safe_browsing("https://example.test/", api_key="unit-test-key", send=send)
    assert result.provider.status == "failed" and result.provider.matched is None
    assert "private" not in result.provider.model_dump_json()


def test_env_fallback_and_canonical_precedence(monkeypatch, tmp_path):
    # This is a synthetic fixture, never the user's real credential file.
    path = tmp_path / "unit-test.env"
    path.write_text("SAFE_BROWSING_API_KEY=legacy-test-value\n", encoding="utf-8")
    monkeypatch.setattr(sb, "ENV_FILE", path)
    seen = []

    def send(_url, key):
        seen.append(key)
        return 200, {}

    sb.check_safe_browsing("https://example.test/", send=send)
    assert seen == ["legacy-test-value"]
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "canonical-test-value")
    sb.check_safe_browsing("https://example.test/", send=send)
    assert seen[-1] == "canonical-test-value"
