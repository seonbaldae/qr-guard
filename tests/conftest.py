import pytest


@pytest.fixture(autouse=True)
def _no_real_api_key(monkeypatch):
    """개발자 PC에 키가 설정돼 있어도 테스트가 실제 Google API를 부르지 않게 한다."""
    monkeypatch.delenv("SAFE_BROWSING_API_KEY", raising=False)
