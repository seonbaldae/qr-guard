import pytest


@pytest.fixture(autouse=True)
def _no_real_api_key(monkeypatch, tmp_path):
    """PC의 환경변수나 저장소의 .env에 키가 있어도 테스트가 실제 Google API를 부르지 않게 한다."""
    monkeypatch.delenv("SAFE_BROWSING_API_KEY", raising=False)
    monkeypatch.setattr("app.precheck.safebrowsing.ENV_FILE", tmp_path / "no-such.env")
