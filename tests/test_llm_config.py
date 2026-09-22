from app.llm import AlfaGenClient, DEFAULT_BASE_URL, DEFAULT_MODEL


def test_llm_defaults(monkeypatch):
    monkeypatch.delenv("ALFAGEN_API_KEY", raising=False)
    monkeypatch.delenv("ALFAGEN_BASE_URL", raising=False)
    monkeypatch.delenv("ALFAGEN_MODEL", raising=False)

    client = AlfaGenClient()

    assert client.api_key == ""
    assert client.base_url == DEFAULT_BASE_URL.rstrip("/")
    assert client.model == DEFAULT_MODEL


def test_llm_reads_environment(monkeypatch):
    monkeypatch.setenv("ALFAGEN_API_KEY", "test-key")
    monkeypatch.setenv("ALFAGEN_BASE_URL", "https://example.test/v1/")
    monkeypatch.setenv("ALFAGEN_MODEL", "test-model")

    client = AlfaGenClient()

    assert client.api_key == "test-key"
    assert client.base_url == "https://example.test/v1"
    assert client.model == "test-model"


def test_explicit_values_override_environment(monkeypatch):
    monkeypatch.setenv("ALFAGEN_API_KEY", "env-key")
    monkeypatch.setenv("ALFAGEN_BASE_URL", "https://env.example/v1")
    monkeypatch.setenv("ALFAGEN_MODEL", "env-model")

    client = AlfaGenClient(
        api_key="explicit-key",
        base_url="https://explicit.example/v1/",
        model="explicit-model",
    )

    assert client.api_key == "explicit-key"
    assert client.base_url == "https://explicit.example/v1"
    assert client.model == "explicit-model"
