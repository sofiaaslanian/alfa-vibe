from app.config import load_config
from app.process import ProcessService
from app.state import MemoryStateStore


def test_autotest_adds_snils_extension_only():
    cfg = load_config("config.yaml")
    svc = ProcessService(cfg, MemoryStateStore())

    snils = svc.detect("СНИЛС клиента: 112-233-445 95", system="autotest")
    assert any(f.type == "SNILS" for f in snils)

    oms = svc.detect("Полис ОМС 1234567890123456", system="autotest")
    assert not any(f.type == "OMS" for f in oms)

    zagran = svc.detect("Загранпаспорт: 75 1234567", system="autotest")
    assert not any(f.type == "INTERNATIONAL_PASSPORT" for f in zagran)


def test_non_autotest_profiles_do_not_gain_snils_extension():
    cfg = load_config("config.yaml")
    svc = ProcessService(cfg, MemoryStateStore())

    out = svc.detect("СНИЛС клиента: 112-233-445 95", system="high_rps")
    assert not any(f.type == "SNILS" for f in out)
