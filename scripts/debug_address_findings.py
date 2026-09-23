from app.config import load_config
from app.process import ProcessService
from app.state import MemoryStateStore

CASES = [
    "Мой адрес: Москва, ул. Лесная, д. 10, кв. 5.",
    "Адрес проживания клиента: Казань, ул. Баумана, д. 7.",
    "Я живу в Самаре на улице Ленина 5.",
    "Адрес регистрации: 190000, Санкт-Петербург, Невский проспект, д. 20.",
    "Доставьте карту по адресу: Екатеринбург, ул. Малышева, д. 15, кв. 8.",
    "Клиентка Мария Соколова родилась 7 января 1992 года, адрес проживания: Казань, ул. Баумана, д. 7.",
]

cfg = load_config("config.yaml")
svc = ProcessService(cfg, MemoryStateStore())
for text in CASES:
    print("TEXT", text)
    for f in svc.detect(text, "autotest"):
        if f.type in {"ADDRESS", "REDACTED_SPAN", "PERSON", "BIRTH_DATE"}:
            print(" FINDING", f.type, getattr(f, "part", ""), f.start, f.end, repr(text[f.start:f.end]), f.detector)
