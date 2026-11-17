"""Explainable, offline URL risk heuristics. No URL is ever opened here."""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from urllib.parse import parse_qsl, unquote, urlsplit

MAX_URL_LENGTH = 2048
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", "tiny.cc"}
LURE_WORDS = {"login", "signin", "verify", "verification", "account", "password", "wallet", "payment", "security", "confirm", "update"}
REDIRECT_KEYS = {"redirect", "redirect_url", "return", "return_url", "next", "continue", "url", "target", "dest", "destination"}
DOWNLOAD_EXTENSIONS = (".exe", ".scr", ".bat", ".cmd", ".ps1", ".apk", ".msi")


class InvalidURL(ValueError):
    pass


def _script_groups(hostname: str) -> set[str]:
    groups = set()
    for char in hostname:
        if not char.isalpha():
            continue
        name = unicodedata.name(char, "")
        for script in ("LATIN", "CYRILLIC", "GREEK"):
            if script in name:
                groups.add(script)
    return groups


def analyze_url(raw: str) -> dict:
    if not isinstance(raw, str):
        raise InvalidURL("Введите URL-адрес текстом.")
    value = raw.strip()
    if not value:
        raise InvalidURL("Введите URL-адрес для проверки.")
    if len(value) > MAX_URL_LENGTH:
        raise InvalidURL("Адрес слишком длинный: максимум 2048 символов.")
    if re.search(r"\s|[\x00-\x1f\x7f]", value):
        raise InvalidURL("В адресе не должно быть пробелов или переносов строк.")

    if "://" not in value:
        bare_host_with_port = re.match(r"^[a-z0-9.-]+:\d+(?:/|$)", value, re.I)
        if bare_host_with_port or not re.match(r"^[a-z][a-z0-9+.-]*:", value, re.I):
            value = "https://" + value
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        port = parsed.port  # validates malformed ports
    except ValueError as exc:
        raise InvalidURL("Не удалось разобрать адрес. Проверьте домен и порт.") from exc

    if parsed.scheme.lower() not in {"http", "https"}:
        raise InvalidURL("Можно проверять только ссылки http:// и https://.")
    if not host or host.startswith(".") or host.endswith(".") or ".." in host:
        raise InvalidURL("Укажите корректный домен или IP-адрес.")
    try:
        ascii_host = host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise InvalidURL("Домен содержит недопустимые символы.") from exc
    if len(ascii_host) > 253 or any(len(label) > 63 for label in ascii_host.split(".")):
        raise InvalidURL("Домен слишком длинный.")

    indicators = []

    def add(code: str, points: int, title: str, detail: str):
        indicators.append({"code": code, "points": points, "title": title, "detail": detail})

    if parsed.scheme.lower() == "http":
        add("http", 12, "Нет защищённого соединения", "Адрес начинается с http://. Сам по себе HTTPS тоже не доказывает безопасность сайта.")

    if "@" in parsed.netloc:
        add("userinfo", 42, "Символ @ в адресе", "Текст до @ может отвлекать от настоящего домена, который указан после него.")

    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    if not is_ip and "." not in ascii_host and ascii_host != "localhost":
        raise InvalidURL("Укажите полный домен, например example.com.")
    if is_ip:
        add("ip_host", 24, "Вместо домена указан IP-адрес", "Для обычной веб-страницы это необычно, но не является доказательством угрозы.")

    if "xn--" in ascii_host or any(ord(ch) > 127 for ch in host):
        add("idn", 10, "Домен с международными символами", "Визуально похожие символы разных алфавитов могут запутать пользователя.")
    if len(_script_groups(host)) > 1:
        add("mixed_script", 22, "Смешаны разные алфавиты", "В домене встречаются буквы разных систем письма, например латиницы и кириллицы.")

    if not is_ip:
        labels = ascii_host.split(".")
        if len(labels) >= 5:
            add("subdomains", 16, "Много уровней домена", "У адреса четыре или больше уровней; его начало может выглядеть убедительнее настоящего домена.")
        if any(label.count("-") >= 3 for label in labels):
            add("hyphens", 12, "Много дефисов в домене", "Это слабый признак маскировки; у обычных сайтов он тоже встречается.")

    if len(value) >= 180:
        add("very_long", 19, "Очень длинный адрес", "В длинной строке сложнее заметить настоящий домен и параметры.")
    elif len(value) >= 100:
        add("long", 10, "Длинный адрес", "Большая длина требует внимательнее проверить домен.")

    if ascii_host in SHORTENERS:
        add("shortener", 18, "Ссылка сокращена", "Конечный адрес скрыт. Сервис не переходит по ссылке и не раскрывает её назначение.")

    decoded_path = unquote(parsed.path).lower()
    host_path_words = set(re.findall(r"[a-z]+", ascii_host + " " + decoded_path))
    found_lures = sorted(host_path_words & LURE_WORDS)
    if len(found_lures) >= 2:
        add("lure_words", 18, "Несколько слов, связанных со входом или оплатой", "Такие слова часто встречаются и на обычных сайтах; здесь это лишь дополнительный сигнал.")
    elif found_lures:
        add("lure_word", 8, "Слово, связанное с учётной записью", "Само по себе это слово не означает, что ссылка опасна.")

    if decoded_path.endswith(DOWNLOAD_EXTENSIONS):
        add("download", 20, "Ссылка похожа на загрузку программы", "Перед запуском файла особенно важно проверить источник.")

    if port is not None and port not in {80, 443}:
        add("port", 10, "Нестандартный порт", "Адрес явно указывает порт, который реже используется обычными сайтами.")

    for key, param_value in parse_qsl(parsed.query, keep_blank_values=True):
        if key.lower() in REDIRECT_KEYS and re.match(r"https?://", unquote(param_value), re.I):
            add("redirect", 20, "Есть переход на другой сайт", "Параметр URL содержит ещё один адрес. Итоговый сайт может отличаться от видимого.")
            break

    score = min(100, sum(item["points"] for item in indicators))
    if score >= 55:
        level, label, summary = "high", "Высокий риск", "Не открывайте, пока не подтвердите источник."
    elif score >= 25:
        level, label, summary = "caution", "Нужна осторожность", "Проверьте источник перед переходом."
    else:
        level, label, summary = "low", "Явных признаков мало", "Серьёзных сигналов не найдено."

    return {
        "input": raw.strip(),
        "normalized_url": value,
        "host": host,
        "score": score,
        "level": level,
        "label": label,
        "summary": summary,
        "indicators": sorted(indicators, key=lambda item: item["points"], reverse=True),
        "method": "Эвристический анализ текста URL без открытия сайта",
        "checked_online": False,
    }
