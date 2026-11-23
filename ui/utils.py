"""Общие утилиты UI."""
import ipaddress
import re


def is_valid_target(text: str) -> bool:
    # Проверка цели: IP, CIDR, диапазон или hostname.
    text = text.strip()
    if not text:
        return False
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        pass
    try:
        ipaddress.ip_network(text, strict=False)
        return True
    except ValueError:
        pass
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}$", text):
        return True
    hostname_re = re.compile(
        r"^(?!-)[a-zA-Z0-9\-]{1,63}(?:\.[a-zA-Z0-9\-]{1,63})*\.?$"
    )
    if hostname_re.match(text):
        if re.match(r"^\d+$", text):
            return False
        return True
    return False
