"""Быстрая smoke-проверка основных чистых функций."""
from core.scanner import parse_target_range, is_target_fully_local
from ui.utils import is_valid_target


def main():
    assert is_valid_target("192.168.1.1")
    assert is_valid_target("10.0.0.0/24")
    assert is_valid_target("192.168.1.1-10")
    assert is_valid_target("example.local")
    assert not is_valid_target("")
    assert not is_valid_target("bad host!!")

    assert parse_target_range("192.168.1.1-3") == ["192.168.1.1", "192.168.1.2", "192.168.1.3"]
    assert len(parse_target_range("192.168.1.0/30")) == 2
    assert parse_target_range("bad") == []

    print("smoke: ok")


if __name__ == "__main__":
    main()
