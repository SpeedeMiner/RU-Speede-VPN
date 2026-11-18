import pytest

from scripts.prepare_v2ray_geoip import MAPPED_IPV4, bytes_field, encode_varint, make_compatible


def cidr(address, bits):
    return bytes_field(2, bytes_field(1, address) + b"\x10" + encode_varint(bits))


def test_removes_only_exact_private_cidr_and_keeps_ru_unchanged():
    private = bytes_field(1, b"PRIVATE") + cidr(b"\x7f\0\0\0", 8)
    explicit_unknown_field = b"\x18\x01"
    ru = bytes_field(1, bytes_field(1, b"RU") + cidr(b"\x5f\0\0\0", 8))
    mapped = cidr(MAPPED_IPV4, 96)
    initial = bytes_field(1, private + mapped + explicit_unknown_field) + ru
    expected = bytes_field(1, private + explicit_unknown_field) + ru
    assert make_compatible(initial) == (expected, 1)
    assert make_compatible(expected) == (expected, 0)


def test_rejects_missing_groups_or_truncated_fields():
    with pytest.raises(ValueError, match="PRIVATE and RU"):
        make_compatible(bytes_field(1, bytes_field(1, b"PRIVATE")))
    with pytest.raises(ValueError, match="Truncated"):
        make_compatible(b"\x0a\x09A")
