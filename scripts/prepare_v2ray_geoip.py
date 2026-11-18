"""Create a V2Ray-compatible copy of the project's GeoIP DAT."""
import argparse
from pathlib import Path

# V2Ray unmapped this IPv6 network to IPv4 before validating /96.
MAPPED_IPV4 = b"\x00" * 10 + b"\xff\xff" + b"\x00" * 4


def varint(data, offset):
    value = 0
    for shift in range(0, 70, 7):
        if offset >= len(data):
            raise ValueError("Truncated protobuf varint")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7f) << shift
        if byte < 0x80:
            return value, offset
    raise ValueError("Oversized protobuf varint")


def encode_varint(value):
    result = bytearray()
    while value > 0x7f:
        result.append((value & 0x7f) | 0x80)
        value >>= 7
    result.append(value)
    return bytes(result)


def bytes_field(number, data):
    return encode_varint((number << 3) | 2) + encode_varint(len(data)) + data


def fields(data):
    offset = 0
    while offset < len(data):
        start = offset
        tag, offset = varint(data, offset)
        number, kind = divmod(tag, 8)
        if not number:
            raise ValueError("Invalid protobuf field number")
        if kind == 0:
            value, offset = varint(data, offset)
        elif kind == 2:
            length, offset = varint(data, offset)
            value = data[offset:offset + length]
            offset += length
        elif kind in (1, 5):
            length = 8 if kind == 1 else 4
            value = data[offset:offset + length]
            offset += length
        else:
            raise ValueError(f"Unsupported protobuf wire type {kind}")
        if offset > len(data):
            raise ValueError("Truncated protobuf field")
        yield number, value, data[start:offset]


def make_compatible(data):
    output = []
    removed = 0
    groups = set()
    for number, group, raw in fields(data):
        if number != 1 or not isinstance(group, bytes):
            output.append(raw)
            continue
        entries = list(fields(group))
        name = next((value for key, value, _ in entries if key == 1), b"")
        groups.add(name)
        if name != b"PRIVATE":
            output.append(raw)
            continue
        keep = []
        for key, value, field in entries:
            if key == 2:
                cidr = {n: value for n, value, _ in fields(value)}
                if cidr.get(1) == MAPPED_IPV4 and cidr.get(2) == 96:
                    removed += 1
                    continue
            keep.append(field)
        output.append(bytes_field(1, b"".join(keep)))
    if not {b"PRIVATE", b"RU"} <= groups:
        raise ValueError("Input GeoIP DAT must contain PRIVATE and RU")
    return b"".join(output), removed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.input.resolve() == args.output.resolve():
        parser.error("Use a separate output path to preserve the original file")
    try:
        result, removed = make_compatible(args.input.read_bytes())
        args.output.write_bytes(result)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"{exc}\n")
    print(f"{args.output}: removed {removed} incompatible PRIVATE CIDR(s)")


if __name__ == "__main__":
    main()
