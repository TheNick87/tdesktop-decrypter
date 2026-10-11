PRIME1 = 2654435761
PRIME2 = 2246822519
PRIME3 = 3266489917
PRIME4 = 668265263
PRIME5 = 374761393
MASK = 0xFFFFFFFF


def _rotl(x: int, r: int) -> int:
    return ((x << r) | (x >> (32 - r))) & MASK


def _round(acc: int, lane: int) -> int:
    acc = (acc + lane * PRIME2) & MASK
    return (_rotl(acc, 13) * PRIME1) & MASK


def xxh32(data: bytes, seed: int = 0) -> int:
    length = len(data)
    pos = 0

    if length >= 16:
        v1 = (seed + PRIME1 + PRIME2) & MASK
        v2 = (seed + PRIME2) & MASK
        v3 = seed & MASK
        v4 = (seed - PRIME1) & MASK

        lanes = memoryview(data)[: length - length % 16].cast("I")
        for i in range(0, len(lanes), 4):
            v1 = _round(v1, lanes[i])
            v2 = _round(v2, lanes[i + 1])
            v3 = _round(v3, lanes[i + 2])
            v4 = _round(v4, lanes[i + 3])

        pos = len(lanes) * 4
        acc = (_rotl(v1, 1) + _rotl(v2, 7) + _rotl(v3, 12) + _rotl(v4, 18)) & MASK
    else:
        acc = (seed + PRIME5) & MASK

    acc = (acc + length) & MASK

    while pos + 4 <= length:
        lane = int.from_bytes(data[pos : pos + 4], "little")
        acc = (acc + lane * PRIME3) & MASK
        acc = (_rotl(acc, 17) * PRIME4) & MASK
        pos += 4

    while pos < length:
        acc = (acc + data[pos] * PRIME5) & MASK
        acc = (_rotl(acc, 11) * PRIME1) & MASK
        pos += 1

    acc ^= acc >> 15
    acc = (acc * PRIME2) & MASK
    acc ^= acc >> 13
    acc = (acc * PRIME3) & MASK
    acc ^= acc >> 16
    return acc
