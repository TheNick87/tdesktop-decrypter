from typing import Dict, List, Optional, Tuple

from tdesktop_decrypter.cache import CacheKey

# Media::Streaming::Reader constants (media/streaming/media_streaming_reader.cpp).
PART_SIZE = 128 * 1024
PARTS_IN_SLICE = 64
SLICE_SIZE = PART_SIZE * PARTS_IN_SLICE
MAX_PARTS_IN_MAP = 80

# bigFileBaseCacheKey() families: high >> 16.
DOCUMENT_FAMILY = 0x1
PHOTO_FAMILY = 0x2


def base_key(key: CacheKey) -> CacheKey:
    return key[0], key[1] & ~0xFFFF


def chunk_number(key: CacheKey) -> int:
    return key[1] & 0xFFFF


def is_media_document_key(key: CacheKey) -> bool:
    return key[0] >> 16 in (DOCUMENT_FAMILY, PHOTO_FAMILY)


def document_id(key: CacheKey) -> int:
    return ((key[0] & 0xFFFF) << 48) | (key[1] >> 16)


def document_base_key(doc_id: int, family: int = DOCUMENT_FAMILY) -> CacheKey:
    return (family << 16) | (doc_id >> 48), (doc_id << 16) & 0xFFFFFFFFFFFFFFFF


Part = Tuple[int, bytes]


def _parse_parts_map(value: bytes, pos: int) -> Optional[Tuple[List[Part], int]]:
    """
    SerializeComplexPartsMap(): u32 count, then count x {u32 offset, u32 size, bytes}, all LE.
    Returns the parts and the position after them, or None if this is not a valid map.
    """
    if pos + 4 > len(value):
        return None

    count = int.from_bytes(value[pos : pos + 4], "little")
    if not 0 < count <= MAX_PARTS_IN_MAP:
        return None

    pos += 4
    parts = []
    for _ in range(count):
        if pos + 8 > len(value):
            return None

        offset = int.from_bytes(value[pos : pos + 4], "little")
        size = int.from_bytes(value[pos + 4 : pos + 8], "little")
        pos += 8

        if offset % PART_SIZE or not 0 < size <= PART_SIZE or pos + size > len(value):
            return None

        parts.append((offset, value[pos : pos + size]))
        pos += size

    return parts, pos


def parse_chunk(value: bytes) -> Tuple[bool, List[Part]]:
    """
    Splits a media-cache chunk into parts at offsets relative to its slice start.
    Returns (is_raw, parts). Raw chunks are contiguous bytes from the slice start.
    The header chunk (number 0) may hold two maps back to back: header parts and slice 1.
    """
    if len(value) % PART_SIZE:
        parsed = _parse_parts_map(value, 0)
        if parsed is not None:
            parts, pos = parsed

            second = _parse_parts_map(value, pos)
            if second is not None:
                parts += second[0]
                pos = second[1]

            if not value[pos:].strip(b"\0"):
                return False, parts

    return True, [(0, value)]


def chunk_offset(number: int) -> int:
    """
    File offset of a chunk's slice: the header (0) uses absolute offsets, slice n starts at (n-1) * 8 MiB.
    """
    return 0 if number == 0 else (number - 1) * SLICE_SIZE


class Reassembly:
    def __init__(self):
        self.parts: Dict[int, bytes] = {}
        # Total size if it could be determined; otherwise None.
        self.size: Optional[int] = None

    @property
    def end(self) -> int:
        if self.size is not None:
            return self.size

        return max((offset + len(data) for offset, data in self.parts.items()), default=0)

    def covered(self) -> int:
        return sum(length for _, length in self.ranges())

    def ranges(self) -> List[Tuple[int, int]]:
        """
        Covered (offset, length) ranges, merged and clipped to the end.
        """
        merged: List[List[int]] = []
        end = self.end
        for offset in sorted(self.parts):
            stop = min(offset + len(self.parts[offset]), end)
            if offset >= stop:
                continue

            if merged and offset <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], stop)
            else:
                merged.append([offset, stop])

        return [(start, stop - start) for start, stop in merged]

    def gaps(self) -> List[Tuple[int, int]]:
        gaps = []
        position = 0
        for offset, length in self.ranges():
            if offset > position:
                gaps.append((position, offset - position))
            position = offset + length

        if position < self.end:
            gaps.append((position, self.end - position))

        return gaps


def reassemble(chunks: Dict[int, bytes], known_size: Optional[int] = None) -> Reassembly:
    """
    Places the parts of every chunk (by chunk number) at their file offsets.
    The size is the known size if given, otherwise inferred from a final short part.
    """
    result = Reassembly()
    inferred_size = None

    for number, value in sorted(chunks.items()):
        is_raw, parts = parse_chunk(value)
        start = chunk_offset(number)

        for offset, data in parts:
            absolute = start + offset
            if absolute not in result.parts or len(data) > len(result.parts[absolute]):
                result.parts[absolute] = data

            if is_raw:
                short = len(data) % PART_SIZE != 0 and len(data) != SLICE_SIZE
            else:
                short = len(data) < PART_SIZE

            if short:
                inferred_size = absolute + len(data)

    result.size = known_size or inferred_size
    return result
