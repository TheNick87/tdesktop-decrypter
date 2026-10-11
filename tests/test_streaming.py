import unittest

from tdesktop_decrypter.streaming import (
    PART_SIZE,
    SLICE_SIZE,
    document_base_key,
    document_id,
    parse_chunk,
    reassemble,
)

from tests.fixtures import parts_map


def part(index: int, size: int = PART_SIZE) -> bytes:
    return bytes([index % 251 + 1]) * size


class KeysTest(unittest.TestCase):
    def test_document_id_round_trip(self):
        doc_id = 5834455249024196761
        self.assertEqual(document_id(document_base_key(doc_id)), doc_id)


class ParseChunkTest(unittest.TestCase):
    def test_raw_prefix(self):
        value = part(0) + part(1)
        self.assertEqual(parse_chunk(value), (True, [(0, value)]))

    def test_complex_map_with_padding(self):
        value = parts_map([(0, part(0)), (3 * PART_SIZE, part(3, 100))])
        value += b"\0"
        is_raw, parts = parse_chunk(value)
        self.assertFalse(is_raw)
        self.assertEqual(parts, [(0, part(0)), (3 * PART_SIZE, part(3, 100))])

    def test_good_header_holds_two_maps(self):
        value = parts_map([(9 * SLICE_SIZE, part(9))]) + parts_map([(0, part(0))]) + b"\0"
        is_raw, parts = parse_chunk(value)
        self.assertFalse(is_raw)
        self.assertEqual([offset for offset, _ in parts], [9 * SLICE_SIZE, 0])

    def test_small_file_is_raw(self):
        value = b"\x00\x00\x00\x1cftypmp42" + bytes(1000)
        self.assertEqual(parse_chunk(value), (True, [(0, value)]))


class ReassembleTest(unittest.TestCase):
    def test_full_file_in_header(self):
        value = b"OggS" + bytes(5000)
        result = reassemble({0: value})
        self.assertEqual(result.size, len(value))
        self.assertEqual(result.covered(), len(value))
        self.assertEqual(result.gaps(), [])

    def test_slices_with_gaps_and_inferred_size(self):
        header = parts_map([(0, part(0)), (SLICE_SIZE + PART_SIZE, part(65, 1000))])
        slice_2 = part(64)  # raw prefix of slice 2, starting at 8 MiB
        result = reassemble({0: header, 2: slice_2})

        self.assertEqual(result.size, SLICE_SIZE + PART_SIZE + 1000)
        self.assertEqual(result.covered(), 2 * PART_SIZE + 1000)
        self.assertEqual(
            result.gaps(), [(PART_SIZE, SLICE_SIZE - PART_SIZE)]
        )

    def test_unknown_size_ends_at_last_byte(self):
        result = reassemble({2: part(64) + part(65)})
        self.assertIsNone(result.size)
        self.assertEqual(result.end, SLICE_SIZE + 2 * PART_SIZE)
        self.assertEqual(result.gaps(), [(0, SLICE_SIZE)])

    def test_known_size_wins(self):
        result = reassemble({1: part(0)}, known_size=3 * PART_SIZE)
        self.assertEqual(result.size, 3 * PART_SIZE)
        self.assertEqual(result.gaps(), [(PART_SIZE, 2 * PART_SIZE)])


if __name__ == "__main__":
    unittest.main()
