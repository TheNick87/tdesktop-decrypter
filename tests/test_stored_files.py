import os
import tempfile
import unittest

from tdesktop_decrypter.decrypter import compute_data_name_key
from tdesktop_decrypter.file_io import LegacyTdataException
from tdesktop_decrypter.maps import read_account_map, to_file_part
from tdesktop_decrypter.stored_files import (
    AccountFiles,
    StoredFileException,
    extract,
    parse_stored_file_id,
    sort_stored_files,
)
from tdesktop_decrypter.streaming import PART_SIZE, document_base_key

from tests.fixtures import (
    LOCAL_KEY,
    CacheBuilder,
    MemoryFileIo,
    encrypted_tdf,
    map_tdf,
    parts_map,
    qt_bytes,
    qt_string,
    tdf,
    u32,
    u64,
)

FOLDER = compute_data_name_key("data#2")
LOCATIONS_KEY = 0x1122334455667788
DRAFT_KEY = 0x0102030405060708
STICKER_DOC = 1001
NAMED_DOC = 2002
VIDEO_DOC = 3003
JPEG = b"\xff\xd8\xff\xe0" + bytes(60)
MP4 = b"\x00\x00\x00\x1cftypmp42" + bytes(20)
EMOJI_DOC = 4004
EMOJI_FRAMES = (2).to_bytes(4, "little") + (20).to_bytes(4, "little") + bytes(40)


def location(doc_id: int, path: str, size: int) -> bytes:
    return (
        u64((0x4E45ABE9 << 32) | 2)
        + u64(doc_id)
        + u32(0)
        + qt_string(path)
        + qt_bytes(b"")
        + bytes(13)
        + u32(size)
    )


def build_tdata() -> MemoryFileIo:
    io = MemoryFileIo()

    account_map = u32(0x04) + u64(LOCATIONS_KEY) + u32(0x01) + u32(1) + u64(DRAFT_KEY) + u64(42)
    io.files[f"{FOLDER}/maps"] = map_tdf(account_map)

    locations = (
        location(NAMED_DOC, "C:\\Downloads\\holiday.jpg", len(JPEG))
        + location(VIDEO_DOC, "F:/Videos/trip.mp4", 0)
        + u64(0) + u64(0) + u32(0) + qt_bytes(b"") + qt_bytes(b"") + bytes(13) + u32(0)
        + u32(0)  # aliases
        + u32(0)  # web locations
    )
    io.files[f"{FOLDER}/{to_file_part(LOCATIONS_KEY)}s"] = encrypted_tdf(locations, 4000000)
    io.files[f"{FOLDER}/{to_file_part(DRAFT_KEY)}s"] = encrypted_tdf(b"draft bytes")
    io.files[f"{FOLDER}/configs"] = encrypted_tdf(b"config bytes")

    cache = CacheBuilder(io, "user_data#2/cache")
    cache.put((0x102, STICKER_DOC), b"RIFF\0\0\0\0WEBPVP8 " + bytes(30), tag=2, time=10)
    cache.put((0x102, NAMED_DOC), b"partial:" + JPEG, tag=1, time=20)
    cache.finish()

    base = document_base_key(VIDEO_DOC)
    header = parts_map([(0, MP4 + bytes(PART_SIZE - len(MP4)))])
    media = CacheBuilder(io, "user_data#2/media_cache")
    media.put(base, header, time=30)
    media.put((base[0], base[1] + 2), b"\x07" * PART_SIZE, time=40)
    media.put((0x30000, 99), b"lottie frames", time=50)
    emoji_base = document_base_key(EMOJI_DOC)
    media.put((emoji_base[0], emoji_base[1] + 246), EMOJI_FRAMES, time=60)
    media.finish()

    return io


class AccountFilesTest(unittest.TestCase):
    def setUp(self):
        self.account = AccountFiles(build_tdata(), 1, "data", LOCAL_KEY)
        self.out_dir = tempfile.mkdtemp()

    def by_id(self):
        return {stored.id: stored for stored in self.account.list()}

    def test_list(self):
        files = self.by_id()

        draft = files[f"1/account/{to_file_part(DRAFT_KEY)}"]
        self.assertEqual(draft.label, "draft (peer 42)")
        self.assertEqual(files["1/account/config"].label, "mtp config")
        self.assertEqual(files[f"1/account/{to_file_part(LOCATIONS_KEY)}"].label, "locations")

        sticker = files[f"1/cache/{0x102:016X}{STICKER_DOC:016X}"]
        self.assertEqual((sticker.tag, sticker.extension, sticker.time), ("sticker", "webp", 10))

        named = files[f"1/cache/{0x102:016X}{NAMED_DOC:016X}"]
        self.assertTrue(named.partial)
        self.assertEqual(named.size, len(JPEG))
        self.assertEqual(named.original_name, "holiday.jpg")

        video = files[f"1/media/{VIDEO_DOC}"]
        self.assertEqual((video.chunks, video.extension, video.original_name), (2, "mp4", "trip.mp4"))

        self.assertIn(f"1/media-entry/{0x30000:016X}{99:016X}", files)

        emoji_base = document_base_key(EMOJI_DOC)
        emoji = files[f"1/media-entry/{emoji_base[0]:016X}{emoji_base[1] + 246:016X}"]
        self.assertEqual(emoji.label, "custom emoji frames")
        self.assertNotIn(f"1/media/{EMOJI_DOC}", files)

        self.assertEqual(len(files), 8)

    def test_sort_by_time_puts_most_recent_first_and_untimed_last(self):
        files = sort_stored_files(self.account.list(), "time")
        times = [stored.time for stored in files]

        # emoji frames, lottie entry, video (latest chunk), partial jpg, sticker, then account files.
        self.assertEqual(times, [60, 50, 40, 20, 10, None, None, None])
        self.assertEqual(files[2].id, f"1/media/{VIDEO_DOC}")

    def test_no_sort_keeps_listing_order(self):
        files = self.account.list()
        self.assertEqual(sort_stored_files(files, None), files)

    def test_extract_partial_cache_entry_uses_original_name(self):
        result = extract(self.account, "cache", f"{0x102:016X}{NAMED_DOC:016X}", self.out_dir)
        self.assertEqual(os.path.basename(result.path), "holiday.jpg")
        with open(result.path, "rb") as f:
            self.assertEqual(f.read(), JPEG)

    def test_extract_cache_entry_without_name_uses_detected_extension(self):
        key = f"{0x102:016X}{STICKER_DOC:016X}"
        result = extract(self.account, "cache", key, self.out_dir)
        self.assertEqual(os.path.basename(result.path), f"{key}.webp")

    def test_extract_media_document_fills_gaps(self):
        result = extract(self.account, "media", str(VIDEO_DOC), self.out_dir, dump_chunks=True)

        with open(result.path, "rb") as f:
            data = f.read()

        self.assertIsNone(result.reassembly.size)
        self.assertEqual(len(data), 8 * 1024 * 1024 + PART_SIZE)
        self.assertTrue(data.startswith(MP4))
        self.assertEqual(data[PART_SIZE : 2 * PART_SIZE], bytes(PART_SIZE))
        self.assertEqual(data[-PART_SIZE:], b"\x07" * PART_SIZE)
        self.assertEqual(len(result.chunk_paths), 2)

    def test_extract_account_file_and_media_entry(self):
        result = extract(self.account, "account", "config", self.out_dir)
        with open(result.path, "rb") as f:
            self.assertEqual(f.read(), b"config bytes")

        result = extract(self.account, "media-entry", f"{0x30000:016X}{99:016X}", self.out_dir)
        with open(result.path, "rb") as f:
            self.assertEqual(f.read(), b"lottie frames")

    def test_refuses_to_overwrite_without_force(self):
        extract(self.account, "account", "config", self.out_dir)
        with self.assertRaises(StoredFileException):
            extract(self.account, "account", "config", self.out_dir)
        extract(self.account, "account", "config", self.out_dir, force=True)

    def test_unknown_files(self):
        with self.assertRaises(StoredFileException):
            extract(self.account, "media", "12345", self.out_dir)
        with self.assertRaises(StoredFileException):
            extract(self.account, "account", "maps", self.out_dir)


class StoredFileIdTest(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(parse_stored_file_id("1/cache/AB"), (1, "cache", "AB"))

    def test_rejects_bad_ids(self):
        for text in ("cache/AB", "x/cache/AB", "1/photos/AB", "1/cache"):
            with self.assertRaises(StoredFileException):
                parse_stored_file_id(text)


class LegacyTdataTest(unittest.TestCase):
    def test_legacy_map_is_rejected(self):
        io = MemoryFileIo({f"{FOLDER}/maps": tdf(qt_bytes(b"salt") + qt_bytes(b"k") + qt_bytes(b""))})
        with self.assertRaises(LegacyTdataException):
            AccountFiles(io, 1, "data", LOCAL_KEY).list()


class AccountMapTest(unittest.TestCase):
    def test_stops_at_unknown_type(self):
        account_map = read_account_map(u32(0x04) + u64(LOCATIONS_KEY) + u32(0xFF) + u64(7))
        self.assertEqual(list(account_map.labels.values()), ["locations"])


if __name__ == "__main__":
    unittest.main()
