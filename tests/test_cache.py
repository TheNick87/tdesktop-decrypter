import unittest

from tdesktop_decrypter.cache import (
    CacheDatabase,
    format_cache_key,
    parse_cache_key,
    place_to_path,
    read_binlog,
)
from tdesktop_decrypter.crypto import CryptoException, decrypt_cache_file
from tdesktop_decrypter.xxh32 import xxh32

from tests.fixtures import (
    LOCAL_KEY,
    CacheBuilder,
    MemoryFileIo,
    access_record,
    binlog_payload,
    encrypt_cache_file,
    remove_record,
    store_record,
)

KEY_A = (0x101, 111)
KEY_B = (0x101, 222)
PLACE = bytes([0x3A, 1, 2, 3, 4, 5, 6])


class Xxh32Test(unittest.TestCase):
    def test_reference_vectors(self):
        self.assertEqual(xxh32(b""), 0x02CC5D05)
        self.assertEqual(xxh32(b"abc"), 0x32D153FF)
        self.assertEqual(xxh32(b"a"), 0x550D7456)


class CacheFileTest(unittest.TestCase):
    def test_round_trip(self):
        payload = b"hello cache" * 10
        decrypted = decrypt_cache_file(encrypt_cache_file(payload), LOCAL_KEY)
        self.assertEqual(decrypted[: len(payload)], payload)
        self.assertEqual(len(decrypted) % 16, 0)

    def test_wrong_key(self):
        data = encrypt_cache_file(b"secret")
        with self.assertRaises(CryptoException):
            decrypt_cache_file(data, bytes(256))

    def test_wrong_magic(self):
        with self.assertRaises(CryptoException):
            decrypt_cache_file(b"XXXX" + bytes(200), LOCAL_KEY)


class KeysTest(unittest.TestCase):
    def test_place_to_path_writes_low_nibble_first(self):
        self.assertEqual(place_to_path(PLACE), "A3/102030405060")

    def test_cache_key_round_trip(self):
        text = format_cache_key(KEY_A)
        self.assertEqual(len(text), 32)
        self.assertEqual(parse_cache_key(text), KEY_A)


class BinlogTest(unittest.TestCase):
    def test_store_remove_access(self):
        records = read_binlog(
            binlog_payload(
                [
                    store_record(KEY_A, b"a" * 10, PLACE, tag=1, time=100),
                    store_record(KEY_B, b"b" * 20, PLACE, time=100),
                    store_record(KEY_A, b"a" * 30, PLACE, tag=1, time=150),
                    remove_record([KEY_B]),
                    access_record([KEY_A], 200),
                ]
            )
        )

        self.assertEqual(list(records), [KEY_A])
        self.assertEqual(records[KEY_A].size, 30)
        self.assertEqual(records[KEY_A].tag, 1)
        self.assertEqual(records[KEY_A].time, 200)

    def test_stops_at_invalid_record(self):
        records = read_binlog(
            binlog_payload(
                [store_record(KEY_A, b"a", PLACE), bytes([0x7F]) + bytes(15)]
                + [store_record(KEY_B, b"b", PLACE)]
            )
        )
        self.assertEqual(list(records), [KEY_A])


class CacheDatabaseTest(unittest.TestCase):
    def setUp(self):
        self.io = MemoryFileIo()
        builder = CacheBuilder(self.io, "user_data/cache")
        builder.put(KEY_A, b"\xff\xd8\xff" + b"x" * 100, tag=1, time=5)
        builder.finish()
        self.db = CacheDatabase(self.io, "user_data/cache", LOCAL_KEY)

    def test_read_and_head(self):
        record = self.db.records()[KEY_A]
        self.assertEqual(self.db.read(record), b"\xff\xd8\xff" + b"x" * 100)
        self.assertEqual(self.db.read_head(record, 3), b"\xff\xd8\xff")

    def test_bad_checksum(self):
        record = self.db.records()[KEY_A]
        record.checksum ^= 1
        with self.assertRaises(CryptoException):
            self.db.read(record)

    def test_missing_database_is_empty(self):
        self.assertEqual(
            CacheDatabase(self.io, "user_data/media_cache", LOCAL_KEY).records(), {}
        )


if __name__ == "__main__":
    unittest.main()
