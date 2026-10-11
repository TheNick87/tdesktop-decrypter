from typing import Dict, Tuple, Optional

from tdesktop_decrypter.crypto import (
    CACHE_PAYLOAD_OFFSET,
    CryptoException,
    decrypt_cache_file,
)
from tdesktop_decrypter.file_io import TdataFileIo
from tdesktop_decrypter.xxh32 import xxh32

# Storage::Cache::Database binlog records (lib_storage storage_cache_types.h).
RECORD_STORE = 0x01
RECORD_MULTI_STORE = 0x02
RECORD_MULTI_REMOVE = 0x03
RECORD_MULTI_ACCESS = 0x04

FLAG_TRACK_ESTIMATED_TIME = 0x01

BINLOG_HEADER_SIZE = 16
STORE_SIZE = 32
STORE_WITH_TIME_SIZE = 48
KEY_SIZE = 16
MAX_DATA_SIZE = 10 * 1024 * 1024

# Cache tags set by tdesktop (data/data_types.h).
CACHE_TAGS = {
    0: None,
    1: "image",
    2: "sticker",
    3: "voice",
    4: "round video",
    5: "animation",
}

CacheKey = Tuple[int, int]


class CacheException(Exception):
    pass


class CacheLockedException(CacheException):
    pass


def format_cache_key(key: CacheKey) -> str:
    return f"{key[0]:016X}{key[1]:016X}"


def parse_cache_key(text: str) -> CacheKey:
    if len(text) != 32:
        raise ValueError(f"cache key must be 32 hex characters: {text}")

    return int(text[:16], 16), int(text[16:], 16)


def place_to_path(place: bytes) -> str:
    def nibbles(b: int) -> str:
        return f"{b & 0xF:X}{b >> 4:X}"

    return nibbles(place[0]) + "/" + "".join(nibbles(b) for b in place[1:7])


class CacheRecord:
    def __init__(self):
        self.key: CacheKey = None
        self.tag: int = None
        self.size: int = None
        self.place: bytes = None
        self.checksum: int = None
        self.time: Optional[int] = None

    def __repr__(self):
        return f"CacheRecord(key={format_cache_key(self.key)}, size={self.size})"


def _read_store(data: bytes, pos: int, with_time: bool) -> CacheRecord:
    record = CacheRecord()
    record.tag = data[pos + 1]
    record.size = int.from_bytes(data[pos + 2 : pos + 5], "little")
    record.place = data[pos + 5 : pos + 12]
    record.checksum = int.from_bytes(data[pos + 12 : pos + 16], "little")
    record.key = _read_key(data, pos + 16)

    if with_time:
        record.time = int.from_bytes(data[pos + 40 : pos + 44], "little")

    return record


def _read_key(data: bytes, pos: int) -> CacheKey:
    return (
        int.from_bytes(data[pos : pos + 8], "little"),
        int.from_bytes(data[pos + 8 : pos + 16], "little"),
    )


def read_binlog(payload: bytes) -> Dict[CacheKey, CacheRecord]:
    """
    Replays a decrypted binlog and returns the live records by key.
    Reading stops at the first invalid or truncated record, as tdesktop does.
    """
    if len(payload) < BINLOG_HEADER_SIZE or payload[0] != 0:
        raise CacheException("unsupported binlog format")

    with_time = bool(payload[1] & FLAG_TRACK_ESTIMATED_TIME)
    store_size = STORE_WITH_TIME_SIZE if with_time else STORE_SIZE

    records: Dict[CacheKey, CacheRecord] = {}
    pos = BINLOG_HEADER_SIZE

    def valid(record: CacheRecord) -> bool:
        return 0 < record.size <= MAX_DATA_SIZE

    while pos < len(payload):
        record_type = payload[pos]
        count = int.from_bytes(payload[pos + 1 : pos + 4], "little")

        if record_type == RECORD_STORE:
            end = pos + store_size
            if end > len(payload):
                break

            record = _read_store(payload, pos, with_time)
            if not valid(record):
                break

            records[record.key] = record
        elif record_type == RECORD_MULTI_STORE:
            end = pos + 16 + count * store_size
            if count == 0 or end > len(payload):
                break

            stores = [
                _read_store(payload, pos + 16 + i * store_size, with_time)
                for i in range(count)
            ]
            if not all(valid(record) for record in stores):
                break

            for record in stores:
                records[record.key] = record
        elif record_type == RECORD_MULTI_REMOVE:
            end = pos + 16 + count * KEY_SIZE
            if count == 0 or end > len(payload):
                break

            for i in range(count):
                records.pop(_read_key(payload, pos + 16 + i * KEY_SIZE), None)
        elif record_type == RECORD_MULTI_ACCESS and with_time:
            end = pos + 16 + count * KEY_SIZE
            if end > len(payload):
                break

            system_time = int.from_bytes(payload[pos + 12 : pos + 16], "little")
            for i in range(count):
                record = records.get(_read_key(payload, pos + 16 + i * KEY_SIZE))
                if record is not None:
                    record.time = system_time
        else:
            break

        pos = end

    return records


class CacheDatabase:
    """
    A Storage::Cache::Database directory, such as user_data/cache or user_data/media_cache.
    """

    def __init__(self, io: TdataFileIo, base_path: str, local_key: bytes):
        self._io = io
        self._base_path = base_path
        self._local_key = local_key
        self._records: Optional[Dict[CacheKey, CacheRecord]] = None

    def _version_path(self) -> str:
        try:
            version = int.from_bytes(
                self._io.read_file(f"{self._base_path}/version")[:4], "little"
            )
        except FileNotFoundError:
            version = 0

        return f"{self._base_path}/{version}"

    def records(self) -> Dict[CacheKey, CacheRecord]:
        if self._records is None:
            binlog_path = f"{self._version_path()}/binlog"
            try:
                data = self._io.read_file(binlog_path)
            except FileNotFoundError:
                self._records = {}
                return self._records
            except OSError as exc:
                raise CacheLockedException(
                    f"cannot read {binlog_path} ({exc.strerror}). "
                    "Is Telegram Desktop running? Quit it and try again."
                ) from exc

            self._records = read_binlog(decrypt_cache_file(data, self._local_key))

        return self._records

    def _value_path(self, record: CacheRecord) -> str:
        return f"{self._version_path()}/{place_to_path(record.place)}"

    def read_head(self, record: CacheRecord, size: int) -> bytes:
        """
        Decrypts only the first bytes of a value, without verifying its checksum.
        """
        size = min(size, record.size)
        data = self._io.read_file_head(
            self._value_path(record), CACHE_PAYLOAD_OFFSET + size + 16
        )
        return decrypt_cache_file(data, self._local_key)[:size]

    def read(self, record: CacheRecord) -> bytes:
        payload = decrypt_cache_file(
            self._io.read_file(self._value_path(record)), self._local_key
        )
        if len(payload) < record.size:
            raise CryptoException(
                f"cache value {format_cache_key(record.key)} is truncated"
            )

        value = payload[: record.size]
        if xxh32(value) != record.checksum:
            raise CryptoException(
                f"cache value {format_cache_key(record.key)} has a bad checksum"
            )

        return value
