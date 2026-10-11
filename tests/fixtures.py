"""
Builders for synthetic, encrypted tdata pieces. Never use data from a real tdata in tests.
"""
import hashlib
import os

from typing import Dict, List, Optional, Tuple

import tgcrypto

from tdesktop_decrypter.cache import (
    RECORD_MULTI_ACCESS,
    RECORD_MULTI_REMOVE,
    RECORD_STORE,
    place_to_path,
)
from tdesktop_decrypter.crypto import prepare_aes_ctr_cache, prepare_aes_old_mtp
from tdesktop_decrypter.file_io import TdataFileIo
from tdesktop_decrypter.tdf import TDF_MAGIC
from tdesktop_decrypter.xxh32 import xxh32

LOCAL_KEY = bytes(range(256))


class MemoryFileIo(TdataFileIo):
    def __init__(self, files: Optional[Dict[str, bytes]] = None):
        self.files: Dict[str, bytes] = dict(files or {})

    def read_file(self, path: str) -> bytes:
        if path not in self.files:
            raise FileNotFoundError(path)

        return self.files[path]

    def list_files(self, path: str) -> List[str]:
        prefix = path + "/"
        return sorted(
            name[len(prefix) :]
            for name in self.files
            if name.startswith(prefix) and "/" not in name[len(prefix) :]
        )


def qt_bytes(data: bytes) -> bytes:
    return len(data).to_bytes(4, "big") + data


def qt_string(text: str) -> bytes:
    return qt_bytes(text.encode("utf-16-be"))


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def u64(value: int) -> bytes:
    return value.to_bytes(8, "big")


def tdf(data: bytes, version: int = 4000000) -> bytes:
    hashsum = hashlib.md5(
        data + len(data).to_bytes(4, "little") + version.to_bytes(4, "little") + TDF_MAGIC
    ).digest()
    return TDF_MAGIC + version.to_bytes(4, "little") + data + hashsum


def encrypt_local(payload: bytes, local_key: bytes = LOCAL_KEY) -> bytes:
    data = (len(payload) + 4).to_bytes(4, "little") + payload
    data += bytes(-len(data) % 16)
    msg_key = hashlib.sha1(data).digest()[:16]
    key, iv = prepare_aes_old_mtp(local_key, msg_key)
    return msg_key + tgcrypto.ige256_encrypt(data, key, iv)


def encrypted_tdf(payload: bytes, version: int = 4000000) -> bytes:
    return tdf(qt_bytes(encrypt_local(payload)), version)


def map_tdf(payload: bytes) -> bytes:
    return tdf(qt_bytes(b"") + qt_bytes(b"") + qt_bytes(encrypt_local(payload)))


def encrypt_cache_file(payload: bytes, local_key: bytes = LOCAL_KEY) -> bytes:
    salt = os.urandom(64)
    basic = bytes(16)
    header = basic + hashlib.sha256(local_key + salt + basic).digest()
    plain = header + payload + os.urandom(-len(payload) % 16)
    key, iv = prepare_aes_ctr_cache(local_key, salt)
    return b"TDEF" + salt + tgcrypto.ctr256_encrypt(plain, key, iv, bytes(1))


def key_bytes(key: Tuple[int, int]) -> bytes:
    return key[0].to_bytes(8, "little") + key[1].to_bytes(8, "little")


def store_record(
    key: Tuple[int, int], value: bytes, place: bytes, tag: int = 0, time: int = 0
) -> bytes:
    return (
        bytes([RECORD_STORE, tag])
        + len(value).to_bytes(3, "little")
        + place
        + xxh32(value).to_bytes(4, "little")
        + key_bytes(key)
        + bytes(8)
        + time.to_bytes(4, "little")
        + bytes(4)
    )


def remove_record(keys: List[Tuple[int, int]]) -> bytes:
    return (
        bytes([RECORD_MULTI_REMOVE])
        + len(keys).to_bytes(3, "little")
        + bytes(12)
        + b"".join(key_bytes(k) for k in keys)
    )


def access_record(keys: List[Tuple[int, int]], time: int) -> bytes:
    return (
        bytes([RECORD_MULTI_ACCESS])
        + len(keys).to_bytes(3, "little")
        + bytes(8)
        + time.to_bytes(4, "little")
        + b"".join(key_bytes(k) for k in keys)
    )


def binlog_payload(records: List[bytes]) -> bytes:
    return bytes([0, 1, 0, 0]) + bytes(12) + b"".join(records)


class CacheBuilder:
    """
    Builds a cache database directory (version 0) inside a MemoryFileIo.
    """

    def __init__(self, io: MemoryFileIo, base_path: str):
        self._io = io
        self._base_path = base_path
        self.records: List[bytes] = []
        self._next_place = 1

    def put(self, key: Tuple[int, int], value: bytes, tag: int = 0, time: int = 0):
        place = self._next_place.to_bytes(7, "little")
        self._next_place += 1

        self._io.files[f"{self._base_path}/0/{place_to_path(place)}"] = encrypt_cache_file(
            value
        )
        self.records.append(store_record(key, value, place, tag, time))

    def finish(self):
        self._io.files[f"{self._base_path}/0/binlog"] = encrypt_cache_file(
            binlog_payload(self.records)
        )


def parts_map(parts: List[Tuple[int, bytes]]) -> bytes:
    data = len(parts).to_bytes(4, "little")
    for offset, part in parts:
        data += offset.to_bytes(4, "little") + len(part).to_bytes(4, "little") + part

    return data
