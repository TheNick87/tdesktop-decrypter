from io import BytesIO
from typing import Dict, Optional, List

from tdesktop_decrypter.qt import (
    read_qt_byte_array,
    read_qt_int32,
    read_qt_int64,
    read_qt_string,
    read_qt_uint32,
    read_qt_uint64,
)


class MapException(Exception):
    pass


def to_file_part(key: int) -> str:
    """
    tdesktop ToFilePart(): 16 uppercase hex digits, least-significant nibble first.
    """
    return "".join(f"{(key >> (4 * i)) & 0xF:X}" for i in range(16))


# Single-key entries of the account map (lsk* in storage/storage_account.cpp).
SINGLE_KEY_LABELS = {
    0x04: "locations",
    0x07: "recent stickers (old)",
    0x08: "background (old)",
    0x09: "user settings",
    0x0A: "recent hashtags and bots",
    0x0B: "stickers (old)",
    0x0C: "saved peers (old)",
    0x0D: "report spam statuses (old)",
    0x0E: "saved gifs (old)",
    0x0F: "saved gifs",
    0x11: "trusted peers",
    0x12: "faved stickers",
    0x13: "export settings",
    0x18: "search suggestions",
    0x1A: "round video placeholder",
    0x1B: "inline bots downloads",
    0x1C: "media playback positions",
    0x1E: "prefs",
    0x1F: "wallet key (old)",
    0x20: "wallet engine key (old)",
}

MULTI_KEY_LABELS = {
    0x10: ["installed stickers", "featured stickers", "recent stickers", "archived stickers"],
    0x14: ["background day (old)", "background night (old)"],
    0x16: ["installed masks", "recent masks", "archived masks"],
    0x17: ["installed custom emoji", "featured custom emoji", "archived custom emoji"],
}

PEER_KEY_LABELS = {
    0x01: "draft",
    0x02: "draft cursor",
    0x1D: "bot storage",
}

LEGACY_CACHE_TYPES = (0x03, 0x05, 0x06)

INLINE_TYPES = (0x15, 0x19)

LSK_LOCATIONS = 0x04


class AccountMap:
    def __init__(self):
        # File name part (as on disk, without the trailing "s") -> label.
        self.labels: Dict[str, str] = {}
        self.locations_key: Optional[str] = None


def read_account_map(data: bytes) -> AccountMap:
    """
    Parses the decrypted payload of the account folder's `maps` file.
    Parsing stops at an unknown entry type, as tdesktop does.
    """
    stream = BytesIO(data)
    account_map = AccountMap()

    def add(key: int, label: str):
        if key:
            account_map.labels[to_file_part(key)] = label

    while stream.tell() < len(data):
        key_type = read_qt_uint32(stream)

        if key_type in SINGLE_KEY_LABELS:
            key = read_qt_uint64(stream)
            add(key, SINGLE_KEY_LABELS[key_type])

            if key_type == LSK_LOCATIONS and key:
                account_map.locations_key = to_file_part(key)
        elif key_type in MULTI_KEY_LABELS:
            for label in MULTI_KEY_LABELS[key_type]:
                add(read_qt_uint64(stream), label)
        elif key_type in PEER_KEY_LABELS:
            for _ in range(read_qt_uint32(stream)):
                key = read_qt_uint64(stream)
                peer_id = read_qt_uint64(stream)
                add(key, f"{PEER_KEY_LABELS[key_type]} (peer {peer_id})")
        elif key_type in LEGACY_CACHE_TYPES:
            for _ in range(read_qt_uint32(stream)):
                key = read_qt_uint64(stream)
                stream.read(8 + 8 + 4)
                add(key, "legacy cache file")
        elif key_type in INLINE_TYPES:
            read_qt_byte_array(stream)
            if key_type == 0x19:
                read_qt_byte_array(stream)
        elif key_type == 0x21:
            for _ in range(read_qt_uint32(stream)):
                key = read_qt_uint64(stream)
                read_qt_string(stream)
                add(key, "wallet engine storage (old)")
        else:
            break

    return account_map


class Location:
    """
    A downloaded document's local file, from the account's locations file.
    """

    def __init__(self):
        self.document_id: int = None
        self.path: str = None
        self.size: int = None


# Locations file version after which a bookmark is stored with each location.
LOCATIONS_BOOKMARK_VERSION = 9013

QDATETIME_SIZE = 8 + 4 + 1

IN_MEDIA_CACHE_PATH = "*media_cache*"


def read_locations(data: bytes, version: int) -> Dict[int, Location]:
    """
    Parses the decrypted locations file and returns locations by document id.
    Downloads list entries are merged in where they add a path.
    """
    stream = BytesIO(data)
    locations: Dict[int, Location] = {}

    while stream.tell() < len(data):
        first = read_qt_uint64(stream)
        second = read_qt_uint64(stream)
        legacy_type = read_qt_uint32(stream)
        path = read_qt_string(stream)
        if version > LOCATIONS_BOOKMARK_VERSION:
            read_qt_byte_array(stream)
        stream.read(QDATETIME_SIZE)
        size = read_qt_uint32(stream)

        if not first and not second and not legacy_type and not path and not size:
            break

        if path:
            location = Location()
            location.document_id = second
            location.path = path
            location.size = size
            locations[second] = location

    try:
        for _ in range(read_qt_uint32(stream)):
            stream.read(4 * 8)
        read_qt_uint32(stream)

        if stream.tell() < len(data):
            downloads = read_downloads(read_qt_byte_array(stream))
            for download in downloads:
                if download.document_id not in locations or (
                    locations[download.document_id].path == IN_MEDIA_CACHE_PATH
                ):
                    locations[download.document_id] = download
    except (StopIteration, UnicodeDecodeError):
        # The downloads list is best effort; the locations above are already complete.
        pass

    return locations


def read_downloads(data: bytes) -> List[Location]:
    stream = BytesIO(data)
    downloads = []

    for _ in range(read_qt_int32(stream)):
        location = Location()
        location.document_id = read_qt_uint64(stream)
        read_qt_int32(stream)  # type
        read_qt_int64(stream)  # started
        location.size = read_qt_uint32(stream)
        read_qt_uint64(stream)  # peer id
        read_qt_int64(stream)  # message id
        read_qt_uint64(stream)  # peer access hash
        location.path = read_qt_string(stream)
        downloads.append(location)

    return downloads
