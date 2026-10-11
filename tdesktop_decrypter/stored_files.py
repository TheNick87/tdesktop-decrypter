import os

from typing import Dict, List, Optional, Tuple

from tdesktop_decrypter.cache import (
    CACHE_TAGS,
    CacheDatabase,
    CacheKey,
    CacheRecord,
    format_cache_key,
    parse_cache_key,
)
from tdesktop_decrypter.decrypter import compose_account_name, compute_data_name_key
from tdesktop_decrypter.file_io import TdataFileIo
from tdesktop_decrypter.filetypes import SNIFF_SIZE, detect_extension, detect_frame_cache
from tdesktop_decrypter.maps import (
    IN_MEDIA_CACHE_PATH,
    AccountMap,
    Location,
    read_account_map,
    read_locations,
)
from tdesktop_decrypter.streaming import (
    DOCUMENT_FAMILY,
    PART_SIZE,
    PHOTO_FAMILY,
    MAX_PARTS_IN_MAP,
    Reassembly,
    base_key,
    chunk_number,
    document_base_key,
    document_id,
    is_media_document_key,
    reassemble,
)

KIND_ACCOUNT = "account"
KIND_CACHE = "cache"
KIND_MEDIA = "media"
KIND_MEDIA_ENTRY = "media-entry"
KINDS = (KIND_ACCOUNT, KIND_CACHE, KIND_MEDIA, KIND_MEDIA_ENTRY)

PARTIAL_PREFIX = b"partial:"

# DocumentCacheKey(): high = 0x100 | dc, low = document id.
DOCUMENT_CACHE_KEY_TYPE = 0x1

ACCOUNT_FOLDER_EXTRA_LABELS = {"config": "mtp config"}


class StoredFileException(Exception):
    pass


class StoredFile:
    def __init__(self, account_index: int, kind: str, key: str):
        self.account_index = account_index
        self.kind = kind
        self.key = key
        # Bytes stored on disk (decrypted size for cache, sum of chunks for media).
        self.size: Optional[int] = None
        self.time: Optional[int] = None
        self.tag: Optional[str] = None
        self.label: Optional[str] = None
        self.extension: Optional[str] = None
        self.partial = False
        self.original_name: Optional[str] = None
        self.known_size: Optional[int] = None
        self.chunks: Optional[int] = None

    @property
    def id(self) -> str:
        return format_stored_file_id(self.account_index, self.kind, self.key)

    def output_name(self) -> str:
        if self.original_name:
            return self.original_name

        return f"{self.key}.{self.extension or 'bin'}"

    def __repr__(self):
        return f"StoredFile({self.id})"


def format_stored_file_id(account_index: int, kind: str, key: str) -> str:
    return f"{account_index}/{kind}/{key}"


def parse_stored_file_id(text: str) -> Tuple[int, str, str]:
    parts = text.split("/")
    if len(parts) != 3 or not parts[0].isdigit() or parts[1] not in KINDS:
        raise StoredFileException(
            f"bad stored-file ID {text!r}: expected <account>/<{'|'.join(KINDS)}>/<key>"
        )

    return int(parts[0]), parts[1], parts[2]


def _basename(path: str) -> str:
    return path.replace("\\", "/").rsplit("/", 1)[-1]


def _strip_partial(value: bytes) -> Tuple[bool, bytes]:
    if value.startswith(PARTIAL_PREFIX):
        return True, value[len(PARTIAL_PREFIX) :]

    return False, value


def _media_payload_head(head: bytes, value_size: int) -> Optional[bytes]:
    """
    Returns the first file bytes of a header chunk, or None if it does not look like a media chunk.
    A complex parts map starts with a small count, then the first part's offset and size.
    """
    if value_size % PART_SIZE:
        count = int.from_bytes(head[:4], "little")
        if 0 < count <= MAX_PARTS_IN_MAP:
            offset = int.from_bytes(head[4:8], "little")
            return head[12:] if offset == 0 else b""

    if detect_extension(head):
        return head

    return None


class AccountFiles:
    """
    Every stored file of one account: its account-folder files, cache entries,
    media documents and other media-cache entries.
    """

    def __init__(self, io: TdataFileIo, index: int, dataname: str, local_key: bytes):
        self._io = io
        self.index = index
        self.user_id: Optional[int] = None

        account_name = compose_account_name(dataname, index)
        self.folder = compute_data_name_key(account_name)
        cache_folder = f"user_{account_name}"

        self._local_key = local_key
        self.cache = CacheDatabase(io, f"{cache_folder}/cache", local_key)
        self.media_cache = CacheDatabase(io, f"{cache_folder}/media_cache", local_key)

        self._account_map: Optional[AccountMap] = None
        self._locations: Optional[Dict[int, Location]] = None

    # Account folder.

    def account_map(self) -> AccountMap:
        if self._account_map is None:
            try:
                data = self._io.read_map_file(f"{self.folder}/map", self._local_key)
                self._account_map = read_account_map(data)
            except FileNotFoundError:
                self._account_map = AccountMap()

        return self._account_map

    def locations(self) -> Dict[int, Location]:
        if self._locations is None:
            self._locations = {}
            locations_key = self.account_map().locations_key
            if locations_key:
                try:
                    version, data = self._io.read_encrypted_file(
                        f"{self.folder}/{locations_key}", self._local_key
                    )
                    self._locations = read_locations(data, version)
                except FileNotFoundError:
                    pass

        return self._locations

    def _location(self, doc_id: int) -> Optional[Location]:
        location = self.locations().get(doc_id)
        if location is None or location.path == IN_MEDIA_CACHE_PATH:
            return None

        return location

    def _account_folder_keys(self) -> List[str]:
        return [
            name[:-1]
            for name in self._io.list_files(self.folder)
            if name.endswith("s") and name != "maps"
        ]

    def list_account_files(self) -> List[StoredFile]:
        labels = self.account_map().labels
        files = []

        for key in self._account_folder_keys():
            stored = StoredFile(self.index, KIND_ACCOUNT, key)
            stored.size = self._io.file_size(f"{self.folder}/{key}s")
            stored.label = labels.get(key) or ACCOUNT_FOLDER_EXTRA_LABELS.get(
                key, "unreferenced"
            )
            stored.extension = "bin"
            files.append(stored)

        return files

    def read_account_file(self, key: str) -> bytes:
        if key not in self._account_folder_keys():
            raise StoredFileException(f"no account-folder file {key} in {self.folder}")

        _, data = self._io.read_encrypted_file(f"{self.folder}/{key}", self._local_key)
        return data

    # Cache.

    def _cache_entry(self, record: CacheRecord) -> StoredFile:
        stored = StoredFile(self.index, KIND_CACHE, format_cache_key(record.key))
        stored.size = record.size
        stored.time = record.time
        stored.tag = CACHE_TAGS.get(record.tag, f"tag {record.tag}")

        if record.key[0] >> 8 == DOCUMENT_CACHE_KEY_TYPE:
            location = self._location(record.key[1])
            if location is not None:
                stored.original_name = _basename(location.path)

        return stored

    def list_cache_entries(self) -> List[StoredFile]:
        files = []
        for record in self.cache.records().values():
            stored = self._cache_entry(record)
            stored.partial, head = _strip_partial(
                self.cache.read_head(record, len(PARTIAL_PREFIX) + SNIFF_SIZE)
            )
            if stored.partial:
                stored.size -= len(PARTIAL_PREFIX)
            stored.extension = detect_extension(head)
            files.append(stored)

        return files

    def read_cache_entry(self, key: str) -> Tuple[StoredFile, bytes]:
        record = self.cache.records().get(parse_cache_key(key))
        if record is None:
            raise StoredFileException(f"no live cache entry {key}")

        stored = self._cache_entry(record)
        stored.partial, value = _strip_partial(self.cache.read(record))
        stored.size = len(value)
        stored.extension = detect_extension(value[:SNIFF_SIZE])
        return stored, value

    # Media cache.

    def _media_groups(self) -> Dict[CacheKey, Dict[int, CacheRecord]]:
        groups: Dict[CacheKey, Dict[int, CacheRecord]] = {}
        for key, record in self.media_cache.records().items():
            if is_media_document_key(key):
                groups.setdefault(base_key(key), {})[chunk_number(key)] = record

        return groups

    def _classify_media_group(
        self, chunks: Dict[int, CacheRecord]
    ) -> Tuple[bool, Optional[str]]:
        """
        Returns (is_media_document, extension) by looking at the lowest chunk.
        Without a header chunk the type is unknown, but frame caches are still recognised.
        """
        number = min(chunks)
        chunk = chunks[number]
        head = self.media_cache.read_head(chunk, 12 + SNIFF_SIZE)

        if detect_frame_cache(head):
            return False, None

        if number != 0:
            return True, None

        payload_head = _media_payload_head(head, chunk.size)
        if payload_head is None:
            return False, None

        return True, detect_extension(payload_head)

    def _media_document(
        self, base: CacheKey, chunks: Dict[int, CacheRecord], extension: Optional[str]
    ) -> StoredFile:
        doc_id = document_id(base)
        stored = StoredFile(self.index, KIND_MEDIA, str(doc_id))
        stored.size = sum(record.size for record in chunks.values())
        stored.time = max((record.time or 0 for record in chunks.values()), default=None)
        stored.extension = extension
        stored.chunks = len(chunks)

        location = self.locations().get(doc_id)
        if location is not None and location.size:
            stored.known_size = location.size
        if self._location(doc_id) is not None:
            stored.original_name = _basename(location.path)

        return stored

    def _media_entry(self, record: CacheRecord) -> StoredFile:
        stored = StoredFile(self.index, KIND_MEDIA_ENTRY, format_cache_key(record.key))
        stored.size = record.size
        stored.time = record.time
        return stored

    def list_media(self) -> List[StoredFile]:
        files = []
        grouped = set()

        for base, chunks in self._media_groups().items():
            is_document, extension = self._classify_media_group(chunks)
            if is_document:
                files.append(self._media_document(base, chunks, extension))
                grouped.update(record.key for record in chunks.values())

        for key, record in self.media_cache.records().items():
            if key not in grouped:
                stored = self._media_entry(record)
                head = self.media_cache.read_head(record, SNIFF_SIZE)
                stored.label = detect_frame_cache(head)
                stored.extension = detect_extension(head)
                files.append(stored)

        return files

    def read_media_document(
        self, doc_id_text: str
    ) -> Tuple[StoredFile, Reassembly, Dict[int, bytes]]:
        if not doc_id_text.isdigit():
            raise StoredFileException(f"bad document id {doc_id_text!r}")

        doc_id = int(doc_id_text)
        groups = self._media_groups()
        for family in (DOCUMENT_FAMILY, PHOTO_FAMILY):
            base = document_base_key(doc_id, family)
            if base in groups:
                break
        else:
            raise StoredFileException(f"no media document {doc_id} in the media cache")

        chunks = groups[base]
        is_document, extension = self._classify_media_group(chunks)
        if not is_document:
            raise StoredFileException(
                f"media-cache entries of {doc_id} are not a streamed document; "
                "extract them as media-entry IDs"
            )

        stored = self._media_document(base, chunks, extension)
        values = {
            number: self.media_cache.read(record) for number, record in chunks.items()
        }
        return stored, reassemble(values, stored.known_size), values

    def read_media_entry(self, key: str) -> Tuple[StoredFile, bytes]:
        record = self.media_cache.records().get(parse_cache_key(key))
        if record is None:
            raise StoredFileException(f"no live media-cache entry {key}")

        stored = self._media_entry(record)
        value = self.media_cache.read(record)
        stored.label = detect_frame_cache(value[:SNIFF_SIZE])
        stored.extension = detect_extension(value[:SNIFF_SIZE])
        return stored, value

    # All kinds.

    def list(self, kinds=KINDS) -> List[StoredFile]:
        files = []
        if KIND_ACCOUNT in kinds:
            files += self.list_account_files()
        if KIND_CACHE in kinds:
            files += self.list_cache_entries()
        if KIND_MEDIA in kinds or KIND_MEDIA_ENTRY in kinds:
            files += [f for f in self.list_media() if f.kind in kinds]

        return files


class ExtractResult:
    def __init__(self, stored: StoredFile, path: str):
        self.stored = stored
        self.path = path
        self.reassembly: Optional[Reassembly] = None
        self.chunk_paths: List[str] = []


def _open_output(path: str, force: bool):
    if os.path.exists(path) and not force:
        raise StoredFileException(f"{path} already exists (use --force to overwrite)")

    return open(path, "wb")


def extract(
    account: AccountFiles,
    kind: str,
    key: str,
    out_dir: str,
    force: bool = False,
    dump_chunks: bool = False,
) -> ExtractResult:
    os.makedirs(out_dir, exist_ok=True)

    if kind == KIND_ACCOUNT:
        data = account.read_account_file(key)
        stored = StoredFile(account.index, kind, key)
        stored.size = len(data)
        stored.extension = "bin"
    elif kind == KIND_CACHE:
        stored, data = account.read_cache_entry(key)
    elif kind == KIND_MEDIA_ENTRY:
        stored, data = account.read_media_entry(key)
    else:
        stored, reassembly, chunks = account.read_media_document(key)
        result = ExtractResult(stored, os.path.join(out_dir, stored.output_name()))

        with _open_output(result.path, force) as f:
            for offset, data in reassembly.parts.items():
                f.seek(offset)
                f.write(data[: max(0, reassembly.end - offset)])
            f.truncate(reassembly.end)

        result.reassembly = reassembly

        if dump_chunks:
            chunks_dir = result.path + ".chunks"
            os.makedirs(chunks_dir, exist_ok=True)
            for number, value in sorted(chunks.items()):
                chunk_path = os.path.join(chunks_dir, f"{number}.bin")
                with _open_output(chunk_path, force) as f:
                    f.write(value)
                result.chunk_paths.append(chunk_path)

        return result

    result = ExtractResult(stored, os.path.join(out_dir, stored.output_name()))
    with _open_output(result.path, force) as f:
        f.write(data)

    return result
