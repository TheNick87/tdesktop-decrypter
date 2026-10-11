import os

from typing import Tuple, List
from io import BytesIO

from tdesktop_decrypter.crypto import decrypt_local
from tdesktop_decrypter.tdf import RawTdfFile, parse_raw_tdf
from tdesktop_decrypter.qt import read_qt_byte_array


class LegacyTdataException(Exception):
    pass


class TdataFileIo:
    def read_file(self, path: str) -> bytes:
        '''
        Reads a file from filesystem or some other data provider.
        Path is a relative path to the file without leading slash.
        For example, path = 'settings'
        Returns the file's data if the file exists, otherwise raises FileNotFoundError.
        '''
        raise NotImplementedError()

    def read_file_head(self, path: str, size: int) -> bytes:
        '''
        Reads at most the first `size` bytes of a file.
        '''
        return self.read_file(path)[:size]

    def list_files(self, path: str) -> List[str]:
        '''
        Lists the regular files in a directory, relative to it.
        Returns an empty list if the directory does not exist.
        '''
        raise NotImplementedError()

    def file_size(self, path: str) -> int:
        return len(self.read_file(path))
    
    def read_tdf_file(self, path: str) -> RawTdfFile:
        candidates = [path + "s", path]

        for candidate in candidates:
            try:
                return parse_raw_tdf(self.read_file(candidate))
            except FileNotFoundError:
                pass

        raise FileNotFoundError(path)

    def read_encrypted_file(self, path: str, local_key: bytes) -> Tuple[int, bytes]:
        tdf_file = self.read_tdf_file(path)
        encrpyted_data = read_qt_byte_array(BytesIO(tdf_file.encrypted_data))
        return tdf_file.version, decrypt_local(encrpyted_data, local_key)

    def read_map_file(self, path: str, local_key: bytes) -> bytes:
        '''
        The account `maps` file holds a legacy salt, a legacy key and the encrypted map.
        Only the key_datas layout (both legacy fields empty) is supported.
        '''
        stream = BytesIO(self.read_tdf_file(path).encrypted_data)
        legacy_salt = read_qt_byte_array(stream)
        legacy_key = read_qt_byte_array(stream)
        if legacy_salt or legacy_key:
            raise LegacyTdataException(
                'legacy tdata layout (without key_datas) is not supported'
            )

        return decrypt_local(read_qt_byte_array(stream), local_key)


class TdataFileSystem(TdataFileIo):
    def __init__(self, base_path: str):
        super().__init__()
        
        self._base_path = base_path
    
    def read_file(self, path: str) -> bytes:
        with open(os.path.join(self._base_path, path), 'rb') as f:
            return f.read()

    def read_file_head(self, path: str, size: int) -> bytes:
        with open(os.path.join(self._base_path, path), 'rb') as f:
            return f.read(size)

    def list_files(self, path: str) -> List[str]:
        base = os.path.join(self._base_path, path)
        if not os.path.isdir(base):
            return []

        return sorted(
            name for name in os.listdir(base)
            if os.path.isfile(os.path.join(base, name))
        )

    def file_size(self, path: str) -> int:
        return os.path.getsize(os.path.join(self._base_path, path))
