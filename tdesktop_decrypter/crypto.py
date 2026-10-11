import hashlib

import tgcrypto

LocalEncryptNoPwdIterCount = 4
LocalEncryptIterCount = 400
kStrongIterationsCount = 100000


class CryptoException(Exception):
    pass


def create_local_key(passcode: bytes, salt: bytes) -> bytes:
    if passcode:
        iterations = kStrongIterationsCount
    else:
        iterations = 1

    password = hashlib.sha512(salt + passcode + salt).digest()
    return hashlib.pbkdf2_hmac("sha512", password, salt, iterations, 256)


def create_legacy_local_key(passcode: bytes, salt: bytes) -> bytes:
    if passcode:
        iterations = LocalEncryptIterCount
    else:
        iterations = LocalEncryptNoPwdIterCount

    return hashlib.pbkdf2_hmac("sha1", passcode, salt, iterations, 256)


def decrypt_local(encrypted_msg, local_key):
    msg_key, encrypted_data = encrypted_msg[:16], encrypted_msg[16:]

    decrypted = aes_decrypt_local(encrypted_data, msg_key, local_key)

    if hashlib.sha1(decrypted).digest()[:16] != msg_key:
        raise CryptoException(
            "bad decrypt key, data not decrypted - incorrect password"
        )

    length = int.from_bytes(decrypted[:4], "little")
    if length > len(decrypted):
        raise CryptoException(f"corrupted data. wrong length: {length}")

    return decrypted[4:length]


def aes_decrypt_local(encrypted_data, msg_key, local_key):
    aes_key, aes_iv = prepare_aes_old_mtp(local_key, msg_key)
    return tgcrypto.ige256_decrypt(encrypted_data, aes_key, aes_iv)


def prepare_aes_old_mtp(local_key, msg_key, send=False):
    x = 0 if send else 8

    def key_pos(pos, size):
        return local_key[pos : pos + size]

    dataA = msg_key + key_pos(x, 32)
    dataB = key_pos(x + 32, 16) + msg_key + key_pos(x + 48, 16)
    dataC = key_pos(x + 64, 32) + msg_key
    dataD = msg_key + key_pos(x + 96, 32)

    sha1A = hashlib.sha1(dataA).digest()
    sha1B = hashlib.sha1(dataB).digest()
    sha1C = hashlib.sha1(dataC).digest()
    sha1D = hashlib.sha1(dataD).digest()

    key = sha1A[:8] + sha1B[8:20] + sha1C[4:16]
    iv = sha1A[8:20] + sha1B[:8] + sha1C[16:20] + sha1D[:8]

    return key, iv


CACHE_FILE_MAGIC = b"TDEF"
CACHE_SALT_SIZE = 64
CACHE_HEADER_SIZE = 48
CACHE_PAYLOAD_OFFSET = len(CACHE_FILE_MAGIC) + CACHE_SALT_SIZE + CACHE_HEADER_SIZE


def prepare_aes_ctr_cache(local_key: bytes, salt: bytes):
    key = hashlib.sha256(local_key[:128] + salt[:32]).digest()
    iv = hashlib.sha256(local_key[128:] + salt[32:]).digest()[:16]
    return key, iv


def decrypt_cache_file(data: bytes, local_key: bytes) -> bytes:
    """
    Decrypts a cache database file (binlog or value): "TDEF" | salt(64) | AES-256-CTR(header(48) | payload).
    Returns the payload, still including its random padding up to a 16-byte boundary.
    """
    if data[:4] != CACHE_FILE_MAGIC:
        raise CryptoException("wrong magic. not a cache database file?")

    salt = data[4 : 4 + CACHE_SALT_SIZE]
    encrypted = data[4 + CACHE_SALT_SIZE :]
    encrypted = encrypted[: len(encrypted) // 16 * 16]

    if len(encrypted) < CACHE_HEADER_SIZE:
        raise CryptoException("cache database file is too short")

    key, iv = prepare_aes_ctr_cache(local_key, salt)
    decrypted = tgcrypto.ctr256_decrypt(encrypted, key, iv, bytes(1))

    checksum = hashlib.sha256(local_key + salt + decrypted[:16]).digest()
    if checksum != decrypted[16:CACHE_HEADER_SIZE]:
        raise CryptoException("bad cache file checksum - wrong key or corrupted file")

    return decrypted[CACHE_HEADER_SIZE:]
