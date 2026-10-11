from typing import Optional

# Number of leading bytes detect_extension() needs.
SNIFF_SIZE = 16


def detect_extension(head: bytes) -> Optional[str]:
    """
    Guesses a file extension from its first bytes. Returns None if unknown.
    """
    if head.startswith(b"\xff\xd8\xff"):
        return "jpg"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if head.startswith(b"RIFF") and head[8:12] == b"WEBP":
        return "webp"
    if head.startswith(b"RIFF") and head[8:12] == b"WAVE":
        return "wav"
    if head.startswith(b"GIF8"):
        return "gif"
    if head.startswith(b"\x1f\x8b"):
        # Animated stickers are gzipped Lottie JSON.
        return "tgs"
    if head.startswith(b"\x1a\x45\xdf\xa3"):
        return "webm"
    if head[4:8] == b"ftyp":
        return "mp4"
    if head.startswith(b"OggS"):
        return "ogg"
    if head.startswith(b"ID3") or (len(head) > 1 and head[0] == 0xFF and head[1] & 0xE0 == 0xE0):
        return "mp3"
    if head.startswith(b"fLaC"):
        return "flac"
    if head.startswith(b"%PDF"):
        return "pdf"
    if head.startswith(b"PK\x03\x04"):
        return "zip"
    if head.startswith(b"{"):
        return "json"

    return None


CUSTOM_EMOJI_CACHE_VERSIONS = (1, 2)
STREAMING_PART_SIZE = 128 * 1024


def detect_frame_cache(head: bytes) -> Optional[str]:
    """
    Recognises the pre-rendered animation frames tdesktop keeps in the media cache.
    """
    if len(head) < 8:
        return None

    first = int.from_bytes(head[:4], "little")
    second = int.from_bytes(head[4:8], "little")

    # lib_ui custom emoji Cache: i32 version, i32 size, ... A streaming parts map
    # with one or two parts would instead have a 128 KiB-aligned offset here.
    if first in CUSTOM_EMOJI_CACHE_VERSIONS and second % STREAMING_PART_SIZE:
        return "custom emoji frames"

    # lib_lottie frame cache starts with a zero i32; media files and parts maps never do.
    if first == 0 and second != 0:
        return "animated sticker frames"

    return None
