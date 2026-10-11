import unittest

from tdesktop_decrypter.filetypes import detect_extension, detect_frame_cache


def u32le(value: int) -> bytes:
    return value.to_bytes(4, "little")


class DetectExtensionTest(unittest.TestCase):
    def test_known_magics(self):
        self.assertEqual(detect_extension(b"\xff\xd8\xff\xe0"), "jpg")
        self.assertEqual(detect_extension(b"RIFF\0\0\0\0WEBPVP8 "), "webp")
        self.assertEqual(detect_extension(b"\x1f\x8b\x08\x00"), "tgs")
        self.assertEqual(detect_extension(b"\x00\x00\x00\x1cftypmp42"), "mp4")
        self.assertEqual(detect_extension(b"OggS\x00"), "ogg")
        self.assertIsNone(detect_extension(b"\x12\x34\x56\x78"))


class DetectFrameCacheTest(unittest.TestCase):
    def test_custom_emoji_frames(self):
        self.assertEqual(detect_frame_cache(u32le(2) + u32le(20)), "custom emoji frames")
        self.assertEqual(detect_frame_cache(u32le(1) + u32le(20)), "custom emoji frames")

    def test_animated_sticker_frames(self):
        head = bytes.fromhex("0000000000000070000000700000020000000200")
        self.assertEqual(detect_frame_cache(head), "animated sticker frames")

    def test_streaming_chunks_are_not_frames(self):
        # A parts map with two parts: count 2, then a 128 KiB-aligned offset.
        self.assertIsNone(detect_frame_cache(u32le(1) + u32le(0)))
        self.assertIsNone(detect_frame_cache(u32le(2) + u32le(0)))
        self.assertIsNone(detect_frame_cache(u32le(2) + u32le(128 * 1024)))
        self.assertIsNone(detect_frame_cache(b"\x00\x00\x00\x1cftypmp42"))


if __name__ == "__main__":
    unittest.main()
