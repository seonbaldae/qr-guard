"""PNG verification must include actual bounded pixel decoding."""

import base64
import struct
import zlib

import pytest

from app.worker import WorkerError, decode_png


def test_corrupt_idat_is_not_accepted_as_ready_png():
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))

    data = b"\x89PNG\r\n\x1a\n"
    data += chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
    data += chunk(b"IDAT", b"not-a-zlib-stream")
    data += chunk(b"IEND", b"")
    with pytest.raises(WorkerError, match="invalid_screenshot"):
        decode_png(base64.b64encode(data).decode())
