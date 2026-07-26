import importlib.util
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GENERATOR_PATH = ROOT / "scripts" / "generate_windows_icon.py"
ICON_PATH = ROOT / "crates" / "gilbreth-app" / "assets" / "windows" / "gilbreth.ico"


def _load_generator():
    spec = importlib.util.spec_from_file_location(
        "generate_windows_icon", GENERATOR_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _entries(payload: bytes) -> list[tuple[int, int, int, int, int]]:
    reserved, image_type, count = struct.unpack_from("<HHH", payload)
    assert (reserved, image_type) == (0, 1)
    entries = []
    for index in range(count):
        (
            width,
            height,
            color_count,
            reserved_byte,
            planes,
            bit_count,
            byte_count,
            offset,
        ) = struct.unpack_from("<BBBBHHII", payload, 6 + index * 16)
        assert color_count == reserved_byte == 0
        assert planes == 1
        entries.append(
            (
                256 if width == 0 else width,
                256 if height == 0 else height,
                bit_count,
                byte_count,
                offset,
            )
        )
    return entries


def test_tracked_windows_icon_is_deterministic() -> None:
    generator = _load_generator()

    assert ICON_PATH.read_bytes() == generator.build_ico()


def test_windows_icon_has_the_required_32_bit_sizes_and_geometry() -> None:
    generator = _load_generator()
    payload = ICON_PATH.read_bytes()
    entries = _entries(payload)

    assert [(width, height) for width, height, _, _, _ in entries] == [
        (size, size) for size in generator.ICON_SIZES
    ]
    assert all(bit_count == 32 for _, _, bit_count, _, _ in entries)

    for size in generator.ICON_SIZES:
        rgba = generator.favicon_rgba(size)

        def pixel(x: int, y: int) -> bytes:
            offset = (y * size + x) * 4
            return rgba[offset : offset + 4]

        center = size // 2
        assert pixel(center, center) == bytes((242, 163, 60, 255))
        assert pixel(center, max(1, size // 8)) == bytes((21, 23, 27, 255))
        assert pixel(0, 0)[3] == 0

    for width, height, _, byte_count, offset in entries:
        dib_size, dib_width, dib_height, planes, bit_count = struct.unpack_from(
            "<IiiHH", payload, offset
        )
        assert dib_size == 40
        assert (dib_width, dib_height) == (width, height * 2)
        assert (planes, bit_count) == (1, 32)
        assert offset + byte_count <= len(payload)
