#!/usr/bin/env python3
"""Generate the deterministic Windows shell icon from Gilbreth's pulse mark."""

from __future__ import annotations

import argparse
import math
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = (
    ROOT / "crates" / "gilbreth-app" / "assets" / "windows" / "gilbreth.ico"
)
ICON_SIZES = (16, 24, 32, 48, 256)
SAMPLES_PER_AXIS = 4
DARKROOM = (21.0, 23.0, 27.0)
LIGHT_TRAIL = (242.0, 163.0, 60.0)


def _inside_circle(px: float, py: float, cx: float, cy: float, radius: float) -> bool:
    dx = px - cx
    dy = py - cy
    return dx * dx + dy * dy <= radius * radius


def _inside_rounded_rect(
    px: float, py: float, width: float, height: float, radius: float
) -> bool:
    nearest_x = min(max(px, radius), width - radius)
    nearest_y = min(max(py, radius), height - radius)
    dx = px - nearest_x
    dy = py - nearest_y
    return dx * dx + dy * dy <= radius * radius


def _rust_round(value: float) -> int:
    """Match Rust f64::round for the non-negative channel values used here."""

    return math.floor(value + 0.5)


def favicon_rgba(size: int) -> bytes:
    """Rasterize the exact 32-unit geometry used by gilbreth-app at runtime."""

    rgba = bytearray()
    scale = 32.0 / size
    sample_count = SAMPLES_PER_AXIS * SAMPLES_PER_AXIS

    for y in range(size):
        for x in range(size):
            red = green = blue = alpha = 0.0
            for sample_y in range(SAMPLES_PER_AXIS):
                for sample_x in range(SAMPLES_PER_AXIS):
                    px = (x + (sample_x + 0.5) / SAMPLES_PER_AXIS) * scale
                    py = (y + (sample_y + 0.5) / SAMPLES_PER_AXIS) * scale
                    if _inside_circle(px, py, 16.0, 16.0, 6.5):
                        color = LIGHT_TRAIL
                    elif _inside_rounded_rect(px, py, 32.0, 32.0, 7.0):
                        color = DARKROOM
                    else:
                        color = None
                    if color is not None:
                        red += color[0]
                        green += color[1]
                        blue += color[2]
                        alpha += 255.0
            rgba.extend(
                (
                    _rust_round(red / sample_count),
                    _rust_round(green / sample_count),
                    _rust_round(blue / sample_count),
                    _rust_round(alpha / sample_count),
                )
            )
    return bytes(rgba)


def _dib_image(size: int) -> bytes:
    rgba = favicon_rgba(size)
    xor = bytearray()
    mask_stride = ((size + 31) // 32) * 4
    mask = bytearray(mask_stride * size)

    for output_row, source_y in enumerate(range(size - 1, -1, -1)):
        for x in range(size):
            offset = (source_y * size + x) * 4
            red, green, blue, alpha = rgba[offset : offset + 4]
            xor.extend((blue, green, red, alpha))
            if alpha == 0:
                mask[output_row * mask_stride + x // 8] |= 0x80 >> (x % 8)

    header = struct.pack(
        "<IiiHHIIiiII",
        40,
        size,
        size * 2,
        1,
        32,
        0,
        len(xor),
        0,
        0,
        0,
        0,
    )
    return header + xor + mask


def build_ico() -> bytes:
    images = [_dib_image(size) for size in ICON_SIZES]
    directory_size = 6 + len(images) * 16
    offset = directory_size
    entries = bytearray()
    for size, image in zip(ICON_SIZES, images, strict=True):
        dimension = 0 if size == 256 else size
        entries.extend(
            struct.pack(
                "<BBBBHHII",
                dimension,
                dimension,
                0,
                0,
                1,
                32,
                len(image),
                offset,
            )
        )
        offset += len(image)
    return struct.pack("<HHH", 0, 1, len(images)) + entries + b"".join(images)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify the tracked ICO")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    expected = build_ico()
    output = args.output.resolve()
    if args.check:
        if not output.is_file() or output.read_bytes() != expected:
            parser.error(f"{output} is missing or stale; regenerate it without --check")
        print(f"Windows icon is current: {output}")
        return 0

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(expected)
    print(f"Wrote {output} ({len(expected)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
