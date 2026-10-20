"""Regenerate the web-app icons.

The icons are committed binaries, which is the one kind of file this project
otherwise does not have. This script is the source for them, so they can be
changed rather than only replaced.

    python3 tools/make_icons.py

Needs Pillow, which the app itself does NOT: the PNGs are committed assets,
so nothing at runtime gains a dependency. Pillow is a dev-time convenience
only, and the script says so rather than pretending otherwise.

    python3 -m pip install Pillow

The mark is an "M" for MChat, drawn as a polygon rather than typeset from a
font: a font would make the output depend on which fonts happened to be
installed on the machine that generated it, and the icon would differ between
them. A path is the same everywhere, and it is the shape itself rather than a
rendering of it.

The tile is in the header colour (--header, #171717) and the mark in the
header-ink colour (--header-ink, #fafafa), the same two the app uses
everywhere else.
"""
import sys
from pathlib import Path

try:
    from PIL import Image, ImageDraw
except ImportError:
    sys.exit("This script needs Pillow (pip install Pillow). The app itself "
             "does not: the generated PNGs are committed.")

STATIC = Path(__file__).resolve().parent.parent / "app" / "static"
BG = (0x17, 0x17, 0x17)      # --header
FG = (0xFA, 0xFA, 0xFA)      # --header-ink
SS = 8                        # supersample factor, downscaled at the end


def m_polygon(u, v, w, h):
    """An M in the box (u, v, w, h), as one closed polygon.

    Two stems and a V: the V dips to 68% of the height and the stems are
    18% wide, so the letter reads as a mark rather than as text.
    """
    def X(fx):
        return u + fx * w

    def Y(fy):
        return v + fy * h

    return [
        (X(0.08), Y(1.00)),   # bottom-left
        (X(0.08), Y(0.00)),   # top-left
        (X(0.30), Y(0.00)),   # top-left inner
        (X(0.50), Y(0.46)),   # centre notch
        (X(0.70), Y(0.00)),   # top-right inner
        (X(0.92), Y(0.00)),   # top-right
        (X(0.92), Y(1.00)),   # bottom-right
        (X(0.74), Y(1.00)),   # bottom-right inner
        (X(0.74), Y(0.30)),   # right stem, inner, lower
        (X(0.50), Y(0.68)),   # centre point
        (X(0.26), Y(0.30)),   # left stem, inner, lower
        (X(0.26), Y(1.00)),   # bottom-left inner
    ]


def render(size, maskable):
    """maskable: the background fills the canvas and the mark stays inside the
    safe zone, because the platform may crop the icon to any shape."""
    s = size * SS
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    if maskable:
        draw.rectangle([0, 0, s, s], fill=BG)
        inner = s * 0.78
        off = (s - inner) / 2
        draw.polygon(m_polygon(off, off, inner, inner), fill=FG)
    else:
        pad = s * 0.06
        draw.rounded_rectangle([pad, pad, s - pad, s - pad], radius=s * 0.22,
                               fill=BG)
        draw.polygon(m_polygon(s * 0.16, s * 0.22, s * 0.68, s * 0.56), fill=FG)
    return img.resize((size, size), Image.LANCZOS)


def main() -> None:
    for size in (192, 512):
        for maskable, suffix in ((False, ""), (True, "-maskable")):
            path = STATIC / f"icon-{size}{suffix}.png"
            render(size, maskable).save(path, "PNG", optimize=True)
            print(f"  {path.name}  {path.stat().st_size} bytes")


if __name__ == "__main__":
    main()
