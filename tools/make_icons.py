"""Regenerate the web-app icons.

The icons are committed binaries, which is the one kind of file this project
otherwise does not have. This script is the source for them, so they can be
changed rather than only replaced.

    python3 tools/make_icons.py

Needs Pillow, which the app itself does NOT: the PNGs are committed assets,
so nothing at runtime gains a dependency. Pillow is a dev-time convenience
only, and the script says so rather than pretending otherwise.

    python3 -m pip install Pillow

The mark is the app's own shape: a rounded tile in the header colour
(--header, #171717) with a speech bubble in the header-ink colour
(--header-ink, #fafafa), plus a maskable variant whose mark sits inside the
central 80% so a launcher that crops to any shape cannot cut it off.
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


def bubble(draw, size, colour):
    """A speech bubble: a rounded rectangle with a tail at the lower left."""
    m = size * 0.24
    x0, y0, x1, y1 = m, size * 0.27, size - m, size * 0.62
    radius = (x1 - x0) * 0.28
    draw.rounded_rectangle([x0, y0, x1, y1], radius=radius, fill=colour)
    draw.polygon([(x0 + (x1 - x0) * 0.12, y1 - radius * 0.6),
                  (x0 + (x1 - x0) * 0.30, y1 - radius * 0.6),
                  (x0 + (x1 - x0) * 0.04, y1 + size * 0.13)], fill=colour)


def render(size, maskable):
    """maskable: the background fills the canvas and the mark stays inside the
    safe zone, because the platform may crop the icon to any shape."""
    s = size * SS
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    if maskable:
        draw.rectangle([0, 0, s, s], fill=BG)
        inner = s * 0.80
        off = (s - inner) / 2
        tile = Image.new("RGBA", (int(inner), int(inner)), (0, 0, 0, 0))
        bubble(ImageDraw.Draw(tile), inner, FG)
        img.alpha_composite(tile, (int(off), int(off)))
    else:
        pad = s * 0.06
        draw.rounded_rectangle([pad, pad, s - pad, s - pad],
                               radius=s * 0.22, fill=BG)
        bubble(draw, s, FG)
    return img.resize((size, size), Image.LANCZOS)


def main() -> None:
    for size in (192, 512):
        for maskable, suffix in ((False, ""), (True, "-maskable")):
            path = STATIC / f"icon-{size}{suffix}.png"
            render(size, maskable).save(path, "PNG", optimize=True)
            print(f"  {path.name}  {path.stat().st_size} bytes")


if __name__ == "__main__":
    main()
