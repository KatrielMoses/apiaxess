#!/usr/bin/env python3
"""Renders the APIaxess application icon set from the identity kit's geometry.

The identity kit (`assets/brand/Apiaxess Logo Kit.html`, Identity kit / v2.1)
defines the app icon as a named identity element, "App icon 1024":

    a 200x200 plate, border-radius 46, background Ink #0D0D0D, holding the
    128x128 mark (viewBox 0 0 200 200) with the bracket and outer chevron in
    #FFFFFF and the shaft and inner arrowhead in Signal Blue #2D7FF9.

Every constant below is transcribed from that block, so the icon this script
emits *is* the kit's icon rather than an approximation of it. The kit also
states that the mark is "simplified at small sizes" and gives the simplified
forms; SMALL_MARK is the kit's 32px form, used for the icon entries too small
to carry the full four-path mark.

Strokes are rendered by stamping each segment as a thick line plus a disc at
every vertex, which is exactly SVG's `stroke-linecap: round` /
`stroke-linejoin: round`. Everything is drawn at 8x and box-filtered down, so
the antialiasing matches a vector rasterizer.

Run from the repository root:

    python tools/brand/render_icons.py
"""

from __future__ import annotations

import pathlib

from PIL import Image, ImageDraw

# ------------------------------------------------------------------ #
# Kit values
# ------------------------------------------------------------------ #

INK = (0x0D, 0x0D, 0x0D, 0xFF)
PAPER = (0xFF, 0xFF, 0xFF, 0xFF)
SIGNAL_BLUE = (0x2D, 0x7F, 0xF9, 0xFF)

#: Plate corner radius as a fraction of the plate edge (46 / 200).
PLATE_RADIUS = 46 / 200
#: Mark edge as a fraction of the plate edge (128 / 200).
MARK_SCALE = 128 / 200

#: The primary mark, kit geometry: 200-unit box, 14-unit strokes. Paths are
#: listed in the kit's paint order — later paths sit over earlier ones.
FULL_MARK = [
    ([(138, 60), (100, 22), (22, 100), (100, 178), (138, 140)], "fg", 14),
    ([(50, 100), (140, 100)], "accent", 14),
    ([(118, 78), (142, 100), (118, 122)], "accent", 14),
    ([(168, 78), (142, 100), (168, 122)], "fg", 14),
]

#: The kit's simplified 32px form: the outer chevron is dropped and the
#: remaining strokes thicken to 20 units so the shape survives the pixel grid.
SMALL_MARK = [
    ([(134, 58), (100, 24), (24, 100), (100, 176), (134, 142)], "fg", 20),
    ([(56, 100), (140, 100)], "accent", 20),
    ([(116, 76), (144, 100), (116, 124)], "accent", 20),
]

#: Below this edge length the plate is too small for the full mark.
SMALL_MARK_BELOW = 48

SUPERSAMPLE = 8

REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parents[2]
DESKTOP_ICONS = REPOSITORY_ROOT / "apps" / "desktop" / "icons"
GUI_PUBLIC = REPOSITORY_ROOT / "apps" / "gui" / "public"


# ------------------------------------------------------------------ #
# Stroke rasterisation
# ------------------------------------------------------------------ #


def stroke_path(
    draw: ImageDraw.ImageDraw,
    points: list[tuple[float, float]],
    colour: tuple[int, int, int, int],
    width: float,
    origin: float,
    scale: float,
) -> None:
    """Stamps one round-capped, round-joined polyline."""
    device = [(origin + x * scale, origin + y * scale) for x, y in points]
    thickness = width * scale
    radius = thickness / 2

    for start, end in zip(device, device[1:]):
        draw.line([start, end], fill=colour, width=max(1, round(thickness)))
    for x, y in device:
        draw.ellipse(
            [x - radius, y - radius, x + radius, y + radius],
            fill=colour,
        )


def render_mark(
    draw: ImageDraw.ImageDraw,
    paths: list[tuple[list[tuple[float, float]], str, float]],
    origin: float,
    scale: float,
    foreground: tuple[int, int, int, int],
    accent: tuple[int, int, int, int],
) -> None:
    for points, tone, width in paths:
        stroke_path(
            draw,
            points,
            foreground if tone == "fg" else accent,
            width,
            origin,
            scale,
        )


# ------------------------------------------------------------------ #
# Icon composition
# ------------------------------------------------------------------ #


def app_icon(edge: int) -> Image.Image:
    """The kit's app icon: Ink plate, white bracket, Signal Blue shaft."""
    canvas = edge * SUPERSAMPLE
    image = Image.new("RGBA", (canvas, canvas), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)

    draw.rounded_rectangle(
        [0, 0, canvas - 1, canvas - 1],
        radius=PLATE_RADIUS * canvas,
        fill=INK,
    )

    mark_edge = MARK_SCALE * canvas
    render_mark(
        draw,
        FULL_MARK if edge >= SMALL_MARK_BELOW else SMALL_MARK,
        origin=(canvas - mark_edge) / 2,
        scale=mark_edge / 200,
        foreground=PAPER,
        accent=SIGNAL_BLUE,
    )

    return image.resize((edge, edge), Image.LANCZOS)


def favicon_bitmap(edge: int) -> Image.Image:
    """The kit's favicon: the bare mark on transparency, Ink on light chrome."""
    canvas = edge * SUPERSAMPLE
    image = Image.new("RGBA", (canvas, canvas), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)

    render_mark(
        draw,
        FULL_MARK if edge >= SMALL_MARK_BELOW else SMALL_MARK,
        origin=0,
        scale=canvas / 200,
        foreground=INK,
        accent=SIGNAL_BLUE,
    )

    return image.resize((edge, edge), Image.LANCZOS)


def main() -> None:
    DESKTOP_ICONS.mkdir(parents=True, exist_ok=True)
    GUI_PUBLIC.mkdir(parents=True, exist_ok=True)

    # Tauri's declared bundle icons, plus the 512 the .deb installs into
    # hicolor/512x512 and the 1024 master the kit names.
    for name, edge in (
        ("32x32.png", 32),
        ("128x128.png", 128),
        ("128x128@2x.png", 256),
        ("icon.png", 512),
        ("icon-1024.png", 1024),
    ):
        app_icon(edge).save(DESKTOP_ICONS / name, format="PNG")
        print(f"wrote {name} ({edge}px)")

    # Windows wants every shell size in one container; render each natively so
    # no entry is a resize of another.
    ico_sizes = [16, 24, 32, 48, 64, 128, 256]
    frames = [app_icon(edge) for edge in ico_sizes]
    frames[0].save(
        DESKTOP_ICONS / "icon.ico",
        format="ICO",
        sizes=[(edge, edge) for edge in ico_sizes],
        append_images=frames[1:],
    )
    print(f"wrote icon.ico ({', '.join(str(s) for s in ico_sizes)})")

    favicon_sizes = [16, 32, 48]
    favicons = [favicon_bitmap(edge) for edge in favicon_sizes]
    favicons[0].save(
        GUI_PUBLIC / "favicon.ico",
        format="ICO",
        sizes=[(edge, edge) for edge in favicon_sizes],
        append_images=favicons[1:],
    )
    print(f"wrote favicon.ico ({', '.join(str(s) for s in favicon_sizes)})")


if __name__ == "__main__":
    main()
