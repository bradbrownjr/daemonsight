#!/usr/bin/env python3
"""Make docs/images/social-preview.png (1280x640) from the Hosts screenshot, the name and the tagline.
Run scripts/screenshots.py first. Needs Pillow and the DejaVu fonts (any TTF will do: --font)."""
import argparse
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
BG, FG, MUTED = (13, 20, 36), (232, 236, 244), (150, 162, 184)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--font", default="/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf")
    ap.add_argument("--out", default=str(ROOT / "docs/images/social-preview.png"))
    a = ap.parse_args()
    img = Image.new("RGB", (1280, 640), BG)
    d = ImageDraw.Draw(img)
    logo = Image.open(ROOT / "assets/logo-dark-256.png").convert("RGBA").resize((96, 96))
    img.paste(logo, (64, 52), logo)
    d.text((176, 56), "DaemonSight", font=ImageFont.truetype(a.font, 56), fill=FG)
    d.text((176, 124), "Self-hosted security dashboard for Linux servers,", font=ImageFont.truetype(a.font, 26), fill=MUTED)
    d.text((176, 158), "Docker, Unraid and OPNsense", font=ImageFont.truetype(a.font, 26), fill=MUTED)
    shot = Image.open(ROOT / "docs/images/hosts.png").convert("RGB")
    w = 1152
    shot = shot.resize((w, round(shot.height * w / shot.width)), Image.LANCZOS)
    img.paste(shot.crop((0, 0, w, 640 - 220)), (64, 220))
    img.quantize(colors=128, dither=Image.Dither.NONE).save(a.out, optimize=True)


if __name__ == "__main__":
    main()
