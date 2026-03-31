#!/usr/bin/env python3
"""Generate a metrics-only TTF font for PDF transparent text overlay.

Requires: pip install fonttools pyyaml
Source font: Noto Sans JP Regular (https://fonts.google.com/noto/specimen/Noto+Sans+JP)

Usage:
    python generate.py <source_ttf> <charset_yaml> <output_ttf>

Example:
    python generate.py NotoSansJP-Regular.ttf ../ndlocr-lite/src/config/NDLmoji.yaml ndlocr-metrics.ttf

The output font contains only glyph widths (no outlines), suitable for
invisible text layers in searchable PDFs. ~180 KB for 7000+ characters.
"""

import sys
import yaml
from fontTools.ttLib import TTFont
from fontTools.pens.ttGlyphPen import TTGlyphPen
from fontTools.fontBuilder import FontBuilder


def main():
    if len(sys.argv) != 4:
        print(__doc__)
        sys.exit(1)

    source_ttf, charset_yaml, output_ttf = sys.argv[1], sys.argv[2], sys.argv[3]

    with open(charset_yaml) as f:
        cfg = yaml.safe_load(f)
    charset = cfg["model"]["charset_train"]

    src = TTFont(source_ttf)
    src_cmap = src.getBestCmap()
    src_hmtx = src["hmtx"]
    upm = src["head"].unitsPerEm

    codepoints = sorted(cp for ch in charset if (cp := ord(ch)) in src_cmap)
    print(f"UPM: {upm}, charset: {len(charset)}, mapped: {len(codepoints)}")

    glyph_names = [".notdef"] + [f"uni{cp:04X}" for cp in codepoints]

    fb = FontBuilder(upm, isTTF=True)
    fb.setupGlyphOrder(glyph_names)
    fb.setupCharacterMap({cp: f"uni{cp:04X}" for cp in codepoints})

    # Empty glyf table (no outlines)
    fb.setupGlyf({})
    glyf = fb.font["glyf"]
    for name in glyph_names:
        pen = TTGlyphPen(None)
        glyf[name] = pen.glyph()

    # Horizontal metrics from source font
    metrics = {".notdef": (500, 0)}
    for cp in codepoints:
        w, _ = src_hmtx[src_cmap[cp]]
        metrics[f"uni{cp:04X}"] = (w, 0)
    fb.setupHorizontalMetrics(metrics)

    fb.setupHorizontalHeader(ascent=880, descent=-120)
    fb.setupNameTable({"familyName": "NDLOCRMetrics", "styleName": "Regular"})
    fb.setupOS2(sTypoAscender=880, sTypoDescender=-120, sTypoLineGap=0)
    fb.setupPost()

    fb.font.save(output_ttf)
    src.close()

    import os
    size = os.path.getsize(output_ttf)
    print(f"Output: {output_ttf} ({size:,} bytes, {size/1024:.1f} KB)")


if __name__ == "__main__":
    main()
