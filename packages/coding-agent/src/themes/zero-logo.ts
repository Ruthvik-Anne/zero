/**
 * Pre-rendered ASCII versions of the Zero mark.
 *
 * Source: assets/brand/zero-mark.svg
 * Re-render at any width: `uv run scripts/render-logo.py --width N`
 * (hand-tuned here since cairosvg has no native cairo lib on this box —
 * re-check against a real render once that toolchain is available)
 */

/** ~11 rows x 20 cols. The default brand mark — an open ring with an orbiting mark, splash-ready. */
export const ZERO_LOGO = `     ▄▄████████▄▄
   ▄██▀▀      ▀▀██▄
  ██▀            ▀██
 ██                ██
 ██                ██
 ██                ██
 ██                ██
  ██▄            ▄██
   ▀██▄▄      ▄▄██▀
      ▀▀     ▀▀
         ▄▄`;
