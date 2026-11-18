"""Compare a PNG cover and stego image using whole-image RGB statistics.

Whole-image statistics are useful mainly for heavily filled images: a low-fill
message (under 10% of available RGB bits) will usually not stand out. Around
50% fill, LSB replacement can substantially lower the pairs-of-values statistic.
Cover content and embedding mode matter; this is a classroom experiment, not a
reliable detector, proof of absence, p-value, or automatic detection threshold.
LSB matching need not produce the same histogram effect as replacement.

Run two experiments on the same synthetic cover, at low and high fill, to show
both the limits of this statistic and the limits of steganography. Fill counts
embedded bits, including the length header; it is NOT the fraction of channels
changed. Alpha is ignored. LSB outputs are black/white R, G, B planes placed
left to right. The statistic uses ONLY the even term of each pair, exactly as
specified in Step 11 (half the conventional two-term Pearson sum).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
from PIL import Image


def read_rgb(path: Path) -> np.ndarray:
    """Load a bounded, single-frame PNG as RGB without changing the input."""
    with Image.open(path) as image:
        if image.format != "PNG" or getattr(image, "n_frames", 1) != 1:
            raise ValueError("Inputs must be single-frame PNG images")
        # SECURITY: bound decompression and array allocation for untrusted PNGs.
        if not (0 < image.width <= 4096 and 0 < image.height <= 4096):
            raise ValueError("Image dimensions must be between 1 and 4096")
        return np.array(image.convert("RGB"), dtype=np.uint8)


def pairs_chi_square(rgb: np.ndarray) -> float:
    """Return the specified even-term pairs-of-values statistic, without a p-value."""
    histogram = np.bincount(rgb.reshape(-1), minlength=256).astype(np.float64)
    even = histogram[::2]
    expected = (even + histogram[1::2]) / 2
    nonempty = expected > 0
    return float(np.sum((even[nonempty] - expected[nonempty]) ** 2
                        / expected[nonempty]))


def lsb_planes(rgb: np.ndarray) -> np.ndarray:
    """Make a grayscale triptych containing each channel's low bit."""
    return np.concatenate([(rgb[:, :, i] & 1) * 255 for i in range(3)], axis=1)


def analyze(original_path: Path, stego_path: Path, output_dir: Path) -> dict:
    """Measure RGB differences and save reproducible, derived image artifacts."""
    original, stego = read_rgb(original_path), read_rgb(stego_path)
    if original.shape != stego.shape:
        raise ValueError("Original and stego images must have identical dimensions")
    changed = original != stego
    count = int(np.count_nonzero(changed))
    report = {
        "width": original.shape[1], "height": original.shape[0],
        "channel_values": int(original.size), "changed_channels": count,
        "changed_percent": count / original.size * 100,
        "original_chi_square": pairs_chi_square(original),
        "stego_chi_square": pairs_chi_square(stego),
        "statistic": "Step 11 even-term pairs-of-values sum; RGB; no p-value",
    }
    # SECURITY: generated evidence must never overwrite either input image.
    inputs = {original_path.resolve(), stego_path.resolve()}
    names = ("diff.png", "original_lsb.png", "stego_lsb.png", "report.json")
    if any((output_dir / name).resolve() in inputs for name in names):
        raise ValueError("Output artifacts must not overwrite an input image")
    output_dir.mkdir(parents=True, exist_ok=True)
    Image.fromarray(changed.astype(np.uint8) * 255).save(output_dir / "diff.png")
    Image.fromarray(lsb_planes(original)).save(output_dir / "original_lsb.png")
    Image.fromarray(lsb_planes(stego)).save(output_dir / "stego_lsb.png")
    (output_dir / "report.json").write_text(json.dumps(report, indent=2) + "\n",
                                           encoding="utf-8")
    return report


def main(argv: list[str] | None = None) -> int:
    """Run the two-image comparison, defaulting to the required evidence folder."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("original", type=Path)
    parser.add_argument("stego", type=Path)
    parser.add_argument("--output-dir", type=Path, default=Path("evidence"))
    args = parser.parse_args(argv)
    try:
        report = analyze(args.original, args.stego, args.output_dir)
    except (OSError, ValueError, Image.DecompressionBombError) as error:
        parser.error(str(error))
    print(f"Image size: {report['width']} x {report['height']} (RGB; alpha ignored)")
    print(f"Changed channel values: {report['changed_channels']} / "
          f"{report['channel_values']} ({report['changed_percent']:.6f}%)")
    print(f"Original pairs-of-values chi-square: {report['original_chi_square']:.6f}")
    print(f"Stego pairs-of-values chi-square: {report['stego_chi_square']:.6f}")
    print("Statistic: even term only; no p-value or automatic detection threshold.")
    print(f"Saved diff.png, original_lsb.png, stego_lsb.png and report.json in {args.output_dir}")
    print("LSB images: black/white R, G, B planes from left to right.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
