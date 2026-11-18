"""Known-value and CLI checks for the Step 11 analysis evidence."""
import json
from pathlib import Path
import subprocess
import sys

import numpy as np
from PIL import Image
import pytest

from tools.stego_analysis import analyze, pairs_chi_square


def test_statistic_uses_exact_even_term_formula_and_skips_empty_pairs():
    # Pair (0,1): (3-2)^2/2=.5; pair (2,3): (0-1)^2/1=1.
    channels = np.array([0, 0, 0, 1, 3, 3], dtype=np.uint8)
    assert pairs_chi_square(channels) == pytest.approx(1.5)
    assert pairs_chi_square(np.array([0, 1, 2, 3], dtype=np.uint8)) == 0


def test_cli_counts_channels_and_writes_binary_diff_and_lsb_planes(tmp_path):
    cover = np.zeros((2, 2, 3), dtype=np.uint8)
    stego = cover.copy()
    stego[0, 1, 2] = 1
    for name, pixels in (("cover", cover), ("stego", stego)):
        Image.fromarray(pixels).save(tmp_path / f"{name}.png")
    result = subprocess.run(
        [sys.executable, str(Path(__file__).resolve().parents[1] / "tools/stego_analysis.py"),
         "cover.png", "stego.png"], cwd=tmp_path, capture_output=True, text=True,
        check=True)
    assert "2 x 2" in result.stdout and "1 / 12 (8.333333%)" in result.stdout
    evidence = tmp_path / "evidence"
    report = json.loads((evidence / "report.json").read_text())
    assert report["changed_channels"] == 1
    assert report["original_chi_square"] == 6
    assert report["stego_chi_square"] == pytest.approx(25 / 6)
    with Image.open(evidence / "diff.png") as difference:
        mask = np.array(difference)
        assert np.count_nonzero(mask) == 1 and mask[0, 1, 2] == 255
    for name in ("original_lsb.png", "stego_lsb.png"):
        with Image.open(evidence / name) as plane:
            assert plane.mode == "L" and plane.size == (6, 2)
            assert set(np.array(plane).reshape(-1)) <= {0, 255}
    with Image.open(evidence / "stego_lsb.png") as plane:
        assert np.array(plane)[0, 5] == 255  # B plane is the rightmost panel.


def test_identical_images_have_zero_changed_channels(tmp_path):
    image = tmp_path / "image.png"
    Image.new("RGBA", (2, 3), (100, 101, 102, 255)).save(image)
    report = analyze(image, image, tmp_path / "output")
    assert report["changed_channels"] == report["changed_percent"] == 0
    assert report["original_chi_square"] == report["stego_chi_square"]


def test_outputs_cannot_overwrite_input_images(tmp_path):
    image = tmp_path / "diff.png"
    Image.new("RGB", (2, 2), (10, 20, 30)).save(image)
    original_bytes = image.read_bytes()
    with pytest.raises(ValueError, match="overwrite"):
        analyze(image, image, tmp_path)
    assert image.read_bytes() == original_bytes


@pytest.mark.parametrize("invalid", ["dimensions", "format", "corrupt"])
def test_invalid_pair_produces_no_misleading_artifacts(tmp_path, invalid):
    cover, other, output = tmp_path / "cover.png", tmp_path / "other.png", tmp_path / "out"
    Image.new("RGB", (2, 2)).save(cover)
    if invalid == "corrupt":
        other.write_bytes(b"not a PNG")
    else:
        Image.new("RGB", (3, 2) if invalid == "dimensions" else (2, 2)).save(
            other, format="JPEG" if invalid == "format" else "PNG")
    with pytest.raises((ValueError, OSError)):
        analyze(cover, other, output)
    assert not output.exists()
