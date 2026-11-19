"""Publish the existing Flask static files at Vercel's /static URL."""

from pathlib import Path
from shutil import copytree


root = Path(__file__).resolve().parent
copytree(root / "static", root / "public" / "static", dirs_exist_ok=True)
