#!/usr/bin/env python3
"""
Download public datasets used by the Telco Multi-Agent AIOps Platform.

Sources (research / open access):
  - Loghub (Zenodo): Apache, Linux, Zookeeper, SSH logs
  - SFU CNL: RIPE BGP anomaly feature CSVs (WannaCrypt, Slammer, ...)

Usage:
  python scripts/download_datasets.py
  python scripts/prepare_datasets.py
"""

from __future__ import annotations

import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "datasets" / "raw"
EXTRACTED = ROOT / "datasets" / "extracted"

DOWNLOADS = [
    (
        "Apache.tar.gz",
        "https://zenodo.org/api/records/8196385/files/Apache.tar.gz/content",
    ),
    (
        "Linux.tar.gz",
        "https://zenodo.org/api/records/8196385/files/Linux.tar.gz/content",
    ),
    (
        "Zookeeper.tar.gz",
        "https://zenodo.org/api/records/8196385/files/Zookeeper.tar.gz/content",
    ),
    (
        "SSH.tar.gz",
        "https://zenodo.org/api/records/8196385/files/SSH.tar.gz/content",
    ),
    (
        "BGP_RIPE_anomaly_csv.zip",
        "https://www.sfu.ca/~ljilja/cnl/projects/BGP_datasets/"
        "BGP_RIPE_datasets_for_anomaly_detection_csv_revised_19022021.zip",
    ),
]


def curl(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and dest.stat().st_size > 1000:
        print(f"[skip] {dest.name} already present")
        return
    print(f"[get]  {dest.name}")
    subprocess.run(
        ["curl", "-L", "--fail", "--retry", "3", "-o", str(dest), url],
        check=True,
    )


def extract_all() -> None:
    EXTRACTED.mkdir(parents=True, exist_ok=True)
    for name, _ in DOWNLOADS:
        path = RAW / name
        if not path.exists():
            continue
        if name.endswith(".tar.gz"):
            if name.startswith("SSH"):
                target = EXTRACTED / "ssh"
                target.mkdir(parents=True, exist_ok=True)
                with tarfile.open(path, "r:gz") as tf:
                    tf.extractall(target)
            else:
                with tarfile.open(path, "r:gz") as tf:
                    tf.extractall(EXTRACTED)
            print(f"[untar] {name}")
        elif name.endswith(".zip"):
            target = EXTRACTED / "bgp_ripe_csv"
            target.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(path) as zf:
                zf.extractall(target)
            print(f"[unzip] {name}")


def main() -> int:
    try:
        for name, url in DOWNLOADS:
            curl(url, RAW / name)
        extract_all()
    except subprocess.CalledProcessError as exc:
        print(f"Download failed: {exc}", file=sys.stderr)
        return 1
    print("Done. Next: python scripts/prepare_datasets.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
