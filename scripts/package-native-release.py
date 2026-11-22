#!/usr/bin/env python3
"""Package native release binaries and licenses in a flat archive."""

import argparse
import gzip
import os
from pathlib import Path
import re
import shutil
import stat
import tarfile
import tempfile
import time
import zipfile


def write_tarball(path, files, epoch):
    with (
        path.open("wb") as output,
        gzip.GzipFile(fileobj=output, filename="", mode="wb", mtime=0) as compressed,
        tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive,
    ):
        for source, mode in files:
            entry = tarfile.TarInfo(source.name)
            entry.mode = mode
            entry.size = source.stat().st_size
            entry.mtime = epoch
            with source.open("rb") as data:
                archive.addfile(entry, data)


def write_zip(path, files, epoch):
    # ZIP timestamps range from 1980-01-01 through 2107-12-31.
    timestamp = time.gmtime(max(315532800, min(epoch, 4354819198)))[:6]
    with zipfile.ZipFile(path, "w") as archive:
        for source, mode in files:
            entry = zipfile.ZipInfo(source.name, timestamp)
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.create_system = 3
            entry.external_attr = (stat.S_IFREG | mode) << 16
            with source.open("rb") as data, archive.open(entry, "w") as compressed:
                shutil.copyfileobj(data, compressed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version")
    parser.add_argument("target", choices=("macos-universal", "windows-x86_64", "windows-arm64"))
    parser.add_argument("binaries", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+_-]*", args.version):
        parser.error(f"invalid package version: {args.version}")
    epoch = os.environ.get("SOURCE_DATE_EPOCH", "0")
    if not re.fullmatch(r"[0-9]+", epoch):
        parser.error("SOURCE_DATE_EPOCH must be a nonnegative integer")

    windows = args.target.startswith("windows-")
    suffix = ".exe" if windows else ""
    extension = "zip" if windows else "tar.gz"
    binaries = [(args.binaries / (name + suffix), 0o755) for name in ("doubletake", "doubletake-ctl")]
    root = Path(__file__).resolve().parent.parent
    files = binaries + [(root / name, 0o644) for name in ("LICENSE", "COPYING.GPL")]
    for source, _ in files:
        if not source.is_file() or source.stat().st_size == 0:
            parser.error(f"missing or empty package file: {source}")

    args.output.mkdir(parents=True, exist_ok=True)
    name = f"doubletake-{args.version}-{args.target}.{extension}"
    with tempfile.TemporaryDirectory(dir=args.output) as temp:
        archive = Path(temp) / name
        writer = write_zip if windows else write_tarball
        writer(archive, files, int(epoch))
        archive.chmod(0o644)
        archive.replace(args.output / name)


if __name__ == "__main__":
    main()
