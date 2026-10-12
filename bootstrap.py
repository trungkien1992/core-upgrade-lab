#!/usr/bin/env python3
"""Download and verify the pinned official Linux x86_64 releases for Core Upgrade Lab."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parent
PINNED_GUIX_COMMIT = "cdac1b3a0bf6ee3d5e688a6075e6168e275d9a4a"
BUILDER_FINGERPRINT = "152812300785C96444D3334D17565732E08E5E41"
RELEASES = {
    "31.1": {
        "url": "https://bitcoincore.org/bin/bitcoin-core-31.1/bitcoin-31.1-x86_64-linux-gnu.tar.gz",
        "sha256": "b80d9c3e04da78fb6f0569685673418cf686fadba9042d926d13fb87ff503f9e",
    },
    "32.0rc3": {
        "url": "https://bitcoincore.org/bin/bitcoin-core-32.0/test.rc3/bitcoin-32.0rc3-x86_64-linux-gnu.tar.gz",
        "sha256": "87c92cd7e1bc41e6fcc9d7739a4a314ed1f8dde67e68985892338b1be797bdac",
    },
}


def digest(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def download(url, path):
    temporary = path.with_suffix(path.suffix + ".part")
    req = urllib.request.Request(url, headers={"User-Agent": "Core-Upgrade-Lab/0.1"})
    with urllib.request.urlopen(req, timeout=60) as source, temporary.open("wb") as target:
        while chunk := source.read(1024 * 1024):
            target.write(chunk)
    temporary.replace(path)


def install_archive(archive, destination, release):
    """Reuse only an executable that matches the signed archive; never overwrite it."""
    member = f"bitcoin-{release}/bin/bitcoind"
    binary = destination / member
    with tarfile.open(archive) as source:
        with source.extractfile(member) as executable:
            expected = hashlib.file_digest(executable, "sha256").hexdigest()
        if destination.exists() or destination.is_symlink():
            if destination.is_symlink() or not destination.is_dir():
                raise ValueError(f"Extraction target is not a regular directory: {destination}")
            if binary.is_symlink() or not binary.is_file() or digest(binary) != expected:
                raise ValueError(f"Existing bitcoind does not match the verified archive: {binary}; choose a new directory.")
        else:
            with tempfile.TemporaryDirectory(prefix=f".{release}-", dir=destination.parent) as tmp:
                staging = Path(tmp) / "extracted"
                staging.mkdir()
                source.extractall(staging, filter="data")
                if digest(staging / member) != expected:
                    raise ValueError("Extracted executable differs from the verified archive")
                staging.rename(destination)
    return binary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", default="vendor")
    args = parser.parse_args(argv)
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "AMD64"}:
        parser.error("The pinned bootstrap is Linux x86_64 only; other platforms need separately verified binaries.")
    root = Path(args.directory).resolve()
    root.mkdir(parents=True, exist_ok=True)
    records = []
    trusted = ROOT / "provenance"
    with tempfile.TemporaryDirectory(prefix="core-lab-verify-") as tmp:
        keyring = Path(tmp) / "public-key.gpg"
        subprocess.run(["gpg", "--batch", "--dearmor", "--output", str(keyring),
                        str(trusted / "achow101.gpg")], check=True, capture_output=True)
        for release, spec in RELEASES.items():
            manifest = trusted / f"{release}.SHA256SUMS"
            signature = trusted / f"{release}.SHA256SUMS.asc"
            result = subprocess.run(["gpgv", "--keyring", str(keyring), "--status-fd", "1",
                                     str(signature), str(manifest)],
                                    capture_output=True, text=True)
            valid = [line for line in result.stdout.splitlines()
                     if line.startswith("[GNUPG:] VALIDSIG ")]
            if result.returncode or not valid or not all(
                line.split()[2] == BUILDER_FINGERPRINT for line in valid
            ):
                raise ValueError(f"Signature verification failed for {release}: {result.stderr}")
            filename = spec["url"].rsplit("/", 1)[-1]
            signed_digest = next(line.split()[0] for line in manifest.read_text().splitlines()
                                 if line.split()[-1] == filename)
            if signed_digest != spec["sha256"]:
                raise ValueError(f"Signed manifest and pinned checksum disagree for {release}")
            archive = root / filename
            if not archive.is_file():
                print(f"Downloading {filename}", flush=True)
                download(spec["url"], archive)
            if digest(archive) != signed_digest:
                raise ValueError(f"Archive hash mismatch for {release}")
            destination = root / release
            binary = install_archive(archive, destination, release)
            record = {
                "release": release, "archive": filename, "sha256": signed_digest,
                "manifest_sha256": digest(manifest), "binary_sha256": digest(binary),
                "binary_matches_signed_archive": True,
                "signing_fingerprint": BUILDER_FINGERPRINT,
                "valid_signature": valid, "guix_source_commit": PINNED_GUIX_COMMIT,
                "url": spec["url"],
                "trust_note": "Key is pinned from the official guix.sigs repository; "
                              "fingerprint identity was not independently verified out of band.",
            }
            records.append(record)
            print(f"Verified {release}: {signed_digest}", flush=True)
    (root / "provenance.json").write_text(json.dumps(records, indent=2) + "\n")
    print(f"Ready: {root}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"{type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(2)
