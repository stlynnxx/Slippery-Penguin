"""
updatehelpers.py - self-update machinery for Slippery Penguin.

Server contract
---------------
GET {UPDATE_URL}{current_version}

Responds with JSON:
    {
      "latest": "2.3.8",
      "url":    "https://.../slipperypenguin-2.3.8.tar.gz",
      "sha256": "<sha256 hex digest of that tarball>"
    }

Any network failure or malformed payload is treated as "no update available"
rather than a fatal error.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tarfile
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from rich.console import Console
console = Console()
UPDATE_URL = "https://eclecticelectronics.fly.dev/api/check-update/"

# Only these may be written into the install directory by an update.
# Everything else in the tarball is ignored. This is the primary defence
# against a compromised or malformed release package.
ALLOWED_FILES = frozenset({
    "slipperypenguin.py",
    "art.txt",
    "flags.json",
})

# Must be present in the tarball or the package is rejected as incomplete.
REQUIRED_FILES = ("slipperypenguin.py", "art.txt", "flags.json")

_TIMEOUT = 10
_CHUNK = 65536


def parse_version(text):
    """'2.3.10' -> (2, 3, 10).

    Comparing version strings directly ranks '2.3.10' below '2.3.9'.
    Splitting into integers makes the comparison numeric.
    """
    parts = []
    for piece in str(text).strip().split("."):
        digits = "".join(ch for ch in piece if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def check_for_update(current_version):
    """Ask the server what the latest version is. Returns dict or None."""
    try:
        request = urllib.request.Request(
            UPDATE_URL + str(current_version),
            headers={"User-Agent": f"SlipperyPenguin/{current_version}"},
        )
        with urllib.request.urlopen(request, timeout=_TIMEOUT) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, json.JSONDecodeError, OSError) as exc:
        console.print(f"[red]Could not reach update server: {exc}[/red]")
        return None

    if not isinstance(payload, dict):
        console.print("[red]Update server returned an unexpected payload.[/red]")
        return None

    return payload


def download_release(url, expected_hash):
    """Download the tarball and verify its SHA-256. Returns path or None."""
    fd, tmp_path = tempfile.mkstemp(suffix=".tar.gz")
    os.close(fd)
    hasher = hashlib.sha256()

    try:
        with urllib.request.urlopen(url, timeout=_TIMEOUT) as response, \
                open(tmp_path, "wb") as out:
            while True:
                chunk = response.read(_CHUNK)
                if not chunk:
                    break
                out.write(chunk)
                hasher.update(chunk)

        actual = hasher.hexdigest()
        if actual != expected_hash:
            raise RuntimeError(
                f"checksum mismatch (got {actual}, expected {expected_hash})"
            )
        return tmp_path

    except Exception as exc:
        print(f"Download failed: {exc}")
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        return None


def _validate_members(tar):
    """Reject absolute paths, traversal, symlinks, and device nodes.

    Done by hand rather than relying on filter='data', which needs
    Python 3.12+.
    """
    for member in tar.getmembers():
        name = member.name
        if name.startswith("/") or ".." in Path(name).parts:
            raise RuntimeError(f"unsafe path in archive: {name}")
        if member.issym() or member.islnk() or member.isdev():
            raise RuntimeError(f"unsafe member type in archive: {name}")
        yield member


def extract_release(tarball_path):
    """Unpack into a temp dir, verifying required files are present."""
    extract_dir = tempfile.mkdtemp(prefix="slipperypenguin-update-")

    try:
        with tarfile.open(tarball_path, "r:gz") as tar:
            tar.extractall(extract_dir, members=_validate_members(tar))
    except (tarfile.TarError, RuntimeError, OSError) as exc:
        shutil.rmtree(extract_dir, ignore_errors=True)
        console.print(f"[red]Could not unpack the update: {exc}[/red]")
        return None

    present = set(os.listdir(extract_dir))
    missing = [name for name in REQUIRED_FILES if name not in present]
    if missing:
        shutil.rmtree(extract_dir, ignore_errors=True)
        console.print(f"[red]Incomplete package (missing: {', '.join(missing)}); aborting.[/red]")
        return None

    return extract_dir


def install_release(extract_dir, install_root=None):
    """Copy whitelisted files into the install directory.

    Each file is staged under a .new suffix and then os.replace()d into
    position, so an interruption cannot leave a half-written script behind.
    """
    if install_root is None:
        install_root = os.path.dirname(os.path.abspath(__file__))

    replaced = []
    for name in sorted(os.listdir(extract_dir)):
        if name not in ALLOWED_FILES:
            continue

        src = os.path.join(extract_dir, name)
        if not os.path.isfile(src):
            continue

        dst = os.path.join(install_root, name)
        staged = dst + ".new"

        shutil.copy2(src, staged)
        os.replace(staged, dst)
        replaced.append(name)

    shutil.rmtree(extract_dir, ignore_errors=True)
    return replaced


def run_update(current_version, assume_yes=False):
    """Full check -> confirm -> download -> install cycle.

    Returns True if any files were replaced.
    """
    info = check_for_update(current_version)
    if info is None:
        return False

    latest = str(info.get("latest", "")).strip()
    if not latest:
        console.print("[red]Update server did not report a version.[/red]")
        return False

    current_t = parse_version(current_version)
    latest_t = parse_version(latest)

    if latest_t == current_t:
        console.print(f"[purple]Already on the latest version ({current_version}).[/purple]")
        return False


    console.print(f"[purple]Update available: {latest} (you are running {current_version})[/purple]")

    if not assume_yes:
        answer = input("Update now? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            console.print("[yellow]Update cancelled.[/yellow]")
            return False

    url = info.get("url")
    expected_hash = info.get("sha256")
    if not url or not expected_hash:
        console.print("[red]Update server supplied no 'url'/'sha256'; aborting.[/red]")
        return False

    tarball = download_release(url, expected_hash)
    if tarball is None:
        return False

    try:
        extract_dir = extract_release(tarball)
    finally:
        if os.path.exists(tarball):
            os.unlink(tarball)

    if extract_dir is None:
        return False

    replaced = install_release(extract_dir)
    if not replaced:
        console.print("[red]Package contained no recognised files; nothing replaced.[/red]")
        return False

    console.print(f"[red]Updated to {latest}. Replaced: {', '.join(replaced)}[/red]")
    return True

