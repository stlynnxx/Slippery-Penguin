from rich.console import Console
import urllib.request
import urllib.error
import json
import os
import sys
import tempfile
import hashlib
import shutil
import subprocess
import tarfile
console = Console()
# Version
__version__ = "2.3.4"
UPDATE_URL = "https://eclecticelectronics.fly.dev/api/check-update/"


def download_update(url, expected_hash):
    fd, tmp_path = tempfile.mkstemp(suffix=".tar.gz")
    os.close(fd)
    hasher = hashlib.sha256()
    try:
        with urllib.request.urlopen(url, timeout=10) as resp, open(tmp_path, "wb") as out:
            while chunk := resp.read(65536):
                out.write(chunk)
                hasher.update(chunk)
            if hasher.hexdigest() != expected_hash:
                os.unlink(tmp_path)
                raise RuntimeError("Checksum mismatch- download aborted")
        return tmp_path
    except Exception as e:
        console.print(f"[red]{e}[/red]")
        return None


def extract_update(tmp_path):
    extract_dir = tempfile.mkdtemp()
    with tarfile.open(tmp_path, "r:gz") as tar:
        tar.extractall(extract_dir, filter="data")
        required = ["slipperypenguin.py", "art.txt", "flags.json"]
        extracted_names = os.listdir(extract_dir)
        for name in required:
            if name not in extracted_names:
                raise RuntimeError("Incomplete package, download aborted")
    return extract_dir


def install_update(extract_dir):
    install_root = os.path.dirname(os.path.abspath(__file__))
    for fname in os.listdir(extract_dir):
        src = os.path.join(extract_dir, fname)
        dst = os.path.join(install_root, fname)
        os.replace(src, dst)
    shutil.rmtree(extract_dir)


def gtfo_update():
    try:
        subprocess.run([
            "curl",
            "https://gtfobins.org/api.json",
            "-o",
            "gtfobins.json"
        ])
        console.print("[green]GTFOBins updated at gtfobins.json[/green]")
    except Exception as e:
        console.print(f"[red]Updating GTFObins failed, {e}[/red]")


def update_chk():
    try:
        with urllib.request.urlopen(UPDATE_URL + __version__, timeout=10) as resp:
            update_info = json.loads(resp.read().decode())
    except (urllib.error.URLError, json.JSONDecodeError) as e:
        console.print(f"[red]Could not reach update server: {e}[/red]")
        return None

    latest = update_info.get("latest", "")

    if latest == __version__:
        console.print("[green]Already on latest version[/green]")
        return None

    if latest < __version__:
        console.print("[yellow]You're on the development version [/yellow]")
        return None

    if latest > __version__:
        console.print(f"[magenta]Update available: {latest} (you are running {__version__})[/magenta]")
        console.print("[green]Would you like to update, or stay on the current version? (y to update):[/green]")
        console.print("[magenta](y/n)[/magenta]")
        usr_in = input().lower()

        if usr_in != "y":
            console.print("[yellow]Update cancelled[/yellow]")
            return None

        # Execute update
        try:
            subprocess.run(["curl", "https://gtfobins.org/api.json", "-o", "gtfobins.json"])
            console.print("[green]GTFOBins updated at gtfobins.json[/green]")

            downloaded_path = download_update(update_info["url"], latest)
            if downloaded_path is None:
                console.print("[red]Download failed, aborting update[/red]")
                return None

            extract_dir = extract_update(downloaded_path)
            install_update(extract_dir)
            console.print("[green]Update Successful![/green]")

        except Exception as e:
            console.print(f"[red]Update failed: {e}[/red]")
            return None

        return update_info