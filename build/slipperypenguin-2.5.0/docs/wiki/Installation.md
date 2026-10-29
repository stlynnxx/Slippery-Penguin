# Installation

Slippery Penguin is a Linux security-auditing tool that enumerates SUID binaries and checks selected binaries for strings, execution traces, GTFOBins matches, Linux capabilities, and configured flag strings. Run it only on systems you own or have explicit permission to assess.

This guide follows the `v2.4.3` source. The repository's `requirements.txt` does not pin dependency versions or declare a minimum Python version; Python 3.11 or newer is a practical choice for current WeasyPrint releases.

## System requirements

Install Python 3, pip, and the external commands used by the scanner:

| Command | Package / purpose |
| --- | --- |
| `find` | `findutils`; enumerates SUID files |
| `strings` | `binutils`; extracts printable strings from binaries |
| `strace` | Traces `execve` calls |
| `getcap` | Provided by the distribution's libcap package; checks Linux file capabilities |
| `curl` | Downloads the GTFOBins dataset and is used by update flows |
| `timeout` | Usually provided by `coreutils`; bounds the strace subprocess |

PDF generation uses WeasyPrint. Installing it with pip does not always install the required native system libraries. On Linux, WeasyPrint needs Pango and related text/rendering libraries. Package names vary by distribution and release; use the matching command below, or follow the [official WeasyPrint installation guide](https://doc.courtbouillon.org/weasyprint/stable/first_steps.html).

### Debian

On Debian 11 or newer, install the scanner's external tools and WeasyPrint runtime libraries:

```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv findutils binutils strace libcap2-bin curl coreutils libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0
```

### Ubuntu

For Ubuntu releases that provide these package names, install the external tools and WeasyPrint runtime libraries:

```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv findutils binutils strace libcap2-bin curl coreutils libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0 libharfbuzz-subset0
```

If a package is unavailable on your Ubuntu release, consult the [WeasyPrint guide](https://doc.courtbouillon.org/weasyprint/stable/first_steps.html) for the package list for that release.

### Fedora

```bash
sudo dnf install python3 python3-pip findutils binutils strace libcap curl coreutils pango
```

### Arch Linux

```bash
sudo pacman -S python python-pip findutils binutils strace libcap curl coreutils pango
```

## Install Slippery Penguin

Clone the repository and enter its directory:

```bash
git clone https://github.com/stlynnxx/Slippery-Penguin.git
cd Slippery-Penguin
```

Create and activate a virtual environment, then install the Python dependencies listed by the project:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

The requirements file lists `rich`, `yattag`, and `weasyprint`. The scanner imports these packages when it starts, including WeasyPrint even when you do not request a PDF report.

## Prepare the GTFOBins dataset

On a fresh checkout, download the GTFOBins JSON dataset before scanning:

```bash
python3 slipperypenguin.py --update-gtfobins
```

The command fetches `https://gtfobins.org/api.json`, writes `gtfobins.json` in the current working directory, and exits. Run it again when you want to refresh the local dataset.

## Run your first scan

Run a scan with terminal output, JSON logs, and an HTML report:

```bash
python3 slipperypenguin.py --skip-update-check --output both --htmlreport
```

The `--skip-update-check` option avoids the interactive startup update prompt. The scanner creates a timestamped directory under `./logs/` by default. With the command above, the run writes its JSON results and `html-out.html` there. The scan enumerates SUID files across the filesystem, but the per-binary analysis loop is restricted to paths beginning with `/usr/bin` in version `2.4.3`.

To choose another output directory, pass `--storage` (or `-s`):

```bash
python3 slipperypenguin.py --skip-update-check --output both --storage ./scan-results
```

To generate a PDF as well, add `--pdfreport` (or `-pdf`). If PDF generation fails with a native-library error, check the WeasyPrint system dependencies above.

## Common installation problems

- **`Missing dependency`**: activate the virtual environment and run `python -m pip install -r requirements.txt` again.
- **`find`, `strings`, `strace`, `getcap`, or `curl` not found**: install the corresponding operating-system package listed above.
- **WeasyPrint/PDF import or rendering error**: install the native Pango/HarfBuzz libraries for your distribution; pip alone may not be sufficient.
- **Permission denied from `strings`**: some privileged executables are intentionally not readable by an ordinary user, so they may produce no string results. This does not necessarily mean installation failed.
- **`strace` cannot attach or execute**: kernel ptrace restrictions and system policy may block tracing without elevated privileges.
- **A binary is marked as timed out**: the default per-binary timeout is two seconds. Slow or large binaries can exceed it.

For scan behavior, output-file formats, CLI flags, and interpreting findings, see the other Slippery Penguin wiki pages as they become available.
