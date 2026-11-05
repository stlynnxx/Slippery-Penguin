import argparse
import asyncio
import csv
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import traceback
from datetime import datetime

from rich.console import Console
from weasyprint import HTML

from htmlgenerator import generate_PDF, generate_report
from runtime_tracing import confirm_runtime_trace, select_trace_candidates, trace_binary
from scan_helpers import collect_scan_inventory, normalise_path

try:
    import updatehelpers
except ImportError:
    updatehelpers = None
console = Console()
# Version
__version__ = "2.5.4"

# art is from https://www.asciiart.eu/art/2e5ef0982cbcf027
with open("art.txt", "r") as file:
    content = file.read()
    console.print(f"[green]{content}[/green]")

# Setting up argparse
parser = argparse.ArgumentParser("SUID enumeration and vulnerability scanning")
parser.add_argument(
    "--output",
    "-o",
    choices=["terminal", "logs", "both"],
    default="terminal",
    help="Output mode",
)
parser.add_argument(
    "--storage", "-s", type=str, default="./logs", help="Log storage directory"
)
parser.add_argument(
    "--update-gtfobins",
    "-upgt",
    action="store_true",
    help="Download/update GTFOBins database",
)
parser.add_argument(
    "--del-logs", "-dl", choices=["run", "close"], default=None, help="Delete Logs"
)
parser.add_argument(
    "--timeout",
    "-t",
    action="store_true",
    help="Used for changing timeout var, default is 10",
)
parser.add_argument(
    "--runtime-trace",
    "-rt",
    action="store_true",
    help="Run evidence-selected runtime traces after explicit confirmation",
)
parser.add_argument(
    "--cleanup",
    "-c",
    action="store_true",
    help="Deletes all data and uninstalls the program",
)
parser.add_argument(
    "--update",
    "-u",
    choices=["run", "close"],
    help="Download and install the latest version",
)
parser.add_argument(
    "--check", "-chk", action="store_true", help="Check the current version"
)
parser.add_argument(
    "--skip-update-check",
    "-suc",
    action="store_true",
    help="Skip the automatic update check at startup",
)
parser.add_argument("--manual", "-man", action="store_true", help="Manual")
parser.add_argument(
    "--htmlreport", "-hr", action="store_true", help="Save results in HTML file"
)
parser.add_argument(
    "--pdfreport", "-pdf", action="store_true", help="Save results in PDF file"
)
parser.add_argument(
    "--csvreport", "-cr", action="store_true", help="Save findings in a CSV file"
)


# Globals for passing data between functions
strings_append = {}
cap_append = {}
strace_append = {}
runtime_trace_plan = {}
runtime_trace_results = {}
timeout_append = {}
gtfo_append = {}
find_append = {"results": []}
flags_append = {}
flags = {}
b_exp = {}
agg_result = []

args = parser.parse_args()
# sys.stdin = open('/dev/tty')
timeout_var = 2

# Setting up dirs
STORAGE_ROOT = args.storage

try:
    from weasyprint import HTML
    from yattag import Doc
except ImportError as e:
    console.print(
        f"[red]Missing dependency: {e.name}. Run: pip install -r requirements.txt[/red]"
    )
    sys.exit(1)

GTFO_FILE = os.path.join("gtfobins.json")
if args.del_logs == "run":
    if not os.path.exists(STORAGE_ROOT):
        print(f"[-] No logs directory found at {STORAGE_ROOT}")
    else:
        for filename in os.listdir(STORAGE_ROOT):
            file_path = os.path.join(STORAGE_ROOT, filename)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            except Exception as e:
                print("Failed to delete %s. Reason: %s" % (file_path, e))
    print("Logs Deleted!")

if args.del_logs == "close":
    if not os.path.exists(STORAGE_ROOT):
        print(f"[-] No logs directory found at {STORAGE_ROOT}")
    else:
        for filename in os.listdir(STORAGE_ROOT):
            file_path = os.path.join(STORAGE_ROOT, filename)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            except Exception as e:
                print("Failed to delete %s. Reason: %s" % (file_path, e))
    print("Logs Deleted!")
    sys.exit(0)

if args.cleanup:
    if not os.path.exists(STORAGE_ROOT):
        print(f"[-] No logs directory found at {STORAGE_ROOT}")
    else:
        for filename in os.listdir(STORAGE_ROOT):
            file_path = os.path.join(STORAGE_ROOT, filename)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            except Exception as e:
                print("Failed to delete %s. Reason: %s" % (file_path, e))

    ## This removes the gtfobins data
    if os.path.exists(GTFO_FILE):
        os.unlink(GTFO_FILE)
        console.print("[green]GTFOBins data removed.[/green]")

    ## this removes the logs dir
    if os.path.exists(STORAGE_ROOT):
        shutil.rmtree(STORAGE_ROOT)
        console.print("[green]Logs directory removed.[/green]")
    sys.exit(0)


# Help!

if args.manual:
    console.print(
        "[cyan]If this is a fresh download, run -update-gtfobins for the most up to date data.[/cyan]"
    )
    print("--output both:       Writes results in the terminal and to logs")
    print("--output terminal:   Writes results to the terminal only")
    print("--output logs:       Writes results to the logs only")
    print(
        "-gtfo:               Checks results against GTFOBins data, data follows output choice"
    )
    print("-update-gtfobins:    Updates GTFOBins data from the GTFOBins API endpoint")
    print("-del-logs:           Deletes all logs that are currently stored")
    print("-timeout:            Allows the user to set the timeout value, default is 2")
    print("-help:               How you got here")

    print(
        "An example command:\npython3 slipperypenguin.py --output logs -gtfo -update-gtfo,\n"
        + "with -update-gtfobins being optional if your data is up to date."
    )
    sys.exit(0)


# Updating gtfobins logic
try:
    if args.update_gtfobins:
        subprocess.run(["curl", "https://gtfobins.org/api.json", "-o", GTFO_FILE])
        print(f"GTFOBins updated at {GTFO_FILE}")
        sys.exit(0)
except Exception as e:
    console.print(f"[red]Updating GTFObins failed, {e}[/red]")


# ---------------------------------------------------------------- updates
# Explicit --update: no confirmation prompt. "run" continues into the scan
# afterwards (with the old code, still in memory), "close" exits.
if args.update in ("run", "close"):
    if updatehelpers is None:
        console.print(
            "[red]Error: updatehelpers.py not found next to slipperypenguin.py[/red]"
        )
        sys.exit(1)

    update_info = updatehelpers.check_for_update(__version__)
    if update_info is None:
        sys.exit(1)

    latest = str(update_info.get("latest", "")).strip()

    # Numeric comparison. The old `latest < __version__` ranked
    # '2.3.10' below '2.3.9' because strings compare per-character.
    # Dev branch running ahead of the published release: nothing to do.
    if updatehelpers.parse_version(latest) <= updatehelpers.parse_version(__version__):
        console.print(f"[purple]No update available (running {__version__}).[/purple]")
    else:
        console.print(
            f"[magenta]Update available: {latest} (you are running {__version__})[/magenta]"
        )

        # GTFOBins refresh, as before
        try:
            subprocess.run(["curl", "https://gtfobins.org/api.json", "-o", GTFO_FILE])
            console.print(f"[green]GTFOBins updated at {GTFO_FILE}[/green]")
        except Exception as e:
            console.print(f"[red]Could not update GTFOBins, {e}[/red]")

        url = update_info.get("url")
        sha = update_info.get("sha256")
        if not url or not sha:
            console.print(
                "[red]Update server supplied no 'url'/'sha256'; aborting.[/red]"
            )
            sys.exit(1)

        tarball = updatehelpers.download_release(url, sha)
        if tarball is None:
            sys.exit(1)

        extract_dir = updatehelpers.extract_release(tarball)
        if extract_dir is None:
            sys.exit(1)

        if not updatehelpers.install_release(extract_dir):
            console.print(
                "[red]Package contained no recognised files; nothing replaced.[/red]"
            )
            sys.exit(1)

        console.print("[green]Update Successful![/green]")

    if args.update == "close":
        sys.exit(0)
    console.print(
        "[yellow]Continuing with the currently loaded version; restart to run the new code.[/yellow]"
    )


# --check: report status only, no install.
if args.check:
    if updatehelpers is None:
        console.print(
            "[red]Error: updatehelpers.py not found next to slipperypenguin.py[/red]"
        )
        sys.exit(1)

    update_info = updatehelpers.check_for_update(__version__)
    if update_info is None:
        sys.exit(1)

    latest = str(update_info.get("latest", "")).strip()
    if updatehelpers.parse_version(latest) > updatehelpers.parse_version(__version__):
        console.print(
            f"[magenta]Update available: {latest} (you are running {__version__})[/magenta]"
        )
    else:
        # Covers both "equal" and "dev build ahead of the published release".
        console.print(f"[green]No update available ({__version__}).[/green]")
    sys.exit(0)


# Startup update check (interactive). Skipped when --update was passed,
# since the explicit update above already ran.
if args.update is None and not args.skip_update_check and updatehelpers is not None:
    update_info = updatehelpers.check_for_update(__version__)
    if update_info is None:
        # Original behaviour on an unreachable server was to abort; kept.
        console.print("[yellow]Skipping update check (server unreachable).[/yellow]")
        # Changed from sys.exit(1): don't kill the scan just because update server is down.
    else:
        latest = str(update_info.get("latest", "")).strip()

        # Numeric comparison. Dev branch (running ahead of the published
        # release) and matching versions both fall through silently -
        # same as the old `if latest < __version__: pass` and the
        # `if latest == __version__: pass`, but now '2.3.10' > '2.3.9'.
        if updatehelpers.parse_version(latest) > updatehelpers.parse_version(
            __version__
        ):
            console.print(
                f"[magenta] Update available: {latest} (you are running {__version__}) [/magenta]"
            )
            console.print(
                "[green] Would you like to update, or stay on the current version? (y to update): [/green]"
            )
            console.print("[magenta](y/n)[/magenta]")
            usr_in = input()
            usr_in = usr_in.lower()
            if usr_in == "n":
                pass
            else:
                # Updating gtfobins logic
                try:
                    subprocess.run(
                        ["curl", "https://gtfobins.org/api.json", "-o", GTFO_FILE]
                    )
                    print(f"GTFOBins updated at {GTFO_FILE}")
                except Exception as e:
                    console.print(f"[red]Could not update GTFOBins, {e}[/red]")

                url = update_info.get("url")
                sha = update_info.get("sha256")
                if not url or not sha:
                    console.print(
                        "[red]Update server supplied no 'url'/'sha256'.[/red]"
                    )
                else:
                    tarball = updatehelpers.download_release(url, sha)
                    if tarball is not None:
                        extract_dir = updatehelpers.extract_release(tarball)
                        if extract_dir is not None:
                            if updatehelpers.install_release(extract_dir):
                                console.print("[green]Update Successful![/green]")
                                console.print(
                                    "[yellow]Restart to run the new version.[/yellow]"
                                )
                            else:
                                console.print(
                                    "[red]Package contained no recognised files; nothing replaced.[/red]"
                                )
elif updatehelpers is None:
    console.print("[yellow]updatehelpers.py not found; skipping update check.[/yellow]")


if args.timeout:
    timeout_var = int(input("[yellow]Enter custom timeout value: [/yellow]"))

# Loading the gtfobins data
gtfo_data = {}
if os.path.exists(GTFO_FILE) and os.path.getsize(GTFO_FILE) > 0:
    with open(GTFO_FILE, "r") as f:
        gtfo_data = json.load(f)


# RUN_ID and RUN_DIR are for the individual filesaves in the dirs
RUN_ID = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
RUN_DIR = os.path.join(STORAGE_ROOT, RUN_ID)

os.makedirs(RUN_DIR, exist_ok=True)

STR_OUT = os.path.join(RUN_DIR, "str-out.json")

CAP_OUT = os.path.join(RUN_DIR, "cap-out.json")
FIND_OUT = os.path.join(RUN_DIR, "find-out.json")
STRACE_OUT = os.path.join(RUN_DIR, "strace-out.json")
RUNTIME_TRACE_PLAN_OUT = os.path.join(RUN_DIR, "runtime-trace-plan.json")
RUNTIME_TRACE_RESULTS_OUT = os.path.join(RUN_DIR, "runtime-trace-results.json")
TIMEOUT_OUT = os.path.join(RUN_DIR, "timeout-out.json")
GTFO_OUT = os.path.join(RUN_DIR, "gfto-out.json")
FLAGS_OUT = os.path.join(RUN_DIR, "flags-out.json")
HTML_OUT = os.path.join(RUN_DIR, "html-out.html")
CSV_OUT = os.path.join(RUN_DIR, "report.csv")
SCAN_OUT = os.path.join(RUN_DIR, "scan-out.json")


border = "-----"


# Build reusable filesystem and capability inventories once per run.
SCAN_STARTED = time.perf_counter()
inventory = collect_scan_inventory("/")
agg_result = inventory.privileged_files
cap_append = inventory.capabilities_by_file
file_metadata = inventory.file_metadata
find_append["results"] = agg_result

if args.output in ("terminal", "both"):
    console.print("[yellow]SUID/SGID files found:[/yellow]")
    for privileged_file in agg_result:
        console.print(f"  [green]{privileged_file}[/green]")
    console.print("[yellow]END SUID/SGID files[/yellow]")
    console.print(
        f"[cyan]Inventory: {len(agg_result)} privileged files, "
        f"{len(cap_append)} capability-bearing files[/cyan]"
    )
    for capability_path, expressions in sorted(cap_append.items()):
        console.print(f"  [green]{capability_path}[/green]: {', '.join(expressions)}")
    console.print(f"[cyan]Inventory timings: {inventory.timings}[/cyan]")
for warning in inventory.warnings:
    pass
    # console.print(f"[yellow]Scan warning: {warning}[/yellow]")


# loading the flags from json
try:
    with open("flags.json", "r") as file:
        flags = json.load(file)
except FileNotFoundError:
    console.print("[red]Flags load failure: {e}[/red]")
    traceback.print_exc()
if os.path.exists(STRACE_OUT):
    with open(STRACE_OUT, "r") as f:
        strace_append = json.loads(f.read())
if os.path.exists(TIMEOUT_OUT):
    with open(TIMEOUT_OUT, "r") as f:
        timeout_append = json.loads(f.read())
if os.path.exists(GTFO_OUT):
    with open(GTFO_OUT, "r") as f:
        gtfo_append = json.loads(f.read())


lock = asyncio.Lock()
semaphore = asyncio.Semaphore(5)


async def append(target: dict, b, data):
    async with semaphore, lock:
        target[b] = data


# Scans
# This is for running the strings scan on a given binary
async def strings_scan(b):
    # Debug
    # if args.output in ("logs"):
    #    print("strings scan started")
    global strings_append
    global timeout_append
    try:
        process = await asyncio.create_subprocess_exec(
            "strings",
            "-a",
            b,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=timeout_var
            )
            # strings_append[b] = stdout.decode().splitlines()
            await append(strings_append, b, stdout.decode().splitlines())
        except TimeoutError:
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            await process.wait()
            await append(timeout_append, b, "timeout")
            # return stdout.decode().splitlines()
    except Exception as e:
        console.print(f"[red]strings_scan failure: {e}[/red]")
        traceback.print_exc()


# Runtime trace commands are prepared only after static analysis.


# gtfobins comp
async def gtfo_scan(b):
    global gtfo_append
    try:
        binary_name = os.path.basename(b)

        # Check gtfo_data structure exists
        executables = gtfo_data.get("executables", {})
        if not executables:
            # console.print(f"[dim]DEBUG: gtfo_data.executables is empty[/dim]")
            return

        entry = executables.get(binary_name)
        if not entry:
            # console.print(f"[dim]ℹ No GTFOBins entry for {binary_name} (not in database)[/dim]")
            return

        functions = entry.get("functions", {})
        for func_type, methods in functions.items():
            # Handle both list and dict contexts
            if isinstance(methods, list):
                for method in methods:
                    contexts = method.get("contexts", [])
                    if "suid" in contexts:
                        console.print(f"[magenta]--Results for: {b}--[/magenta]")
                        console.print(f"[cyan]  SUID exploit: {func_type}[/cyan]")

                        gtfo_append.setdefault(b, [])
                        gtfo_append[b].append(
                            {
                                "type": func_type,
                                "context": "suid",
                                "method": str(method),
                            }
                        )
            elif isinstance(methods, dict):
                # Sometimes methods is a dict of {context: commands}
                if "suid" in methods:
                    console.print(f"[magenta]--Results for: {b}--[/magenta]")
                    console.print(f"[cyan]  SUID exploit: {func_type}[/cyan]")

                    gtfo_append.setdefault(b, [])
                    gtfo_append[b].append(
                        {
                            "type": func_type,
                            "context": "suid",
                            "method": str(methods["suid"]),
                        }
                    )
    except Exception as e:
        console.print(f"[red]gtfo comp failure: {e}[/red]")
        traceback.print_exc()


async def timeouts():
    global timeout_append
    try:
        if args.output in ("terminal", "both"):
            console.print("[yellow]Timeouts:[/yellow]")
            for t in timeout_append:
                console.print(f"\n[green] {t}[/green]")
    except Exception as e:
        console.print(f"[red]timeouts failure: {e}[/red]")
        traceback.print_exc()


# File writing


def strings_write(b):
    """Print this binary's strings; all JSON files are persisted once per run."""
    if args.output in ("terminal", "both"):
        console.print(f"[yellow]Strings Found for [/yellow][magenta] {b}:[/magenta] ")
        for string in strings_append.get(b, []):
            console.print(f"    [green]{string}[/green]")


# flags writing - no longer in gather(), called AFTER strings_scan completes
def flags_write_print():
    global flags_append
    global strings_append


# flags writing - REMOVED await keyword, kept sync to match original style
def flags_write(b):
    global flags_append
    global strings_append
    try:
        for flag in flags:
            if flag["string"] in strings_append.get(b, []):
                flags_append.setdefault(b, [])
                appendItem = {
                    "string": flag["string"],
                    "severity": flag["severity"],
                    "context": flag.get("context", ""),
                }
                flags_append[b].append(appendItem)
                if args.output in ("terminal", "both"):
                    console.print(
                        f"[magenta]{flag['severity']}[/magenta]: {flag['string']}"
                    )

    except Exception as e:
        console.print(f"[red]Flags dump failure: {e}[/red]")
        traceback.print_exc()


def write_scan_outputs():
    """Persist accumulated output once, avoiding repeated per-binary disk writes."""
    if args.output not in ("logs", "both"):
        return
    outputs = (
        (FIND_OUT, find_append["results"]),
        (CAP_OUT, cap_append),
        (STR_OUT, strings_append),
        (STRACE_OUT, strace_append),
        (RUNTIME_TRACE_PLAN_OUT, runtime_trace_plan),
        (RUNTIME_TRACE_RESULTS_OUT, runtime_trace_results),
        (TIMEOUT_OUT, timeout_append),
        (GTFO_OUT, gtfo_append),
        (FLAGS_OUT, flags_append),
    )
    for output_path, payload in outputs:
        with open(output_path, "w", encoding="utf-8") as output_file:
            json.dump(payload, output_file, indent=2)


def write_csv_report(results, output_path):
    fieldnames = ["binary", "finding_type", "finding", "severity", "context"]
    with open(output_path, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()

        for binary, binary_data in sorted(results.items()):
            for finding_type in (
                "strings",
                "strace",
                "runtime_trace",
                "flags",
                "gtfo",
                "timeouts",
                "capabilities",
            ):
                findings = binary_data.get(finding_type)
                if not findings:
                    continue

                if isinstance(findings, (str, bytes)):
                    findings = [findings]
                elif isinstance(findings, dict):
                    findings = list(findings.values())

                for finding in findings:
                    if not finding:
                        continue

                    row = {
                        "binary": binary,
                        "finding_type": finding_type,
                        "finding": "",
                        "severity": "",
                        "context": "",
                    }
                    if finding_type == "runtime_trace" and isinstance(finding, dict):
                        row["finding"] = json.dumps(finding, sort_keys=True)
                    elif finding_type == "flags" and isinstance(finding, dict):
                        row["finding"] = str(finding.get("string") or "").strip()
                        row["severity"] = str(finding.get("severity") or "").strip()
                        row["context"] = str(finding.get("context") or "").strip()
                    else:
                        row["finding"] = str(finding).strip()

                    if row["finding"] or row["severity"] or row["context"]:
                        writer.writerow(row)


async def main():
    global b_exp
    global agg_result
    with console.status("[blue]Sliding Around... [/blue]"):
        try:
            for binary in agg_result:
                if not binary.startswith("/usr/bin"):
                    continue
                try:
                    # FIXED: strings_scan MUST complete BEFORE flags_write runs
                    # flags_write matches flag strings against strings_append[binary]
                    # If run concurrently via gather(), flags_write executes first and sees empty list
                    await asyncio.gather(
                        strings_scan(binary),
                        gtfo_scan(binary),
                        return_exceptions=True,
                    )

                    # NOW safe: strings_append[binary] is populated
                    flags_write(binary)

                    b_exp.setdefault(binary, {})
                    b_exp[binary]["strings"] = strings_append.get(binary, [])
                    b_exp[binary]["flags"] = flags_append.get(binary, [])
                    b_exp[binary]["strace"] = strace_append.get(binary, [])
                    b_exp[binary]["gtfo"] = gtfo_append.get(binary, [])
                    b_exp[binary]["timeouts"] = timeout_append.get(binary, [])
                    binary_key = normalise_path(binary)
                    b_exp[binary]["capabilities"] = cap_append.get(binary_key, [])
                    b_exp[binary]["file_metadata"] = file_metadata.get(binary_key, {})
                    strings_write(binary)
                except (asyncio.CancelledError, Exception) as e:
                    console.print(f"[red]scan failure: {e}[/red]")
                    traceback.print_exc()

        except Exception as e:
            console.print(f"[red]main failure: {e}[/red]")
            traceback.print_exc()

        # Runtime tracing is deliberately a second, opt-in phase after static analysis.
        if args.runtime_trace:
            candidates = select_trace_candidates(agg_result, b_exp)
            if not candidates:
                console.print(
                    "[yellow]No privileged binaries met the static-evidence criteria.[/yellow]"
                )
            else:
                console.print(
                    "[bold red]DANGER: runtime tracing EXECUTES each selected binary. "
                    "Targets may modify files, access resources, or cause other side effects. "
                    "strace is NOT a sandbox. Only continue on systems and binaries you are "
                    "authorised to execute.[/bold red]"
                )
                for candidate, reasons in candidates.items():
                    console.print(f"[cyan]{candidate}[/cyan]")
                    for reason in reasons:
                        console.print(f"  [dim]- {reason}[/dim]")
                    runtime_trace_plan[candidate] = {
                        "selection_reasons": reasons,
                        "timeout_seconds": timeout_var,
                        "status": "awaiting_confirmation",
                    }

                if not confirm_runtime_trace():
                    console.print(
                        "[yellow]Runtime tracing cancelled; no selected binaries were executed.[/yellow]"
                    )
                    for candidate in candidates:
                        runtime_trace_plan[candidate]["status"] = "cancelled"
                else:
                    for candidate in candidates:
                        runtime_trace_plan[candidate]["status"] = "running"
                        try:
                            result = await trace_binary(candidate, timeout=timeout_var)
                            result_data = result.to_dict()
                        except asyncio.CancelledError:
                            runtime_trace_plan[candidate]["status"] = "cancelled"
                            raise
                        except Exception as exc:
                            result_data = {
                                "status": "failed",
                                "returncode": None,
                                "observations": [],
                                "diagnostics": [f"Runtime tracing failed: {exc}"],
                                "timed_out": False,
                            }

                        runtime_trace_results[candidate] = result_data
                        strace_append[candidate] = result_data["observations"]
                        runtime_trace_plan[candidate]["status"] = result_data["status"]
                        binary_report = b_exp.setdefault(candidate, {})
                        binary_report["strace"] = result_data["observations"]
                        binary_report["runtime_trace"] = {
                            "status": result_data["status"],
                            "returncode": result_data["returncode"],
                            "timed_out": result_data["timed_out"],
                            "diagnostics": result_data["diagnostics"],
                        }
                        console.print(
                            f"[cyan]{candidate}[/cyan]: runtime trace {result_data['status']} "
                            f"({len(result_data['observations'])} observations)"
                        )
                        for diagnostic in result_data["diagnostics"]:
                            console.print(f"[yellow]  {diagnostic}[/yellow]")

        # Include every capability-bearing file in reports, even when it is
        # outside the existing /usr/bin analysis scope.
        for capability_path, expressions in cap_append.items():
            report_data = b_exp.setdefault(capability_path, {})
            report_data.setdefault("strings", [])
            report_data.setdefault("strace", [])
            report_data.setdefault("flags", [])
            report_data.setdefault("gtfo", [])
            report_data.setdefault("timeouts", [])
            report_data["capabilities"] = expressions
            report_data["file_metadata"] = file_metadata.get(capability_path, {})

        if args.htmlreport and b_exp:
            html = generate_report(b_exp, default_binary=next(iter(b_exp.keys()), None))
            with open(HTML_OUT, "w", encoding="utf-8") as f:
                f.write(html)
        if args.pdfreport:
            pdf = generate_PDF(b_exp)
            HTML(string=pdf).write_pdf(f"{RUN_DIR}/report_{RUN_ID}.pdf")
        if args.csvreport:
            write_csv_report(b_exp, CSV_OUT)

        try:
            await timeouts()
        except Exception as e:
            console.print(f"[red]Timeout summary failed: {e}[/red]")

        write_scan_outputs()
        total_scan_seconds = round(time.perf_counter() - SCAN_STARTED, 6)
        inventory_seconds = float(inventory.timings["total_seconds"])
        scan_summary = {
            "run_id": RUN_ID,
            "counts": {
                "privileged_files": len(agg_result),
                "capability_files": len(cap_append),
                "metadata_cached_files": len(file_metadata),
                "analysed_binaries": len(b_exp),
            },
            "timings_seconds": {
                **inventory.timings,
                "analysis_and_reporting_seconds": round(
                    max(0.0, total_scan_seconds - inventory_seconds), 6
                ),
                "total_scan_seconds": total_scan_seconds,
            },
            "warnings": inventory.warnings,
            "file_metadata": file_metadata,
        }
        if args.output in ("logs", "both"):
            with open(SCAN_OUT, "w", encoding="utf-8") as summary_file:
                json.dump(scan_summary, summary_file, indent=2)
        if args.output in ("terminal", "both"):
            console.print(
                f"[cyan]Total scan duration: {total_scan_seconds:.3f}s[/cyan]"
            )


asyncio.run(main())
console.print("[bold bright_green]Done![/bold bright_green]")
