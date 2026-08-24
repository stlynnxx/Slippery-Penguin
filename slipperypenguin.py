import subprocess
import os
import json
from contextlib import nullcontext
from datetime import datetime
import argparse
import sys
import shutil
from rich.console import Console
import asyncio
import traceback
#69
console = Console()
# art is from https://www.asciiart.eu/art/2e5ef0982cbcf027
with open('art.txt', 'r') as file:
    content = file.read()
    console.print(f"[green]{content}[/green]")

# Setting up argparse
parser = argparse.ArgumentParser("SUID enumeration and vulnerability scanning")
parser.add_argument("--output", choices=["terminal", "logs", "both"], default="both", help="Output mode")
parser.add_argument("--storage", type=str, default="./logs", help="Log storage directory")
parser.add_argument("-gtfo", action="store_true", help="Enables GTFO Comparison")
parser.add_argument("-update-gtfobins", action="store_true", help="Download/update GTFOBins database")
parser.add_argument("-del-logs", choices=["run", "close"],  default=None, help="Delete Logs")
parser.add_argument("-help", action="store_true", help="Help!")
parser.add_argument("-timeout", action="store_true", help="Used for changing timeout var, default is 10")
parser.add_argument("-verbose", action="store_true", help="Show context in terminal for each flag")
parser.add_argument("-cleanup", action="store_true", help="Deletes all data and uninstalls the program")


args = parser.parse_args()
sys.stdin = open('/dev/tty')
timeout_var = 10

# Setting up dirs
STORAGE_ROOT = args.storage
GTFODIR = STORAGE_ROOT
os.makedirs(GTFODIR, exist_ok=True)
GTFO_FILE = os.path.join(GTFODIR, "gtfobins.json")
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
        console.print(f"[green]GTFOBins data removed.[/green]")

    ## this removes the logs dir
    if os.path.exists(STORAGE_ROOT):
        shutil.rmtree(STORAGE_ROOT)
        console.print(f"[green]Logs directory removed.[/green]")
    sys.exit(0)




# Help!

if args.help:
    console.print("[cyan]If this is a fresh download, run -update-gtfobins for the most up to date data.[/cyan]")
    print("--output both:       Writes results in the terminal and to logs")
    print("--output terminal:   Writes results to the terminal only")
    print("--output logs:       Writes results to the logs only")
    print("-gtfo:               Checks results against GTFOBins data, data follows output choice")
    print("-update-gtfobins:    Updates GTFOBins data from the GTFOBins API endpoint")
    print("-del-logs:           Deletes all logs that are currently stored")
    print("-timeout:            Allows the user to set the timeout value")
    print("-help:               How you got here")

    print("An example command:\npython3 slipperypenguin.py --output logs -gtfo -update-gtfo,\n" +
          "with -gtfo-update being optional if your data is up to date.")
    sys.exit(0)




# Updating gtfobins logic
if args.update_gtfobins:
    subprocess.run([
        "curl",
        "https://gtfobins.org/api.json",
        "-o",
        GTFO_FILE
    ])
    print(f"GTFOBins updated at {GTFO_FILE}")
    sys.exit(0)

if args.timeout:
    timeout_var = int(input(f"{YELLOW}Enter custom timeout value: {RESET}"))

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
FLAGS = os.path.join(RUN_DIR, "flags.json")
CAP_OUT = os.path.join(RUN_DIR, "cap-out.json")
FIND_OUT = os.path.join(RUN_DIR, "find-out.json")
STRACE_OUT = os.path.join(RUN_DIR, "strace-out.json")
TIMEOUT_OUT = os.path.join(RUN_DIR, "timeout-out.json")
GTFO_OUT = os.path.join(RUN_DIR, "gfto-out.json")


# The flags list itself
flags = [
    {"string": "execve", "severity": "LOW WITH CONTEXT", "context": "Binary executes another program. If called with user-influenced arguments while elevated, could be used to execute arbitrary code with elevated privileges."},
    {"string": "ENCRYPT_METHOD", "severity": "HIGH", "context": "References encryption method configuration, typically sourced from /etc/login.defs. A SUID binary reading or influencing encryption method selection could weaken system-wide password hashing if the method is manipulable or insufficiently strong."},
    {"string": "PASS_MIN_LEN", "severity": "MEDIUM",  "context": "References minimum password length configuration. If this binary reads or writes password policy, misconfiguration could weaken system authentication."},
    {"string": "PASS_MAX_LEN", "severity": "MEDIUM", "context": "References maximum password length configuration. Some implementations truncate passwords silently, which can weaken security or indicate policy manipulation."},
    {"string": "FAIL_DELAY", "severity": "MEDIUM", "context": "References the delay after a failed authentication attempt. If manipulable, an attacker could reduce or eliminate brute force delay."},
    {"string": "FAKE_SHELL", "severity": "HIGH", "context": "Explicit reference to a fake or substitute shell. Presence in a SUID binary is highly suspicious and warrants immediate investigation."},
    {"string": "SYS_GID_MAX", "severity": "HIGH", "context": "References system group ID boundaries. A SUID binary reading or writing GID configuration could be used to manipulate group membership or escalate group privileges."},
    {"string": "fchown", "severity": "LOW", "context": "Binary can change file ownership. If called while elevated and the target path is user-influenced, could be used to take ownership of sensitive files."},
    {"string": "fchmod", "severity": "LOW", "context": "Binary can change file permissions. If called while elevated and the target path is user-influenced, could be used to make sensitive files world-readable or executable."},
    {"string": "tcsetattr", "severity": "LOW", "context": "Binary modifies terminal attributes. Can affect terminal input handling. If not restored properly, may leave the terminal in an insecure or broken state."},
    {"string": "fork", "severity": "LOW WITH CONTEXT",  "context": "Binary spawns child processes. Combined with execve or shell references in the same binary, may indicate a pattern worth investigating for process injection or privilege inheritance."},
    {"string": "getlogin", "severity": "LOW", "context": "Binary reads the current login name. If used for authentication or authorization decisions without proper validation, could be spoofed in some environments."},
    {"string": "%s: failed to drop privileges (%s)", "severity": "MEDIUM WITH CONTEXT",  "context": "Binary attempted to drop elevated privileges and failed. If execution continues after this failure, the binary may be running with unintended elevated privileges."},
    {"string": "SUDO_ASKPASS", "severity": "MEDIUM WITH CONTEXT", "context": "Binary references the sudo password helper path. If this environment variable is read without sanitization, an attacker could point it to a malicious program to intercept sudo password prompts."},
    {"string": "allow_root", "severity": "MEDIUM", "context": "FUSE mount option that permits root to access a user-mounted filesystem. Combined with a permissive /etc/fuse.conf, could allow a malicious userspace filesystem to intercept root file access"},
    {"string": "/bin/sh", "severity": "MEDIUM WITH CONTEXT", "context": "Binary spawns a shell. If privileges are not dropped before the shell is executed, the spawned shell may inherit elevated privileges."},
    {"string": "/usr/sbin:/usr/bin:/sbin:/bin:%s/bin", "severity": "HIGH WITH CONTEXT",
     "context": "Binary constructs a PATH dynamically with a variable component. If the variable is user-influenced, an attacker may be able to inject a malicious directory into the PATH and hijack binary execution. Associated with CVE-2021-4034 in pkexec."},
    ]

border = "-----"




if os.path.exists(FIND_OUT):
    with open(FIND_OUT, "r") as f:
        find_append = json.loads(f.read())
# Enumerates SUIDs and checking capabilites
result = subprocess.run( ["find", "/", "-perm", "-4000", "-type", "f"], capture_output=True, text=True)
agg_result = result.stdout.splitlines()
find_append = agg_result
if args.output in ("terminal", "both"):
    console.print(f"[yellow]SUIDs Found:[/yellow]")
    for suid in agg_result:
        console.print(f"  [green]{suid}[/green]")
    console.print(f"[yellow]END SUIDs[/yellow]\n")
if args.output in ("logs", "both"):
    with open(FIND_OUT, "w") as f:
        json.dump(find_append, f)




# Globals for passing data between functions
strings_append = {}
cap_append = {}
strace_append = {}
timeout_append = {}
gtfo_append = {}
find_append = {}
getcap_append = {}
flags_append = {}


if os.path.exists(CAP_OUT):
    with open(CAP_OUT, "r") as f:
        cap_append = json.loads(f.read())

if os.path.exists(STRACE_OUT):
    with open(STRACE_OUT, "r") as f:
        strace_append = json.loads(f.read())
if os.path.exists(TIMEOUT_OUT):
    with open(TIMEOUT_OUT, "r") as f:
        timout_append = json.loads(f.read())
if os.path.exists(GTFO_OUT):
    with open(GTFO_OUT, "r") as f:
        gtfo_append = json.loads(f.read())

# Scans

# This is for running the strings scan on a given binary
async def strings_scan(b):
    global strings_append
    global timeout_append
    try:
        process = await asyncio.create_subprocess_exec(
            "strings",
            "-a",
            b,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout_var)
            strings_append[b] = stdout.decode().splitlines()
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            timeout_append[b] = "timeout"

        # return stdout.decode().splitlines()
    except Exception as e:
        console.print(f"[red]strings_scan failure: {e}[/red]")
        traceback.print_exc()
# strace scanning
async def strace_scan(b):
    global strace_append
    global timeout_append
    try:
        process = await asyncio.create_subprocess_exec(
            "strace", "-e", "execve", b,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout_var)
            strace_append[b] = stderr.decode().splitlines()
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            timeout_append[b] = "timeout"
        if args.output in ("terminal", "both"):
            print(f"\n[yellow]Strace:[/yellow][green]{strace_append}[/green]")

    except Exception as e:
        console.print(f"[red]strace_scan failure: {e}[/red]")
        traceback.print_exc()
    # return stdout.decode().splitlines()

#gtfobins comp
async def gtfo_scan(b):
    global gtfo_append
    try:
        if args.gtfo:
            binary_name = os.path.basename(b)
            entry = gtfo_data["executables"].get(binary_name)
            functions = entry.get("functions", {})
            if entry:
                for func_type, methods in functions.items():
                    for method in methods:
                        contexts = method.get("contexts", {})
                        if "suid" in contexts:
                            console.print(f"[magenta]--Results for: {b}--[/magenta]")
                            console.print(f"[cyan]  SUID exploit: {func_type}[/cyan]")
    except Exception as e:
        console.print(f"[red]gtfo comp failure: {e}[/red]")
        traceback.print_exc()

# getcap scan
async def get_scan(b):
    global getcap_append
    try:
        result = await asyncio.create_subprocess_exec(
            "getcap",
            "-r",
            b,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        try:
            stdout, stderr = await asyncio.wait_for(result.communicate(), timeout=timeout_var)
            getcap_append[b] = stdout.decode().splitlines()
        except asyncio.TimeoutError:
            result.kill()
            await result.wait()
            timeout_append[b] = "timeout"
        if result.stdout:
            cap_append.setdefault(b, [])
            cap_item = [f"Cap check {b}: {result.stdout}"]
            cap_append[b].append(cap_item)
        if args.output in ("terminal", "both"):
            console.print(f"\n[yellow]getcap: [/yellow][green]{cap_append}[/green]")
    except Exception as e:
        console.print(f"[red]get_scan failure: {e}[/red]")
        traceback.print_exc()
async def timeouts(b):
    global timeout_append
    try:
        if args.output in ("terminal", "both"):
            console.print("[yellow]Timeouts:[/yellow]")
            for t in timeout_append:
                console.print(f"\n[green] {t}[/green]")
        if args.output in ("logs", "both"):
            with open(TIMEOUT_OUT, "w") as f:
                json.dump(timeout_append, f)

    except Exception as e:
        console.print(f"[red]timeouts failure: {e}[/red]")
        traceback.print_exc()


# File writing



# strace results
async def strace_write(b):
    global strace_append
    try:
        if args.output in ("logs", "both"):
            # strace write to file
            with open(STRACE_OUT, "w") as f:
                json.dump(strace_append, f)
    except Exception as e:
        console.print(f"[red]strace write failure: {e}[/red]")
        traceback.print_exc()

# strings results
async def strings_write(b):
    global strings_append
    try:
        if args.output in ("terminal", "both"):
            console.print(f"[yellow]Strings Found for [/yellow][magenta] {b}:[/magenta] ")
            for string in strings_append:
                console.print(f"    [green]{string}[/green]")
        if args.output in ("logs", "both"):
            if os.path.exists(STR_OUT):
                with open(STR_OUT, "r") as f:
                    passer = json.loads(f.read())
            else:
                passer = {}
            passer[b] = strings_append.get(b, [])
            with open(STR_OUT, "w", encoding='utf-8') as f:
                json.dump(passer, f)
    except Exception as e:
        console.print(f"[red]strings write failure: {e}[/red]")
        traceback.print_exc()
        pass

# flags writing
async def flags_write(b):
    global flags_append
    global strings_append
    try:
        if args.output in ("terminal", "both"):
            # This is the logic for writing any flags found to the file
            flags_append = {}
            if os.path.exists(FLAGS):
                with open(FLAGS, "r") as f:
                    flags_append = json.loads(f.read())
            for flag in flags:
                if flag["string"] in strings_append.get(b, []):
                    flags_append.setdefault(b, [])
                    appendItem = {
                        "string": flag["string"],
                        "severity": flag["severity"],
                        "context": flag.get("context", "")
                    }
                    flags_append[b].append(appendItem)
            for binary, findings in flags_append.items():
                console.print(f"\n[yellow]Flags for {binary}: [/yellow]")
                for finding in findings:
                    console.print(f"  [yellow]{finding['severity']}[/yellow] - [yellow]{finding['string']}[/yellow]")
                    if args.verbose and "context" in finding:
                        console.print(f"    [cyan]Context: {finding['context']}[/cyan]")
                    console.print(f"[yellow]--------[/yellow]")
            with open(FLAGS, "w", encoding='utf-8') as f:
                json.dump(flags_append, f)
    except Exception as e:
        console.print(f"[red]gtfo error: {e}[/red]")
        traceback.print_exc()
        pass

# getcap results writing
async def getcap_write(b):
    global cap_append
    try:
        if args.output in ("logs", "both"):
            with open(CAP_OUT, "w", encoding='utf-8') as f:
                json.dump(cap_append, f)
    except Exception as e:
        console.print(f"[red]gtfo error: {e}[/red]")
        traceback.print_exc()
        pass

# gtfobins results writing
async def gtfo_write(b):
    global gtfo_append
    try:
        if args.output in ("logs", "both"):
            with open(GTFO_OUT, "w", encoding='utf-8') as f:
                json.dump(gtfo_append, f)
    except Exception as e:
        console.print(f"[red]gtfo write error : {e}[/red]")


# New
async def main():
    with (console.status("[blue]Sliding Around... [/blue]")):
        try:
            for binary in agg_result:
                if not binary.startswith("/usr/bin"):
                    continue
                try:
                    results = await asyncio.gather(
                        strings_scan(binary),
                        strace_scan(binary),
                        gtfo_scan(binary),
                        get_scan(binary)


                    )
                except Exception as e:
                    console.print(f"[red]scan failure: {e}[/red]")
                    traceback.print_exc()
                try:
                    write_results = await asyncio.gather(
                        strace_write(binary),
                        strings_write(binary),
                        flags_write(binary),
                        getcap_write(binary),
                        gtfo_write(binary),

                    )
                except Exception as e:
                    console.print(f"[red]write failure: {e}[/red]")
                    traceback.print_exc()

        except Exception as e:
            console.print(f"[red]main failure: {e}[/red]")
            traceback.print_exc()

asyncio.run(main())

print(f"[bold bright_green]Done![/bold bright_green]")
