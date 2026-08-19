import subprocess
import os
import json
from contextlib import nullcontext
from datetime import datetime
import argparse
import sys
import shutil
from rich.console import Console



# Decor
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
MAGENTA = '\033[95m'
CYAN = '\033[96m'
WHITE = '\033[97m'
RESET = '\033[0m'
BLACK = '\033[30m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'

# art is from https://www.asciiart.eu/art/2e5ef0982cbcf027
with open('art.txt', 'r') as file:
    content = file.read()
    print(f"{GREEN}{content}{RESET}")

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
console = Console()
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
        print(f"{GREEN}GTFOBins data removed.{RESET}")

    ## this removes the logs dir
    if os.path.exists(STORAGE_ROOT):
        shutil.rmtree(STORAGE_ROOT)
        print(f"{GREEN}Logs directory removed.{RESET}")
    sys.exit(0)




# Help!

if args.help:
    print("If this is a fresh download, run -update-gtfobins for the most up to date data.")
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
    print(f"[+] GTFOBins updated at {GTFO_FILE}")
    sys.exit(0)

if args.timeout:
    timeout_var = int(input(f"{YELLOW}Enter custom timeout value: {RESET}"))


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



find_append = {}
agg_result = []
if os.path.exists(FIND_OUT):
    with open(FIND_OUT, "r") as f:
        find_append = json.loads(f.read())
# Enumerates SUIDs and checking capabilites
result = subprocess.run( ["find", "/", "-perm", "-4000", "-type", "f"], capture_output=True, text=True)
agg_result = result.stdout.splitlines()



# print(f"Find result: {result.stdout}")
find_append = agg_result


if args.output in ("logs", "both"):
    with open(FIND_OUT, "w") as f:
        json.dump(find_append, f)

if args.output in ("terminal", "both"):
    print(f"\n{YELLOW}SUIDs Found:{RESET}")
    for suid in agg_result:
        print(f"  {GREEN}{suid}{RESET}")
    print(f"{YELLOW}END SUIDs{RESET}\n")






cap_append = {}
strace_append = {}
timeout_append = {}
gtfo_append = {}

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
    process = await asyncio.create_subprocess_exec(
        "strings",
        "-a",
        b,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate()
    return stdout.decode().splitlines()
# strace scanning
async def strace_scan(b):
    process = await asyncio.create_subprocess_exec(
        ["strace", "-e", "execve", b],
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate()
    return stdout.decode().splitlines()

# File writing
# strace results
async def strace_write(b):
    for line in r.stderr.decode('utf-8', errors='replace').splitlines():
        if "execve" in line:
            strace_append.setdefault(b, [])
            strace_append[b].append(line)
    if args.output in ("terminal", "both"):
        print(f"\n{YELLOW}Strace:{RESET} {GREEN}{strace_append}{RESET}")
        print(f"\nTimeouts: {timeout_append}")
    if args.output in ("logs", "both"):
        # strace write to file
        with open(STRACE_OUT, "w") as f:
            json.dump(strace_append, f)

        # timeout write to file
        with open(TIMEOUT_OUT, "w") as f:
            json.dump(timeout_append, f)
# strings results
async def strings_write(b):
    if args.output in ("terminal", "both"):
        print(f"{YELLOW}Strings Found for {MAGENTA}{b}:{RESET} ")
        for string in s_result:
            print(f"    {GREEN}{string}{RESET}")
    if args.output in ("logs", "both"):
        if os.path.exists(STR_OUT):
            with open(STR_OUT, "r") as f:
                passer = json.loads(f.read())
        else:
            passer = {}
        passer[b] = s_result
        with open(STR_OUT, "w", encoding='utf-8') as f:
            json.dump(passer, f)

# flags writing
async def flags_write(b):
    if args.output in ("terminal", "both"):
        # This is the logic for writing any flags found to the file
        flags_append = {}
        if os.path.exists(FLAGS):
            with open(FLAGS, "r") as f:
                flags_append = json.loads(f.read())
        for flag in flags:
            if flag["string"] in s_result:
                flags_append.setdefault(b, [])
                appendItem = {
                    "string": flag["string"],
                    "severity": flag["severity"],
                    "context": flag.get("context", "")
                }
                flags_append[b].append(appendItem)
        for binary, findings in flags_append.items():
            print(f"\n{YELLOW}Flags for {binary}:{RESET}")
            for finding in findings:
                print(f"  {YELLOW}{finding['severity']}{RESET} - {MAGENTA}{finding['string']}{RESET}")
                if args.verbose and "context" in finding:
                    print(f"    {CYAN}Context: {finding['context']}{RESET}")
                print(f"{YELLOW}--------{RESET}")
            with open(FLAGS, "w", encoding='utf-8') as f:
                json.dump(flags_append, f)


# New
async def main():
    with console.status("[blue]Sliding Around... [/blue]"):
        try:
            for binary in agg_result:
                if not binary.startswith("/usr/bin"):
                    pass
                try:
                    results = await asyncio.gather(
                        strings_scan(binary),
                        strace_scan(binary),

                    )
                except:
                    console.print("[red]scan failure[/red]")
                try:
                    write_results = await asyncio.gather(
                        strace_write(binary),
                        strings_write(binary),
                        flags_write(binary),
                    )
                except:
                    console.print("[red]write failure[/red]")

        except:
            console.print("[red]binary failure[/red]")

asyncio.run(main())

# Old
# with console.status(f"{BLUE}Sliding Around...{RESET}"):
    #try:
        #for b in agg_result:
            #if not b.startswith("/usr/bin"):
                #pass
            # try:
                # asynced
                # r = subprocess.run(
                #    ["strace", "-e", "execve", f"{b}"],
                #    stdin=subprocess.DEVNULL,
                #    stdout=subprocess.PIPE,
                #    stderr=subprocess.PIPE,
                #    timeout=timeout_var,
                #    start_new_session=True
                #)
            # except:
                # console.print("[red]strace failure[/red]")

            # try:
                # for line in r.stderr.decode('utf-8', errors='replace').splitlines():
                    # if "execve" in line:
                        # strace_append.setdefault(b, [])
                        # strace_append[b].append(line)
                # if args.output in ("terminal", "both"):
                    # print(f"\n{YELLOW}Strace:{RESET} {GREEN}{strace_append}{RESET}")
                    # print(f"\nTimeouts: {timeout_append}")
                # if args.output in ("logs", "both"):
                    # strace write to file
                    # with open(STRACE_OUT, "w") as f:
                        # json.dump(strace_append, f)

                    # timeout write to file
                    # with open(TIMEOUT_OUT, "w") as f:
                        # json.dump(timeout_append, f)
            # except:
                # console.print("[red]strace write failure[/red]")

            #try:



                # This has been replaced with strings_scan
                # s_result = subprocess.run(
                #     ["strings", "-a", f"{b}"],
                #     capture_output=True, text=True
                # )
                # s_result = s_result.stdout.splitlines()
                # Strings output to terminal
                # if args.output in ("terminal", "both"):
                    # print(f"{YELLOW}Strings Found for {MAGENTA}{b}:{RESET} ")
                    # for string in s_result:
                    #    print(f"    {GREEN}{string}{RESET}")
                # if args.output in ("logs", "both"):
                #     if os.path.exists(STR_OUT):
                #         with open(STR_OUT, "r") as f:
                #             passer = json.loads(f.read())
                #    else:
                #         passer = {}
                #    passer[b] = s_result
                #    with open(STR_OUT, "w", encoding='utf-8') as f:
                #        json.dump(passer, f)
            # except:
                #console.print("[red]strings failure[/red]")
            # try:
                # Checking against gtfobins and appending/printing the results
                if args.gtfo:
                    binary_name = os.path.basename(b)
                if binary_name in gtfo_data.get("executables", {}):
                    entry = gtfo_data["executables"][binary_name]
                    functions = entry.get("functions", {})
                    if "suid" in functions:
                        suid_finding = f"GTFOBins SUID finding {binary_name}"
                    if args.output in ("terminal", "both"):
                        console.print(f"[magenta]--Results for: {b}--[/magenta]]")
                        # getcap
                        result = subprocess.run(["getcap", "-r", f"{b}"], capture_output=True, text=True)  # capability check
                    if result.stdout:
                        cap_append.setdefault(b, [])
                        cap_item = [f"Cap check {b}: {result.stdout}"]
                        cap_append[b].append(cap_item)
                    if args.output in ("terminal", "both"):
                        console.print(f"\n[yellow]getcap: [/yellow][green]{cap_append}[/green]")
                    if args.output in ("logs", "both"):
                        with open(CAP_OUT, "w", encoding='utf-8') as f:
                            json.dump(cap_append, f)
            except:
                console.print("[red]gtfo error[/red]")
                pass

            # This runs strace to track the execve calls
            # and will write both the strace results and
            # the timeouts to seperate files

            # try:
              #  r = subprocess.run(
            # ["strace", "-e", "execve", f"{b}"],
            #        stdin=subprocess.DEVNULL,
            #        stdout=subprocess.PIPE,
            #        stderr=subprocess.PIPE,
            #        timeout=timeout_var,
            #        start_new_session=True
            #)
            #except:
            #    console.print("[red]execve failure[/red]")
            #    pass
            #try:
            #    for line in r.stderr.decode('utf-8', errors='replace').splitlines():
            #        if "execve" in line:
            #            strace_append.setdefault(b, [])
            #            strace_append[b].append(line)
            #except:
            #    console.print("[red]execve write failure[/red]")
            #    pass
            #try:
            #    if args.output in ("terminal", "both"):
            #        console.print(f"\n[yellow]Strace:[/yellow] [green]{strace_append}[/green]")
            #        console.print(f"\nTimeouts: {timeout_append}")
            #    if args.output in ("logs", "both"):
            #        # strace write to file
            #        with open(STRACE_OUT, "w") as f:
            #            json.dump(strace_append, f)
            #        # timeout write to file
            #        with open(TIMEOUT_OUT, "w") as f:
            #            json.dump(timeout_append, f)
            #except:
            #    console.print("[red]Strace write failure/red]")
            #    pass
            try:
                # This is the logic for writing any flags found to the file
                flags_append = {}
                if os.path.exists(FLAGS):
                    with open(FLAGS, "r") as f:
                        flags_append = json.loads(f.read())

                for flag in flags:
                    if flag["string"] in s_result:
                        flags_append.setdefault(b, [])
                        appendItem = {
                            "string": flag["string"],
                            "severity": flag["severity"],
                            "context": flag.get("context", "")
                        }
                        flags_append[b].append(appendItem)

                if args.output in ("terminal", "both"):
                    for binary, findings in flags_append.items():
                        print(f"\n{YELLOW}Flags for {binary}:{RESET}")
                        for finding in findings:
                            print(f"  {YELLOW}{finding['severity']}{RESET} - {MAGENTA}{finding['string']}{RESET}")
                            if args.verbose and "context" in finding:
                                print(f"    {CYAN}Context: {finding['context']}{RESET}")
                    print(f"{YELLOW}--------{RESET}")
                if args.output in ("logs", "both"):
                    with open(FLAGS, "w", encoding='utf-8') as f:
                        json.dump(flags_append, f)
            except:
                console.print("[red]flags failure[/red]")
    except:
        console.print("[red]b failure[/red]")


print(f"{BOLD}{YELLOW}Done!{RESET}")



