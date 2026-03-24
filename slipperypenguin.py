import subprocess
import os
import json
from datetime import datetime
import argparse
import signal
import sys

# art is from https://www.asciiart.eu/art/2e5ef0982cbcf027
with open('art.txt', 'r') as file:
    content = file.read()
    print(content)

# Setting up argparse
parser = argparse.ArgumentParser("description=SUID enumeration and vulnerability scanning")
parser.add_argument("--output", choices=["terminal", "logs", "both"], default="both", help="Output mode")
parser.add_argument("--storage", type=str, default="./logs", help="Log storage directory")
parser.add_argument("-gtfo", action="store_true", help="Enables GTFO Comparison")
parser.add_argument("-update-gtfobins", action="store_true", help="Download/update GTFOBins database")




args = parser.parse_args()
sys.stdin = open('/dev/tty')


# Setting up dirs
STORAGE_ROOT = args.storage
GTFODIR = STORAGE_ROOT
os.makedirs(GTFODIR, exist_ok=True)
GTFO_FILE = os.path.join(GTFODIR, "gtfobins.json")





# Updating gtfobins logic
if args.update_gtfobins:
    subprocess.run([
        "curl",
        "https://gtfobins.org/api.json",
        "-o",
        GTFO_FILE
    ])
    print(f"[+] GTFOBins updated at {GTFO_FILE}")




gtfo_data = {}

if os.path.exists(GTFO_FILE) and os.path.getsize(GTFO_FILE) > 0:
    with open(GTFO_FILE, "r") as f:
        gtfo_data = json.load(f)

print("Sliding Around...")

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
    {"string": "execve", "severity": "LOW WITH CONTEXT"},
    {"string": "ENCRYPT_METHOD", "severity": "HIGH"},
    {"string": "PASS_MIN_LEN", "severity": "MEDIUM"},
    {"string": "PASS_MAX_LEN", "severity": "MEDIUM"},
    {"string": "FAIL_DELAY", "severity": "MEDIUM"},
    {"string": "FAKE_SHELL", "severity": "HIGH"},
    {"string": "SYS_GID_MAX", "severity": "HIGH"},
    {"string": "fchown", "severity": "LOW"},
    {"string": "fchmod", "severity": "LOW"},
    {"string": "tcsetattr", "severity": "LOW"},
    # "tcsetattr\nwrite",
    {"string": "fork", "severity": "LOW WITH CONTEXT"},
    {"string": "getlogin", "severity": "LOW"},
    {"string": "%s: failed to drop privileges (%s)", "severity": "MEDIUM WITH CONTEXT"},
    {"string": "SUDO_ASKPASS", "severity": "MEDIUM WITH CONTEXT"},
    {"string": "allow_root", "severity": "MEDIUM"},
    {"string": "/bin/sh", "severity": "MEDIUM WITH CONTEXT"},
    {"string": "/usr/sbin:/usr/bin:/sbin:/bin:%s/bin", "severity": "HIGH WITH CONTEXT"},
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
# spinner.stop()
if args.output in ("terminal", "both"):
    print(f"SUIDs: {agg_result}")





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


for b in agg_result:
    if not b.startswith("/usr/bin"):
        continue

    result = subprocess.run(["getcap", "-r", f"{b}"], capture_output=True, text=True)  # capability check
    if result.stdout:
        cap_append.setdefault(b, [])
        cap_item = [f"Cap check {b}: {result.stdout}"]
        cap_append[b].append(cap_item)

    # print(f"Cap check {b}: {result.stdout}")
    # print(f"cap_append contents: {cap_append}")
    if args.output in ("terminal", "both"):
        print(f"getcap: {cap_append}")
    if args.output in ("logs", "both"):
        with open(CAP_OUT, "w", encoding='utf-8') as f:
            json.dump(cap_append, f)

    # This runs strace to track the execve calls
    # and will write both the strace results and
    # the timeouts to seperate files

    try:
        r = subprocess.run(
            ["strace", "-e", "execve", f"{b}"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            start_new_session=True
        )
    except subprocess.TimeoutExpired:
        pass


    if args.output in ("terminal", "both"):
        print(f"strace: {strace_append}")
        print(f"timeouts: {timeout_append}")
    if args.output in ("logs", "both"):
        # strace write to file
        with open(STRACE_OUT, "w") as f:
            json.dump(strace_append, f)

        # timeout write to file
        with open(TIMEOUT_OUT, "w") as f:
            json.dump(timeout_append, f)


    # This runs strings and then writes the results to the file
    s_result = subprocess.run(
        ["strings", "-a", f"{b}"],
         capture_output=True, text=True
    )
    s_result = s_result.stdout.splitlines()


    # Checking against gtfobins and appending/printing the results
    if args.gtfo:
        binary_name = os.path.basename(b)
        if binary_name in gtfo_data.get("executables", {}):
            entry = gtfo_data["executables"][binary_name]
            functions = entry.get("functions", {})
            if "suid" in functions:
                suid_finding = f"GTFOBins SUID finding {binary_name}"
                print(f"GTFO Match: {binary_name}")
        else:
            print(f"No GTFOBins entry for {binary_name}")





    if args.output in ("terminal", "both"):
        print(f"strings: {s_result}")
    if args.output in ("logs", "both"):
        if os.path.exists(STR_OUT):
            with open(STR_OUT, "r") as f:
                passer = json.loads(f.read())
        else:
            passer = {}
        passer[b] = s_result
        with open(STR_OUT, "w", encoding='utf-8') as f:
            json.dump(passer, f)


    # This is the logic for writing any flags found to the file
    flags_append = {}
    if os.path.exists(FLAGS):
        with open(FLAGS, "r") as f:
            flags_append = json.loads(f.read())

    for flag in flags:
        if flag["string"] in s_result:
            flags_append.setdefault(b, [])
            appendItem = f"[{flag['severity']}] Found: {flag['string']}"
            flags_append[b].append(appendItem)


    if args.output in ("terminal", "both"):
        print(f"flags: {flags_append}")
    if args.output in ("logs", "both"):
        with open(FLAGS, "w", encoding='utf-8') as f:
            json.dump(flags_append, f)




