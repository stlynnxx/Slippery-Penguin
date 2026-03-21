import subprocess
import os
import json
from datetime import datetime

# File handling
STORAGE_ROOT = os.environ.get("STORAGE_ROOT", "./logs")
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
    {"string": "getlogin", "severity": "LOW"},]
border = "-----"
print("Working")
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
with open(FIND_OUT, "w") as f:
    json.dump(find_append, f)


print("Working...")


cap_append = {}
strace_append = {}
timeout_append = {}

if os.path.exists(CAP_OUT):
    with open(CAP_OUT, "r") as f:
        cap_append = json.loads(f.read())

if os.path.exists(STRACE_OUT):
       with open(STRACE_OUT, "r") as f:
           strace_append = json.loads(f.read())
if os.path.exists(TIMEOUT_OUT):
       with open(TIMEOUT_OUT, "r") as f:
           timout_append = json.loads(f.read())


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
    with open(CAP_OUT, "w", encoding='utf-8') as f:
        json.dump(cap_append, f)

    # This runs strace to track the execve calls
    # and will write both the strace results and
    # the timeouts to seperate files


    try:
        r = subprocess.run(
            ["strace", "-e", "execve", f"{b}"],
            capture_output=True, text=True, timeout=10
        )
        for line in r.stderr.splitlines():
            if "execve" in line:
                execve_to_print = f"    {line}"
                strace_append.setdefault(b, [])
                strace_append[b].append(execve_to_print)

    except subprocess.TimeoutExpired:
        timeout_to_print = f"    [Timeout] {b}"
        timeout_append.setdefault(b, [])
        timeout_append[b].append(timeout_to_print)
    with open(STRACE_OUT, "w") as f:
        json.dump(strace_append, f)
    with open(TIMEOUT_OUT, "w") as f:
        json.dump(timeout_append, f)


    # This runs strings and then writes the results to the file
    s_result = subprocess.run(
        ["strings", "-a", f"{b}"],
         capture_output=True, text=True
    )
    s_result = s_result.stdout.splitlines()
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
    for f in flags:
        if f["string"] in s_result:

            flags_append.setdefault(b, [])
            appendItem = f"[{f['severity']}] Found: {f['string']}"
            flags_append[b].append(appendItem)

    with open(FLAGS, "w", encoding='utf-8') as f:
        json.dump(flags_append, f)




