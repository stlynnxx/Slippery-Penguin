import subprocess

watchlist = [
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
print("Working")
agg_result = []
# Enumerates SUIDs and checking capabilites
result = subprocess.run( ["find", "/", "-perm", "-4000", "-type", "f"], capture_output=True, text=True)
agg_result = result.stdout.splitlines()
print(result.stdout)
print("Working...")
for b in agg_result:
    if not b.startswith("/usr/bin"):
        continue

    result = subprocess.run(["getcap", "-r", f"{b}"], capture_output=True, text=True) #capability check
    print(f"Cap check {b}: {result.stdout}")


    # tracking execution runs
    try:
        r = subprocess.run(
            ["strace", "-e", "execve", f"{b}"],
            capture_output=True, text=True, timeout=10
        )
        for line in r.stderr.splitlines():
            if "execve" in line:
                print(f"    {line}")
    except subprocess.TimeoutExpired:
        print(f"    [Timeout] {b}")



    s_result = subprocess.run(
        ["strings", "-a", f"{b}"],
    )
    s_result = s_result.stdout.splitlines()
    print(s_result)



