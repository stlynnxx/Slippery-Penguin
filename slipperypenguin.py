import subprocess
import os
import json
from datetime import datetime
import argparse
import sys
import shutil


from rich.console import Console
import asyncio
import traceback



#1000
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
# sys.stdin = open('/dev/tty')
timeout_var = 5





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
          "with -update-gtfobins being optional if your data is up to date.")
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
    timeout_var = int(input(f"[yellow]Enter custom timeout value: [/yellow]"))

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
TIMEOUT_OUT = os.path.join(RUN_DIR, "timeout-out.json")
GTFO_OUT = os.path.join(RUN_DIR, "gfto-out.json")


# The flags list itself

border = "-----"

# The datetime
dt = str(datetime.now())



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
flags = {}

# loading the flags from json
try:
    with open("flags.json", 'r') as file:
        flags = json.load(file)
except FileNotFoundError as e:
    console.print("[red]Flags load failure: {e}[/red]")
    traceback.print_exc()

if os.path.exists(CAP_OUT):
    with open(CAP_OUT, "r") as f:
        cap_append = json.loads(f.read())

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
    async with semaphore:
        async with lock:
            target[b] = data




# Scans
# This is for running the strings scan on a given binary
async def strings_scan(b):
    async with semaphore:
        # Debug
        if args.output in ("logs"):
            print("strings scan started")
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
                # strings_append[b] = stdout.decode().splitlines()
                await append(strings_append, b, stdout.decode().splitlines())
            except TimeoutError:
                process.kill()
                try:
                    await process.wait()
                except (asyncio.CancelledError, Exception) as e:
                    pass
                finally:
                    # DB
                    if args.output in ("logs"):
                        print("strings scan finished")
                    timeout_append[b] = "timeout"

            # return stdout.decode().splitlines()
        except Exception as e:
            console.print(f"[red]strings_scan failure: {e}[/red]")
            traceback.print_exc()

# strace scanning
async def strace_scan(b):
    async with semaphore:
        # DB
        if args.output ("logs"):
            print("strace scan started")
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
                await append(strace_append, b, stdout.decode().splitlines())
                # strace_append[b] = stderr.decode().splitlines()
            except TimeoutError:
                try:
                    process.terminate()
                except Exception as e:
                    console.print(f"[red]process.terminate failure, {e}[/red]")
                    pass

                try:
                    if process.returncode is None:
                        process.kill()

                except Exception as e:
                    console.print(f"[red]process.kill failure, {e}[/red]")
                    pass
                try:
                    await process.wait()
                except (asyncio.CancelledError, Exception) as e:
                    console.print(f"[red]await process.wait() failure, {e}[/red]")
                    pass
                finally:
                    # DB
                    if args.output in ("logs"):
                        print("strace scan finished")
                    timeout_append[b] = "timeout"
            if args.output in ("terminal", "both"):
                print(f"\n[yellow]Strace:[/yellow][green]{strace_append}[/green]")
        except Exception as e:
            console.print(f"[red]strace_scan failure: {e}[/red]")
            traceback.print_exc()
        # return stdout.decode().splitlines()

#gtfobins comp
async def gtfo_scan(b):
    async with semaphore:
        # DB
        if args.output in ("logs"):
        print("gtfo scan started")
        global gtfo_append
        try:
            if args.gtfo:
                binary_name = os.path.basename(b)
                entry = gtfo_data["executables"].get(binary_name)
                if entry:
                    functions = entry.get("functions", {})
                    for func_type, methods in functions.items():
                        for method in methods:
                            contexts = method.get("contexts", {})
                            if "suid" in contexts:
                                console.print(f"[magenta]--Results for: {b}--[/magenta]")
                                console.print(f"[cyan]  SUID exploit: {func_type}[/cyan]")
                                # DB
                                # if args.output in ("logs"):
                                #     print("gtfo scan finished")
        except Exception as e:
            console.print(f"[red]gtfo comp failure: {e}[/red]")
            traceback.print_exc()

# getcap scan
async def get_scan():
    async with semaphore:
        # DB
        if args.output in ("logs"):
             print("get scan started")
        global getcap_append
        global dt
        global strings_append
        global flags_append
        global timeout_append
        for flag in flags_append:
            if flag["string"] in strings_append.get(flag, {}):
                try:
                    result = await asyncio.create_subprocess_exec(
                    "getcap",
                    "-r",
                        flag,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    try:
                        stdout, stderr = await asyncio.wait_for(result.communicate(), timeout=timeout_var)
                        getcap_append[dt] = stdout.decode().splitlines()
                        try:
                            if stdout:
                                cap_append.setdefault(dt, [])
                                cap_item = [f"Cap check {dt}: {result.stdout}"]
                                cap_append[dt].append(cap_item)
                            if args.output in ("terminal", "both"):
                                console.print(f"\n[yellow]getcap: [/yellow][green]{cap_append}[/green]")
                        except Exception as e:
                            console.print(f"[red]get_scan failure: {e}[/red]")
                            traceback.print_exc()
                    except TimeoutError:
                        result.kill()
                except (asyncio.CancelledError, Exception) as e:
                    console.print(f"getcap flag append failure {e}")
                    traceback.print_exc()
            else:
                console.print("[magenta]No strings matches found for getcap scan[/magenta]")

        try:
            await result.wait()
        except (asyncio.CancelledError, Exception) as e:
            pass
        finally:
            timeout_append[dt] = "timeout"
            # DB
            if args.output in ("logs"):
                print("get scan finished")

async def timeouts(b):
    asyncio with semaphore:
        global timeout_append
        try:
            if args.output in ("terminal", "both"):
                console.print("[yellow]Timeouts:[/yellow]")
                for t in timeout_append:
                    console.print(f"\n[green] {t}[/green]")
                with open(TIMEOUT_OUT, "w") as f:
                    json.dump(timeout_append, f)
            if args.output in ("logs"):
                print("timeout write")
        except Exception as e:
            console.print(f"[red]timeouts failure: {e}[/red]")
            traceback.print_exc()


# File writing



# strace results
def strace_write(b):
    global strace_append
    try:
        if args.output in ("terminal", "both"):
            # strace write to file
            with open(STRACE_OUT, "w") as f:
                json.dump(strace_append, f)
        if args.output in ("logs"):
            print("strace write")
    except Exception as e:
        console.print(f"[red]strace write failure: {e}[/red]")
        traceback.print_exc()

# strings results
def strings_write(b):
    if args.output in ("logs"):
        print("strings write start")
    global strings_append
    try:
        if args.output in ("terminal", "both"):
            console.print(f"[yellow]Strings Found for [/yellow][magenta] {b}:[/magenta] ")
            for string in strings_append.get(b, {}):
                console.print(f"    [green]{string}[/green]")
        if args.output in ("logs", "both"):
            if os.path.exists(STR_OUT):
                with open(STR_OUT, "r") as f:
                    passer = json.loads(f.read())
            else:
                passer = {}
            passer[b] = strings_append.get(b, {})
            with open(STR_OUT, "w", encoding='utf-8') as f:
                json.dump(passer, f)
        if args.output in ("logs"):
            print("strings write")
    except Exception as e:
        console.print(f"[red]strings write failure: {e}[/red]")
        traceback.print_exc()
        pass

# flags writing

def flags_write_print():
    global flags_append
    global strings_append

async def flags_write(b):
    if args.output in ("logs"):
        print("Flags write start")
    global flags_append
    global strings_append
    try:
        if args.output in ("terminal", "both"):
            # This is the logic for writing any flags found to the file
            for flag in flags:
                if flag["string"] in strings_append.get(b, {}):
                    flags_append.setdefault(b, {})
                    appendItem = {
                        "string": flag["string"],
                        "severity": flag["severity"],
                        "context": flag.get("context", "")
                    }
                    flags_append[b] = appendItem
            try:
                with open("flags.json", 'r') as file:
                    json.dump(flags_append, file)
                if args.output in ("logs"):
                    print("flags write")
            except FileNotFoundError as e:
                console.print("[red]Flags dump failure: {e}[/red]")
                traceback.print_exc()
    except Exception as e:
        console.print(f"[red]gtfo error: {e}[/red]")
        traceback.print_exc()
        pass

# getcap results writing
def getcap_write(b):
    global cap_append
    try:
        if args.output in ("terminal", "both"):
            with open(CAP_OUT, "w", encoding='utf-8') as f:
                json.dump(cap_append, f)
            if args.output in ("logs"):
                print("cap write")
    except Exception as e:
        console.print(f"[red]gtfo error: {e}[/red]")
        traceback.print_exc()
        pass

# gtfobins results writing
def gtfo_write(b):
    global gtfo_append
    try:
        if args.output in ("terminal", "both"):
            with open(GTFO_OUT, "w", encoding='utf-8') as f:
                json.dump(gtfo_append, f)
            if args.output in ("logs"):
                print("gtfo write")
    except Exception as e:
        console.print(f"[red]gtfo write error : {e}[/red]")


# New
async def main():
        with (console.status("[blue]Sliding Around... [/blue]")):
            print("1000")
            try:
                for binary in agg_result:
                    if not binary.startswith("/usr/bin"):
                        continue
                    try:
                        results = await asyncio.gather(
                            strings_scan(binary),
                            flags_write(binary),
                            strace_scan(binary),
                            gtfo_scan(binary),
                            timeouts(binary),
                            return_exceptions=True


                        )

                        await get_scan()
                        if args.output in ("logs"):
                            print("Moving along..")
                    except (asyncio.CancelledError, Exception) as e:
                        console.print(f"[red]scan failure: {e}[/red]")
                        traceback.print_exc()
                        pass
                    try:
                        # flags_write(binary)
                        getcap_write(binary)
                        gtfo_write(binary)
                        strace_write(binary)
                        strings_write(binary)



                        # DB
                        if args.output in ("logs"):
                            print("Tried!")
                        if args.output in ("terminal", "both"):
                            flags_write_print()
                        # DB
                        if args.output in ("logs"):
                            print("Wow!")
                    except (Exception) as e:
                        console.print(f"[red]write failure: {e}[/red]")
                        traceback.print_exc()
                        pass

            except Exception as e:
                console.print(f"[red]main failure: {e}[/red]")
                traceback.print_exc()
                pass

            if args.output in ("logs"):
                print("The end")
        return 0




asyncio.run(main())

print(f"[bold bright_green]Done![/bold bright_green]")
