import signal, subprocess,os, json, argparse, sys, shutil, urllib.request, tempfile,hashlib,asyncio,traceback
import tarfile, urllib.error
from datetime import datetime
from rich.console import Console

# Version
__version__ = "2.1.0"
console = Console()
UPDATE_URL = "https://eclecticelectronics.fly.dev/api/check-update/"

# art is from https://www.asciiart.eu/art/2e5ef0982cbcf027
with open('art.txt', 'r') as file:
    content = file.read()
    console.print(f"[green]{content}[/green]")

# Setting up argparse
parser = argparse.ArgumentParser("SUID enumeration and vulnerability scanning")
parser.add_argument("--output", "-o", choices=["terminal", "logs", "both"], default="terminal", help="Output mode")
parser.add_argument("--storage", "-s", type=str, default="./logs", help="Log storage directory")
parser.add_argument("-gtfo", action="store_true", help="Enables GTFO Comparison")
parser.add_argument("--update-gtfobins", "-upgt", action="store_true", help="Download/update GTFOBins database")
parser.add_argument("--del-logs", "-dl", choices=["run", "close"],  default=None, help="Delete Logs")
parser.add_argument("--timeout", "-t", action="store_true", help="Used for changing timeout var, default is 10")
parser.add_argument("--cleanup", "-c", action="store_true", help="Deletes all data and uninstalls the program")
parser.add_argument("--update", "-u", choices=["run", "close"], help="Download and install the latest version")
parser.add_argument("--check", "-chk", action="store_true", help="Check the current version")
parser.add_argument("--manual", "-man", action="store_true", help="Manual")

args = parser.parse_args()
# sys.stdin = open('/dev/tty')
timeout_var = 2





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

if args.manual:
    console.print("[cyan]If this is a fresh download, run -update-gtfobins for the most up to date data.[/cyan]")
    print("--output both:       Writes results in the terminal and to logs")
    print("--output terminal:   Writes results to the terminal only")
    print("--output logs:       Writes results to the logs only")
    print("-gtfo:               Checks results against GTFOBins data, data follows output choice")
    print("-update-gtfobins:    Updates GTFOBins data from the GTFOBins API endpoint")
    print("-del-logs:           Deletes all logs that are currently stored")
    print("-timeout:            Allows the user to set the timeout value, default is 2")
    print("-help:               How you got here")

    print("An example command:\npython3 slipperypenguin.py --output logs -gtfo -update-gtfo,\n" +
          "with -update-gtfobins being optional if your data is up to date.")
    sys.exit(0)




# Updating gtfobins logic
try:
    if args.update_gtfobins:
        subprocess.run([
            "curl",
            "https://gtfobins.org/api.json",
            "-o",
            GTFO_FILE
        ])
        print(f"GTFOBins updated at {GTFO_FILE}")
        sys.exit(0)
except Exception as e:
    console.print(f"[red]Updating GTFObins failed, {e}[/red]")
# Checking for available updates
if args.check:
    print(f"Current version: {__version__}")
    # This is where we will contact the server for updates whenever i'm finished setting all of that up.
    try:
        with urllib.request.urlopen(UPDATE_URL + __version__, timeout=10) as resp:
            update_info = json.loads(resp.read().decode())
    except (urllib.error.URLError, json.JSONDecodeError) as e:
        print(f"[-] Could not reach update server: {e}")
        sys.exit(1)
    latest = update_info.get("latest", "")
    if latest == __version__:
        print("[+] Up to date.")
    else:
        print(f"[*] Update available: {latest} (you are running {__version__})")
        print(update_info.get("notes", ""))
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




border = "-----"





if os.path.exists(FIND_OUT):
    with open(FIND_OUT, "r") as f:
        find_append = json.loads(f.read())


# Updating logic helper functions
if args.update in ("run", "close"):
    try:
        # Updating gtfobins logic
        subprocess.run([
            "curl",
            "https://gtfobins.org/api.json",
            "-o",
            GTFO_FILE
        ])
        print(f"GTFOBins updated at {GTFO_FILE}")
    except Exception as e:
        console.print(f"[red]Could not update GTFOBins, {e}[/red]")
    try:
        def download_update(url,expected_hash):
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
            except Exception as e:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
                raise e
    except Exception:
        console.print(f"[red]{Exception}[/red]")
        exit(-1)
    try:
        def extract_update(tmp_path):
            extract_dir = tempfile.mkdtemp()
            with tarfile.open(tmp_path, "r:gz") as tar:
                tar.extractall(extract_dir, filter="data")

            required = ["slipperypenguin.py", "art.txt", "flags.json"]
            extracted_names = os.listdir(extract_dir)
            for name in required:
                if name not in extracted_names:
                    raise RuntimeError(
                        "Incomplete package, download aborted"
                    )
            return extract_dir
    except Exception:
        console.print(f"[red]{Exception}[/red]")
        exit(-1)
    try:
        def install_update(extract_dir):
            install_root = os.path.dirname(os.path.abspath(__file__))
            for fname in os.listdir(extract_dir):
                src = os.path.join(extract_dir, fname)
                dst = os.path.join(install_root, fname)
                os.replace(src, dst)
            shutil.rmtree(extract_dir)
    except Exception:
        console.print(f"[red]{Exception}[/red]")
        exit(-1)
    console.print("[green]Update Successful![/green]")
    if args.update in ("run"):
        pass
    if args.update in ("close"):
        exit(0)

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
    # Debug
    #if args.output in ("logs"):
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
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout_var)
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

# strace scanning
async def strace_scan(b):
    global strace_append, timeout_append
    try:
        process = await asyncio.create_subprocess_exec(
            "timeout", str(timeout_var), "strace", "-e", "execve", b,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=timeout_var
            )
            await append(strace_append, b, stderr.decode().splitlines())
        except TimeoutError:
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            await process.wait()
            await append(timeout_append, b, "timeout")
        if args.output in ("terminal", "both"):
            print(f"\nStrace for {b}: {strace_append.get(b, [])}")
    except Exception as e:
        console.print(f"[red]strace_scan failure: {e}[/red]")
        traceback.print_exc()

#gtfobins comp
async def gtfo_scan(b):
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
    except Exception as e:
        console.print(f"[red]gtfo comp failure: {e}[/red]")
        traceback.print_exc()

# getcap scan
async def get_scan():
    global getcap_append
    global strings_append
    global flags_append
    global timeout_append
    dt = str(datetime.now())
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
                    # await append(getcap_append, dt, stdout.decode().splitlines())
                    # getcap_append[dt] = stdout.decode().splitlines()
                    try:
                        if stdout:
                            cap_append.setdefault(dt, [])
                            cap_item = [f"Cap check {dt}: {result.stdout.decode().splitlines()}"]
                            await append(getcap_append, dt, cap_item)
                            # cap_append[dt].append(cap_item)
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


async def timeouts(b):
    global timeout_append

    try:
        if args.output in ("terminal", "both"):
            console.print("[yellow]Timeouts:[/yellow]")
            for t in timeout_append:
                console.print(f"\n[green] {t}[/green]")
            with open(TIMEOUT_OUT, "w") as f:
                json.dump(timeout_append, f)
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
    except Exception as e:
        console.print(f"[red]strace write failure: {e}[/red]")
        traceback.print_exc()

# strings results
def strings_write(b):
    passer = {}
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
    except Exception as e:
        console.print(f"[red]strings write failure: {e}[/red]")
        traceback.print_exc()
        pass

# flags writing

def flags_write_print():
    global flags_append
    global strings_append

# flags writing
async def flags_write(b):
    global flags_append
    global strings_append
    try:
        if args.output in ("terminal", "both"):
            for flag in flags:
                if flag["string"] in strings_append.get(b, {}):
                    flags_append.setdefault(b, [])
                    appendItem = {
                        "string": flag["string"],
                        "severity": flag["severity"],
                        "context": flag.get("context", "")
                    }
                    flags_append[b].append(appendItem)


        with open("flags.json", 'w') as file:
            json.dump(flags_append, file)
    except Exception as e:
        console.print(f"[red]Flags dump failure: {e}[/red]")
        traceback.print_exc()

# getcap results writing
def getcap_write(b):
    global cap_append
    try:
        if args.output in ("terminal", "both"):
            with open(CAP_OUT, "w", encoding='utf-8') as f:
                json.dump(cap_append, f)
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
    except Exception as e:
        console.print(f"[red]gtfo write error : {e}[/red]")


# New
async def main():
        with (console.status("[blue]Sliding Around... [/blue]")):
            #print("1000")
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

                            return_exceptions=True


                        )
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
                        await get_scan()
                    except (Exception) as e:
                        console.print(f"[red]write failure: {e}[/red]")
                        traceback.print_exc()
                        pass
            except Exception as e:
                console.print(f"[red]main failure: {e}[/red]")
                traceback.print_exc()
                pass
            try:
                await timeouts(binary)
            except (Exception) as e:
                console.print({e})
        return 0
asyncio.run(main())
console.print(f"[bold bright_green]Done![/bold bright_green]")
