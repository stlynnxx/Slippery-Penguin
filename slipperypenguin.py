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
#956



async def strings_scan(b):
    global strings_append
    global timeout_append
    process = await asyncio.create_subprocess_exec(
        "strings",
        "-a",
        b,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await process.communicate()
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        timeout_append[b]
    strings_append[b] = stdout.decode().splitlines()
    # return stdout.decode().splitlines()
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
        console.print(f"[red]strings_scan failure: {e}")
        traceback.print_exc()
# strace scanning
async def strace_scan(b):
    global strace_append
    global timeout_append
    process = await asyncio.create_subprocess_exec(
        "strace", "-e", "execve", b,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await process.communicate()
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        timeout_append[b]
    strace_append = stdout.decode().splitlines()
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

    except Exception as e:
        console.print(f"[red]strace_scan failure: {e}[/red]")
        traceback.print_exc()
    # return stdout.decode().splitlines()

#gtfobins comp
async def gtfo_scan(b):
    global gtfo_append
    if args.gtfo:
        binary_name = os.path.basename(b)
    for exe in gtfo_data.get("executables", []):
        if binary_name in gtfo_data.get("executables", {}):
            entry = gtfo_data["executables"][binary_name]
    try:
        if args.gtfo:
            binary_name = os.path.basename(b)
            entry = gtfo_data["executables"].get(binary_name)
            functions = entry.get("functions", {})
        if "suid" in functions:
            suid_finding = f"GTFOBins SUID finding {binary_name}"
            gtfo_append = suid_finding
        if args.output in ("terminal", "both"):
            console.print(f"[magenta]--Results for: {b}--[/magenta]]")
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
    result = await asyncio.create_subprocess_exec(
        "getcap",
        "-r",
        b,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    try:
        stdout, stderr = await result.communicate()
    except asyncio.TimeoutError:
        result.kill()
        await result.wait()
        timeout_append[b]
    if result.stdout:
        cap_append.setdefault(b, [])
        cap_item = [f"Cap check {b}: {result.stdout}"]
        cap_append[b].append(cap_item)
    if args.output in ("terminal", "both"):
        console.print(f"\n[yellow]getcap: [/yellow][green]{cap_append}[/green]")
    getcap_append = stdout.decode().splitlines()
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
            timeout_append[b]
        if result.stdout:
            cap_append.setdefault(b, [])
            cap_item = [f"Cap check {b}: {result.stdout}"]
            cap_append[b].append(cap_item)
        if args.output in ("terminal", "both"):
            console.print(f"\n[yellow]getcap: [/yellow][green]{cap_append}[/green]")
    except Exception as e:
        console.print(f"[red]get_scan failure: {e}[/red]")
        traceback.print_exc()
# File writing



# strace results
async def strace_write(b):
    global strace_append
    for line in strace_append:
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
    try:
        for line in strace_append.get(b, []):
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
    except Exception as e:
        console.print(f"[red]strace write failure: {e}[/red]")

# strings results
async def strings_write(b):
    global strings_append
    if args.output in ("terminal", "both"):
        print(f"{YELLOW}Strings Found for {MAGENTA}{b}:{RESET} ")
        for string in strings_append:
            print(f"    {GREEN}{string}{RESET}")
    if args.output in ("logs", "both"):
        if os.path.exists(STR_OUT):
            with open(STR_OUT, "r") as f:
                passer = json.loads(f.read())
        else:
            passer = {}
        passer[b] = strace_append
        with open(STR_OUT, "w", encoding='utf-8') as f:
            json.dump(passer, f)
    try:
        if args.output in ("terminal", "both"):
            print(f"{YELLOW}Strings Found for {MAGENTA}{b}:{RESET} ")
            for string in strings_append:
                print(f"    {GREEN}{string}{RESET}")
        if args.output in ("logs", "both"):
            if os.path.exists(STR_OUT):
                with open(STR_OUT, "r") as f:
                    passer = json.loads(f.read())
            else:
                passer = {}
            passer[b] = strings_append
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
    if args.output in ("terminal", "both"):
        # This is the logic for writing any flags found to the file
        flags_append = {}
        if os.path.exists(FLAGS):
            with open(FLAGS, "r") as f:
                flags_append = json.loads(f.read())
        for flag in flags:
            if flag["string"] in strings_append:
                flags_append.setdefault(b, [])
                appendItem = {
                    "string": flag["string"],
                    "severity": flag["severity"],
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
            print(f"\n{YELLOW}Flags for {binary}:{RESET}")
            for finding in findings:
                print(f"  {YELLOW}{finding['severity']}{RESET} - {MAGENTA}{finding['string']}{RESET}")
                if args.verbose and "context" in finding:
                    print(f"    {CYAN}Context: {finding['context']}{RESET}")
                print(f"{YELLOW}--------{RESET}")
            with open(FLAGS, "w", encoding='utf-8') as f:
                json.dump(flags_append, f)
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
    except Exception as e:
        console.print(f"[red]gtfo error: {e}[/red]")
        traceback.print_exc()
        pass

# getcap results writing
async def getcap_write(b):
@@ -392,8 +424,9 @@ async def getcap_write(b):
        if args.output in ("logs", "both"):
            with open(CAP_OUT, "w", encoding='utf-8') as f:
                json.dump(cap_append, f)
    except:
        console.print("[red]gtfo error[/red]")
    except Exception as e:
        console.print(f"[red]gtfo error: {e}[/red]")
        traceback.print_exc()
        pass

# gtfobins results writing
@@ -403,207 +436,47 @@ async def gtfo_write(b):
        if args.output in ("logs", "both"):
            with open(GTFO_OUT, "w", encoding='utf-8') as f:
                json.dump(gtfo_append, f)
    except:
        console.print("[red]gtfo write error[/red]")
    except Exception as e:
        console.print(f"[red]gtfo write error : {e}[/red]")


# New
async def main():
    with console.status("[blue]Sliding Around... [/blue]"):
        # try:
    with (console.status("[blue]Sliding Around... [/blue]")):
        try:
            for binary in agg_result:
                if not binary.startswith("/usr/bin"):
                    continue
                try:
                    results = await asyncio.gather(
                        await strings_scan(binary),
                        await strace_scan(binary),
                        await gtfo_scan(binary),
                        strings_scan(binary),
                        strace_scan(binary),
                        gtfo_scan(binary),


                    )
                except:
                    console.print("[red]scan failure[/red]")
                except Exception as e:
                    console.print(f"[red]scan failure: {e}[/red]")
                    traceback.print_exc()
                try:
                    write_results = await asyncio.gather(
                        await strace_write(binary),
                        await strings_write(binary),
                        await flags_write(binary),
                        await getcap_write(binary),
                        await gtfo_write(binary),
                        strace_write(binary),
                        strings_write(binary),
                        flags_write(binary),
                        getcap_write(binary),
                        gtfo_write(binary),

                    )
                except:
                    console.print("[red]write failure[/red]")
                except Exception as e:
                    console.print(f"[red]write failure: {e}[/red]")
                    traceback.print_exc()

        # except:
            # console.print("[red]main failure[/red]")
        except Exception as e:
            console.print(f"[red]main failure: {e}[/red]")
            traceback.print_exc()

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
                # if args.gtfo:
                #    binary_name = os.path.basename(b)
                # if binary_name in gtfo_data.get("executables", {}):
                #    entry = gtfo_data["executables"][binary_name]
                #    functions = entry.get("functions", {})
                #    if "suid" in functions:
                #        suid_finding = f"GTFOBins SUID finding {binary_name}"
                #    if args.output in ("terminal", "both"):
                #        console.print(f"[magenta]--Results for: {b}--[/magenta]]")
                        # getcap
               #         result = subprocess.run(["getcap", "-r", f"{b}"], capture_output=True, text=True)  # capability check
               #     if result.stdout:
               #         cap_append.setdefault(b, [])
               #         cap_item = [f"Cap check {b}: {result.stdout}"]
               #         cap_append[b].append(cap_item)
               #     if args.output in ("terminal", "both"):
               #         console.print(f"\n[yellow]getcap: [/yellow][green]{cap_append}[/green]")
               #     if args.output in ("logs", "both"):
               #         with open(CAP_OUT, "w", encoding='utf-8') as f:
               #             json.dump(cap_append, f)
            #except:
            #    console.print("[red]gtfo error[/red]")
            #    pass

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
           # try:
                # This is the logic for writing any flags found to the file
           #     flags_append = {}
           #     if os.path.exists(FLAGS):
           #         with open(FLAGS, "r") as f:

           #             flags_append = json.loads(f.read())

           #     for flag in flags:
           #         if flag["string"] in s_result:
           #             flags_append.setdefault(b, [])
           #             appendItem = {
           #                 "string": flag["string"],
           #                 "severity": flag["severity"],
           #                 "context": flag.get("context", "")
           #             }
           #             flags_append[b].append(appendItem)

          #      if args.output in ("terminal", "both"):
          #          for binary, findings in flags_append.items():
          #              print(f"\n{YELLOW}Flags for {binary}:{RESET}")
          #              for finding in findings:
          #                  print(f"  {YELLOW}{finding['severity']}{RESET} - {MAGENTA}{finding['string']}{RESET}")
          #                  if args.verbose and "context" in finding:
          #                      print(f"    {CYAN}Context: {finding['context']}{RESET}")
          #          print(f"{YELLOW}--------{RESET}")
          #      if args.output in ("logs", "both"):
          #          with open(FLAGS, "w", encoding='utf-8') as f:
          #              json.dump(flags_append, f)
          #  except:
          #      console.print("[red]flags failure[/red]")
    #except:
    #    console.print("[red]b failure[/red]")


print(f"{BOLD}{YELLOW}Done!{RESET}")
