# Slippery Penguin

***Slippery Penguin is intended strictly for use on systems you own or have explicit authorization
to test. This tool is provided for educational and security research purposes only. The author assumes no liability for misuse or damage caused by this tool. Use responsibly and in accordance with all applicable local, state, and federal laws.***

**Local privilege escalation enumeration for Linux systems**

Slippery Penguin enumerates SUID binaries, checks file capabilities, traces
execution calls, extracts strings, and checks the results against a ranked 
list of possible indicators for exploration.

*Version:*\
This is the official release, v1.1.0, released on 8/17/2026.

You are welcome to use the dev branch 
for the newest features and updates,
but I cannot promise it is ever stable.

*Features:*
- SUID binary enumeration across the entire filesystem via `find`
- Capability checking via `getcap -r`
- Execution call tracing via `strace -e execve`
- Binary string analysis against a customizable watchlist
- Checks discovered binaries against GTFOBins data, filtered by SUID context
- All four scans run in parallel per binary via
  `asyncio.gather`, throttled by a semaphore to avoid system overload
- Child processes are isolated from your TTY, and orphaned children are killed via process group signals
- Timestamped individualized JSON file for each type of scan result


*Requirements:*\
-Linux\
-Python 3\
-strace\
-getcap\
-curl\
-rich

The JSON files are stored in /SlipperyPenguin/logs, within timestamped directories.
Each form of output has it's own json file within the timestamped directory. 

Flags.json can be found in the project dir and is easily customizable. 

Usage:

Quick installation-
```bash
git clone -b dev https://github.com/stlynnxx/Slippery-Penguin.git
cd Slippery-Penguin
chmod +x setup.sh
sudo ./setup.sh
```

To write output to log files only-
 ```bash
python3 slipperypenguin.py --output logs
```
To write output to the terminal only-
```bash
python3 slipperypenguin.py --output terminal
```

To write output to both the log files and the terminal-
```bash
python3 slipperypenguin.py --output both
```
To update the GTFOBins data:
```bash
python3 slipperypenguin.py -update-gtfobins

```

Add for checking output against GTFOBins data
```bash
-gtfo
```

To delete logs and then run the program-
```bash
-del-logs run
```
NOTE: This will result in leaving logs in the directory still, it will just be limited to that run.

To delete logs without running the program after- 
```bash
-del-logs close
```

# Contributing

Slippery Penguin is always open for contributions!

Check out the dev branch if you want to contribute to the newest
features (you can read my daily work and goals in the notes file),
or check out the issues list!

Flags contributions would be *huge*; if anyone out there has any 
findings that they added to their personal flags.json or think should
be added to the repository's please send them my way! 







