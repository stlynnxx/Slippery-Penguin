# Slippery Penguin




***Slippery Penguin is intended strictly for use on systems you own or have explicit authorization
to test. This tool is provided for educational and security research purposes only. The author assumes no liability for misuse or damage caused by this tool. Use responsibly and in accordance with all applicable local, state, and federal laws.***


Slippery Penguin is a local privilege escalation tool
for Linux Systems. It enumerates SUID binaries, checks
capabilities, traces execution calls, and analyzes 
binary strings, checking the results against a ranked 
list of possible indicators for exploration.

*Version:*\
This is the dev branch, where I push my in progress work to.
You are welcome to use it at any point you would like if you are 
interested, it may have new/improved features not present in the 
official release, however, it is not promised to always be stable
as I will be actively working on it from time to time.


*Features:*\
-SUID binary enumeration across the filesystem\
-Capability checking via getcap\
-Execution call tracing via strace\
-Binary string analysis against a severity-rated watchlist\
-Configurable path filtering and timeout handling\
-JSON Logging


*Requirements:*\
-Linux\
-Python 3\
-strace\
-getcap

The JSON files are stored in /SlipperyPenguin/logs, within timestamped directories.
Each form of output has it's own json file within the timestamped directory. 


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
