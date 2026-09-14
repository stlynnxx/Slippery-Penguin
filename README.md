# Slippery Penguin




***Slippery Penguin is intended strictly for use on systems you own or have explicit authorization
to test. This tool is provided for educational and security research purposes only. The author assumes no liability for misuse or damage caused by this tool. Use responsibly and in accordance with all applicable local, state, and federal laws.***


Slippery Penguin is a local privilege escalation tool
for Linux Systems. It enumerates SUID binaries, checks
capabilities, traces execution calls, and analyzes 
binary strings, checking the results against a ranked 
list of possible indicators for exploration.

*Version:*\
This is v2.1.0, the official release.


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
curl -L https://eclecticelectronics.fly.dev/api/download/2.1.0 -o slipperypenguin-2.1.0.tar.gz
sha256sum slipperypenguin-2.1.0.tar.gz
```
##### Or

```bash
git clone -b dev https://github.com/stlynnxx/Slippery-Penguin.git
cd Slippery-Penguin
chmod +x setup.sh
sudo ./setup.sh
```

### To write output to log files only-
 ```bash
python3 slipperypenguin.py --output logs / python3 slipperypenguin.py -o logs
```

### To write output to the terminal only-
```bash
python3 slipperypenguin.py --output terminal / python3 slipperypenguin.py -o terminal 
```

### To write output to both the log files and the terminal-
```bash
python3 slipperypenguin.py --output both / python3 slipperypenguin.py -o terminal 
```

### To update the GTFOBins data:
```bash
python3 slipperypenguin.py --update-gtfobins / python3 slipperypenguin.py -upgt

```

### Add for checking output against GTFOBins data
```bash
python3 slippperypenguin.py -o [choice] -gtfo
```

### To delete logs and then run the program-
```bash
python3 slipperypenguin.py --del-logs run / python3 slipperypenguin.py -dl run
```
NOTE: This will result in leaving logs in the directory still, it will just be limited to that run.

### To delete logs without running the program after- 
```bash
python3 slipperypenguin.py --del-logs close / python3 slipperypenguin.py -dl close
```

# Contributing

Slippery Penguin is always open for contributions!

Check out the dev branch if you want to contribute to the newest
features (you can read my daily work and goals in the notes file),
or check out the issues list!
