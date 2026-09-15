# Slippery Penguin




***Slippery Penguin is intended strictly for use on systems you own or have explicit authorization
to test. This tool is provided for educational and security research purposes only. The author assumes no liability for misuse or damage caused by this tool. Use responsibly and in accordance with all applicable local, state, and federal laws.***



Slippery Penguin is a local privilege escalation tool
for Linux Systems. It enumerates SUID binaries, checks
capabilities, traces execution calls, and analyzes 
binary strings, checking the results against a ranked 
list of possible indicators for exploration.

*Version:*\
This is v2.1.2, the official release.

The only change from v2.1.1 was a bug fix.

*Features:*\
-SUID binary enumeration across the filesystem\
-Capability checking via getcap\
-Execution call tracing via strace\
-Binary string analysis against a severity rated watchlist\
-Configurable path filtering and timeout handling\
-JSON Logging
- Automatic updating and update checking

*Requirements:*\
-Linux\
-Python 3\
-strace\
-getcap\
-curl\
-git

The JSON files are stored in /SlipperyPenguin/logs, within timestamped directories.
Each form of output has it's own json file within the timestamped directory. 


Quick installation-
```bash
curl -L https://eclecticelectronics.fly.dev/api/download/2.1.0 -o slipperypenguin-2.1.2.tar.gz
sha256sum slipperypenguin-2.1.2.tar.gz
```
##### Or

```bash
git clone -b dev https://github.com/stlynnxx/Slippery-Penguin.git
cd Slippery-Penguin
chmod +x setup.sh
sudo ./setup.sh
```

Usage:
### To write output to log files only-
 ```bash
python3 slipperypenguin.py --output logs
```
#### OR
```bash
python3 slipperypenguin.py -o logs
```

### To write output to the terminal only-
```bash
python3 slipperypenguin.py --output terminal
```
#### OR
```bash
python3 slipperypenguin.py -o terminal
```


### To write output to both the log files and the terminal-
```bash
python3 slipperypenguin.py --output both
```
#### OR
```bash
python3 slipperypenguin.py -o both
```

### To update the GTFOBins data:
```bash
python3 slipperypenguin.py --update-gtfobins

```
#### OR
```bash
python3 slipperypenguin.py -upgt
```


### Add for checking output against GTFOBins data
```bash
python3 slipperypenguin.py -o [choice]-gtfo
```

### To delete logs and then run the program-
```bash
python3 slipperypenguin.py --del-logs run
```
#### OR
```bash
python3 slipperypenguin.py -dl run
```

NOTE: This will result in leaving logs in the directory still, it will just be limited to that run.

### To delete logs without running the program after- 
```bash
python3 slipperypenguin.py --del-logs close
```
#### OR
```bash
python3 slipperypenguin.py -dl close
```

### To bring up the help menu-
```bash
python3 slipperypenguin.py --help
```
#### OR
```bash
python3 slipperypenguin.py -h
```
### To change the default timeout value-
```bash
python3 slipperypenguin.py --timeout 
```
#### OR
```bash
python3 slipperypenguin.py -t
```

### Cleanup Logs-
```bash
python3 slipperypenguin.py --cleanup
```
#### OR
```bash
python3 slipperypenguin.py -c
```
### Update the Program and run afterwards
```bash
python3 slipperypenguin.py --update run
```
#### OR
```bash
python3 slipperypenguin.py -u
```

### Update the Program and Close
```bash
python3 slipperypenguin.py --update close
```
#### OR
```bash
python3 slipperypenguin.py -u close
```
### Check for updates

### Update the Program and run afterwards
```bash
python3 slipperypenguin.py --check
```
#### OR
```bash
python3 slipperypenguin.py -c
```





# Contributing

Slippery Penguin is always open for contributions!

Check out the dev branch if you want to contribute to the newest
features (you can read my daily work and goals in the notes file),
or check out the issues list!

### Donations
I am physically disabled and do this and hardware repair to support myself; if you feel generous and 
can afford to do so, every penny helps out! 

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/H5F5269IH4)
