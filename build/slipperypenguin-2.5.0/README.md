***Slippery Penguin is intended strictly for use on systems you own or have explicit authorization
to test. This tool is provided for educational and security research purposes only. The author assumes no liability for misuse or damage caused by this tool. 
Use responsibly and in accordance with all applicable local, state, and federal laws.***



# Slippery Penguin



**SUID Enumeration and Vulnerability Scanning Tool**

Slippery Penguin is a security auditing tool designed to enumerate SUID binaries, scan for dangerous capabilities, and cross-reference findings against the GTFOBins database to identify potential privilege escalation vectors.

[![XERJ Corpus Hub contributor](https://hub.xerj.org/contributors/stlynnxx/badge.svg)](https://hub.xerj.org/contributors/stlynnxx)

Now featured in the Xerj Corpus! Check Xerj out at https://github.com/xerj-org/xerj

##  Features

**SUID Enumeration**: Recursively scans filesystem for SUID binaries (`-perm -4000`) 
**Capability Scanning**: Detects Linux capabilities on binaries via `getcap` 
**Strings Analysis**: Extracts strings from binaries for hidden credentials/paths 
**Strace Monitoring**: Tracks system calls made by SUID binaries 
**GTFOBins Matching**: Cross-references binaries against GTFOBins exploit database 
**Report Generation**: Export results as HTML or PDF 
**Auto-Updates**: Built-in update checker and installer 
**Concurrent Scanning**: Async architecture with configurable concurrency (5 workers) 
**Multiple Output Modes**:" Terminal, logs, or both 


## Requirements

```bash
pip install rich yattag weasyprint
```

**External dependencies:**
- `curl` - For updates and GTFOBins fetching
- `strace` - For syscall tracing
- `find` - For SUID enumeration
- `getcap` - For capability detection



If you have dependency issues on first install, run setup.sh


# Installation
Cloning the repo-
```bash
git clone https://github.com/stlynnxx/slipperypenguin.git
cd slipperypenguin

pip install -r requirements.txt

python3 slipperypenguin.py --update-gtfobins
```
Downloading the .tar.gz from www.eclecticelectrionics.com (https://github.com/stlynnxx/EclecticElectronics)
```bash
curl -L https://eclecticelectronics.fly.dev/api/download/2.4.3 -o slipperypenguin-2.4.3.tar.gz
sha256sum slipperypenguin-2.4.3.tar.gz

pip install -r requirements.txt

python3 slipperypenguin.py --update-gtfobins

```

## Donations
I am physically disabled and do this and hardware repair to support myself; if you feel generous and 
can afford to do so, every penny helps out! 

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/H5F5269IH4)


## Usage

## Command Line Arguments

| Argument | Short | Type | Description |
|----------|-------|------|-------------|
| `--output` | `-o` | `terminal`/`logs`/`both` | Output mode (default: terminal) |
| `--storage` | `-s` | path | Log storage directory (default: ./logs) |
| `--update-gtfobins` | `-upgt` | flag | Download/update GTFOBins database |
| `--del-logs` | `-dl` | `run`/`close` | Delete existing logs |
| `--timeout` | `-t` | flag | Set custom timeout (default: 2 seconds) |
| `--cleanup` | `-c` | flag | Delete all data and uninstall |
| `--update` | `-u` | `run`/`close` | Download and install latest version |
| `--check` | `-chk` | flag | Check current version |
| `--manual` | `-man` | flag | Display help/usage information |
| `--htmlreport` | `-hr` | flag | Save results in HTML file |
| `--pdfreport` | `-pdf` | flag | Save results in PDF file |
| `--csvreport` | `-cr` | flag | Save findings in CSV file |

---

## Examples
### Basic Scans

#### Full scan with results in terminal only
```bash
python3 slipperypenguin.py -o terminal
```
#### Full scan with JSON logging only
```bash
python3 slipperypenguin.py -o logs
```
#### Full scan with JSON and HTML Reporting

```bash
python3 slipperypenguin.py -o logs -hr
```
#### Full scan with JSON and PDF Reporting

```bash
python3 slipperypenguin.py -o logs -pdf
```
#### Full scan with JSON, HTML, and PDF Reporting
```bash
python3 slipperypenguin.py -o logs -hr -pdf
```

#### Full scan with CSV Reporting
```bash
python3 slipperypenguin.py -o logs -cr
```


### Full Privilege Escalation Assessment

```bash
python3 slipperypenguin.py \
    --output both \
    --htmlreport \
    --pdfreport \
    --timeout \
```


### Clean Slate (remove old logs, update GTFOBins)

```bash
python3 slipperypenguin.py --del-logs run --update-gtfobins
```

### Completely Uninstall

```bash
python3 slipperypenguin.py --cleanup
```
## Project Structure
```bash
slipperypenguin/
├── slipperypenguin.py      # Main script
├── art.txt                 # ASCII banner
├── flags.json              # Flag detection patterns
├── gtfobins.json           # GTFOBins database (generated)
├── logs/                   # Scan output directory
│   └── YYYY-MM-DD_HH-MM-SS/
│       ├── str-out.json
│       ├── cap-out.json
│       ├── find-out.json
│       ├── strace-out.json
│       ├── timeout-out.json
│       ├── gfto-out.json
│       ├── html-out.html
│       └── report.csv
└── requirements.txt
```
## Technical Details

### Scan Workflow

```bash
flowchart TD
    A[Start] --> B[Enumerate SUID Binaries]
    B --> C[For Each Binary]
    C --> D[strings Scan]
    C --> E[strace Execution]
    C --> F[GTFOBins Match]
    C --> G[Flag Detection]
    D & E & F & G --> H[Aggregate Results]
    H --> I[Generate Report]
    I --> J[End]
```

### Concurrency Model

- **Async Architecture**: Uses `asyncio` for concurrent binary scanning
- **Semaphore Limit**: 5 concurrent tasks maximum
- **Lock Protection**: Thread-safe dictionary operations
- **Timeout Handling**: Configurable per-binary timeout with graceful kill

### Output Files

| File | Contents |
|------|----------|
| `str-out.json` | Extracted strings from binaries |
| `cap-out.json` | Linux capabilities detected |
| `find-out.json` | SUID binary locations |
| `strace-out.json` | System call traces |
| `timeout-out.json` | Timeout occurrences |
| `gfto-out.json` | GTFOBins matches |
| `html-out.html` | Formatted HTML report |

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| `Missing dependency: yattag` | Run `pip install -r requirements.txt` |
| `GTFOBins update failed` | Check internet connectivity, verify `https://gtfobins.org/api.json` |
| `Permission denied` | Run with `sudo` for full filesystem access |
| `Update server unreachable` | Check `UPDATE_URL` connectivity or skip auto-update |
| `strace not found` | Install via `apt install strace` or equivalent |



# Contributing

This is the dev branch, where I merge PR requests into and also push my ongoing work to.
If there are any issues listed, you are welcome to take them on and send your PR in.
If you use the program and want to make any changes or additions, feel free to fork it and send a PR to this branch for review!
I'm also always looking for help making flags.json as robust as possible. 

If you find a bug in the current master release, I would check the dev 
version to see if it's been fixed but not yet released on master
before submitting a PR. I really prefer for contributions to come 
on the dev branch, but will not automatically reject them on master. 
