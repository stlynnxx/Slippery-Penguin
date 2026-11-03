***Slippery Penguin is intended strictly for use on systems you own or have explicit authorization
to test. This tool is provided for educational and security research purposes only. The authors assumes no liability for misuse or damage caused by this tool. 
Use responsibly and in accordance with all applicable local, state, and federal laws.***



# Slippery Penguin

**This is the development branch, where new work gets pushed to as the next release is built. It may have features not present in the current release, and may be less stable than the latest release.**

**SUID/SGID Enumeration and Vulnerability Scanning Tool**

Slippery Penguin is a security auditing tool designed to enumerate SUID binaries, scan for dangerous capabilities, and cross-reference findings against the GTFOBins database to identify potential privilege escalation vectors.

[![XERJ Corpus Hub contributor](https://hub.xerj.org/contributors/stlynnxx/badge.svg)](https://hub.xerj.org/contributors/stlynnxx)

Now featured in the Xerj Corpus! Check Xerj out at https://github.com/xerj-org/xerj

##  Features

**SUID/SGID Enumeration**: Recursively scans filesystem for privileged binaries (`-perm -4000` or `-perm -2000`) 
**Capability Scanning**: Detects Linux capabilities on binaries via `getcap` 
**Strings Analysis**: Extracts strings from binaries for hidden credentials/paths 
**Opt-in Runtime Trace Planning**: Selects privileged binaries with strong static findings and prepares bounded strace commands for operator review 
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
- `strace` - Optional; required only when `--runtime-trace` is requested
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
Note: **This installs the latest release, not the development branch**
```bash
curl -L https://eclecticelectronics.fly.dev/api/download/2.5.2 -o slipperypenguin-2.5.2.tar.gz
sha256sum slipperypenguin-2.5.2.tar.gz

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
| `--runtime-trace` |  | flag | Run evidence-selected runtime traces after explicit confirmation |
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

#### Prepare optional runtime tracing
```bash
python3 slipperypenguin.py --runtime-trace --output both
```
This completes static analysis first, then lists only privileged binaries supported by HIGH/CRITICAL flag findings or a GTFOBins SUID match. The CLI explains that tracing executes each selected binary and requires you to type `yes` before any target is run. Any other response, including end-of-input, cancels tracing. Traces use the isolated, timeout- and cancellation-aware `trace_binary()` helper. Results are saved in `strace-out.json` and `runtime-trace-results.json`, with execution status and diagnostics kept separate from static findings in generated reports.


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
│       ├── scan-out.json
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
    A[Start] --> B[Enumerate SUID/SGID Files Once]
    B --> C[Recursive getcap Scan Once]
    B --> D[Static Analysis for Each Binary]
    D --> E[Strings and Flag Analysis]
    D --> F[GTFOBins Matching]
    C & E & F --> G[Aggregate Static Findings]
    G --> H{Runtime trace planning opted in?}
    H -->|No| I[Generate Reports]
    H -->|Yes| J[Select Evidence-Based Candidates]
    J --> K[Show Targets and Reasons]
    K --> M{User types yes?}
    M -->|No| I
    M -->|Yes| N[Run trace_binary with Timeout and Cancellation]
    N --> O[Store Runtime Observations Separately]
    O --> I
    I --> L[End]
```

### Concurrency Model

- **Async Architecture**: Uses `asyncio` for concurrent per-binary analysis
- **Inventory pass**: Enumerates SUID/SGID files once and runs one recursive `getcap` pass; cached results are reused throughout the run
- **Semaphore Limit**: 5 concurrent tasks maximum
- **Lock Protection**: Thread-safe dictionary operations
- **Timeout Handling**: Configurable per-binary timeout with graceful kill

### Output Files

| File | Contents |
|------|----------|
| `str-out.json` | Extracted strings from binaries |
| `cap-out.json` | Linux file capabilities collected by one recursive getcap pass |
| `scan-out.json` | Scan timings, warnings, counts, and cached file metadata |
| `find-out.json` | SUID and SGID binary locations |
| `strace-out.json` | Runtime syscall observations supplied separately; not produced by default scans |
| `runtime-trace-plan.json` | Candidate selection reasons and per-target execution status |
| `timeout-out.json` | Timeout occurrences |
| `gfto-out.json` | GTFOBins matches |
| `html-out.html` | Formatted HTML report |

## Runtime Tracing Safety and Selection

Runtime tracing is **disabled by default**. A normal scan performs static analysis only and does not execute discovered SUID/SGID binaries.

To run runtime tracing, pass `--runtime-trace`. Static analysis completes first. The CLI displays each eligible target and its selection reasons, then requires the exact response `yes` before execution. Any other response, EOF, or Ctrl-C cancels tracing. A candidate must be present in the discovered privileged-file inventory and have at least one strong signal:
- a configured `HIGH` or `CRITICAL` flag finding; or
- a GTFOBins match explicitly marked for the `suid` context.

LOW and MEDIUM findings alone do not qualify a binary. Candidate reasons and execution status are written to `runtime-trace-plan.json`. Traces are performed by the isolated `trace_binary()` helper, which applies timeout and cancellation cleanup. Runtime observations are saved separately from static findings. **strace executes the target and is not a sandbox**: file changes, resource access, network activity, and other side effects remain possible. Use it only on systems and binaries you are authorised to assess.

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
