"""Synthetic benchmark for repeated getcap subprocess overhead."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scan_helpers import scan_file_capabilities  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--files", type=int, default=40)
    parser.add_argument("--delay", type=float, default=0.01)
    args = parser.parse_args()
    if args.files < 1 or args.delay < 0:
        parser.error("--files must be positive and --delay cannot be negative")

    with tempfile.TemporaryDirectory(prefix="slippery-penguin-bench-") as temp:
        root = Path(temp)
        fixture = root / "fixture"
        bindir = root / "bin"
        fixture.mkdir()
        bindir.mkdir()
        files = []
        for index in range(args.files):
            path = fixture / f"binary-{index:04d}"
            path.write_text("fixture", encoding="utf-8")
            files.append(path)

        counter = root / "calls.txt"
        fake = bindir / "getcap"
        fake.write_text(
            "#!/bin/sh\n"
            'printf "call\n" >> "$GETCAP_COUNTER"\n'
            f"sleep {args.delay}\n"
            'for arg do target="$arg"; done\n'
            'if [ -d "$target" ]; then\n'
            '  for path in "$target"/binary-*; do\n'
            '    [ -f "$path" ] && printf "%s cap_net_bind_service=ep\n" "$path"\n'
            '  done\n'
            'elif [ -f "$target" ]; then\n'
            '  printf "%s cap_net_bind_service=ep\n" "$target"\n'
            "fi\n",
            encoding="utf-8",
        )
        fake.chmod(0o755)
        env = os.environ.copy()
        env["PATH"] = str(bindir) + os.pathsep + env.get("PATH", "")
        env["GETCAP_COUNTER"] = str(counter)

        started = time.perf_counter()
        for path in files:
            subprocess.run(
                ["getcap", "-r", str(path)],
                capture_output=True,
                text=True,
                check=False,
                env=env,
            )
        legacy_seconds = time.perf_counter() - started
        legacy_calls = len(counter.read_text(encoding="utf-8").splitlines())
        counter.unlink(missing_ok=True)

        def runner(
            command: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            return subprocess.run(command, env=env, **kwargs)  # type: ignore[arg-type,return-value]

        started = time.perf_counter()
        capabilities, warnings = scan_file_capabilities(
            str(fixture), runner=runner  # type: ignore[arg-type]
        )
        cached_seconds = time.perf_counter() - started
        cached_calls = len(counter.read_text(encoding="utf-8").splitlines())
        print(json.dumps({
            "fixture_files": args.files,
            "legacy_getcap_calls": legacy_calls,
            "single_pass_getcap_calls": cached_calls,
            "call_reduction_percent": round((1 - cached_calls / legacy_calls) * 100, 2)
                if legacy_calls else 0,
            "legacy_seconds": round(legacy_seconds, 6),
            "single_pass_seconds": round(cached_seconds, 6),
            "capability_files_found": len(capabilities),
            "all_findings_retained": len(capabilities) == args.files,
            "warnings": warnings,
            "note": "Synthetic subprocess-overhead benchmark, not a production filesystem walk.",
        }, indent=2))


if __name__ == "__main__":
    main()
