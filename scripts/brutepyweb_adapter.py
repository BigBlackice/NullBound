#!/usr/bin/env python3
"""Run Brutepyweb while emitting structured credential findings as JSONL."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys


RESULT = re.compile(
    r"^\[\+\] (?P<classification>Candidate|Validated): status=(?P<status>\d+) "
    r"length=(?P<length>\d+)(?: signals=(?P<signals>[^ ]+))? password=(?P<password>.+)$"
)


def candidate_reference(arguments: list[str], candidate: str) -> tuple[str, int | None]:
    try:
        path = Path(arguments[arguments.index("-p") + 1])
    except (ValueError, IndexError):
        return "", None
    try:
        with path.open("r", encoding="utf-8", errors="replace") as stream:
            for line_number, line in enumerate(stream, start=1):
                if line.strip() == candidate:
                    return path.name, line_number
    except OSError:
        pass
    return path.name, None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tool", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--identity", default="")
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    forwarded = args.arguments[1:] if args.arguments[:1] == ["--"] else args.arguments
    try:
        target = forwarded[forwarded.index("-u") + 1]
    except (ValueError, IndexError):
        parser.error("forwarded Brutepyweb arguments require -u")

    args.artifact.parent.mkdir(parents=True, exist_ok=True)
    process = subprocess.Popen(
        [sys.executable, "-u", str(args.tool), *forwarded],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    try:
        with args.artifact.open("w", encoding="utf-8") as artifact:
            assert process.stdout is not None
            for raw_line in process.stdout:
                line = raw_line.rstrip("\r\n")
                match = RESULT.match(line)
                if match:
                    password = match.group("password")
                    wordlist_name, wordlist_line = candidate_reference(forwarded, password)
                    record = {
                        "url": target,
                        "identity": args.identity,
                        "password": password,
                        "status": int(match.group("status")),
                        "length": int(match.group("length")),
                        "password_length": len(password),
                        "classification": match.group("classification").casefold(),
                    }
                    if match.group("signals"):
                        record["signals"] = match.group("signals").split(",")
                    if wordlist_name:
                        record["wordlist_name"] = wordlist_name
                    if wordlist_line is not None:
                        record["wordlist_line"] = wordlist_line
                    artifact.write(json.dumps(record) + "\n")
                    artifact.flush()
                print(line, flush=True)
        return process.wait()
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == "__main__":
    raise SystemExit(main())
