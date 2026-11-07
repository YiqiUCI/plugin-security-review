"""Report static README signals without copying any input text to output."""

import argparse
import codecs
import json
from pathlib import Path
import re
import stat
import sys


MAX_BYTES = 256 * 1024
MAX_FINDINGS = 50

# ponytail: these patterns aid triage. Add a rule only for an observed gap.
RULES = {
    "hidden_markup": re.compile(r"<!--|\bdisplay\s*:\s*none\b|\bvisibility\s*:\s*hidden\b", re.I),
    "invisible_unicode": re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060\u2066-\u2069\ufeff]"),
    "inline_shell": re.compile(r"!`"),
}
INSTRUCTION_OVERRIDE = re.compile(
    r"\b(?:ignore|disregard|override)\s+(?:all\s+)?(?:the\s+)?"
    r"(?:previous|prior|above|system)\s+(?:instructions?|rules?|prompts?)\b"
    r"|<\s*(?:/\s*)?(?:system|developer|assistant)\s*>|\[/?INST\]"
    r"|(?:忽略|无视|覆盖)(?:\s*(?:此前|之前|以上|系统|所有|先前)){1,3}"
    r"\s*(?:的\s*)?(?:指令|规则|提示词)",
    re.I,
)
DOWNLOAD = re.compile(r"\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b", re.I)
SHELL_PIPE = re.compile(r"\|[ \t]*(?:bash|sh|zsh|pwsh|powershell|iex|invoke-expression)\b", re.I)


def scan(raw):
    truncated = len(raw) > MAX_BYTES
    result = {"status": "truncated" if truncated else "complete", "lines_scanned": 0,
              "findings": [], "omitted_findings": 0}
    try:
        decoder = codecs.getincrementaldecoder("utf-8-sig")()
        content = decoder.decode(raw[:MAX_BYTES], final=not truncated)
    except UnicodeDecodeError:
        result["status"] = "unsupported_encoding"
        return result

    # Match a wrapped directive once and report the line where it starts.
    override_lines = set()
    number, offset = 1, 0
    for match in INSTRUCTION_OVERRIDE.finditer(content):
        number += content.count("\n", offset, match.start())
        override_lines.add(number)
        offset = match.start()

    lines = content.split("\n")
    if not lines[-1]:
        lines.pop()
    result["lines_scanned"] = len(lines)
    for number, line in enumerate(lines, 1):
        kinds = [kind for kind, rule in RULES.items() if rule.search(line)]
        if number in override_lines:
            kinds.append("instruction_override")
        if SHELL_PIPE.search(line) and DOWNLOAD.search(line):
            kinds.append("download_to_shell")
        for kind in kinds:
            if len(result["findings"]) < MAX_FINDINGS:
                result["findings"].append({"line": number, "kind": kind})
            else:
                result["omitted_findings"] += 1
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("readme", help="A verified local README file, or - for raw bytes on stdin")
    args = parser.parse_args()
    try:
        if args.readme == "-":
            raw = sys.stdin.buffer.read(MAX_BYTES + 1)
        else:
            path = Path(args.readme)
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or (
                getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
            ):
                raise OSError
            with path.open("rb") as stream:
                raw = stream.read(MAX_BYTES + 1)
    except (OSError, ValueError):
        print('{"status":"read_error","lines_scanned":0,"findings":[],"omitted_findings":0}')
        return 1

    print(json.dumps(scan(raw)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
