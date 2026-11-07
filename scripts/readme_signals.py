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

DOWNLOADER = r"\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b"
SHELL = r"(?:bash|sh|zsh|dash|ksh|fish|pwsh|powershell|cmd|iex|invoke-expression)(?:\.exe)?\b"
COMMAND_SEPARATOR = r"(?:&&|;|\r?\n)[ \t]*"
FILE_EXEC = (
    rf"(?:{SHELL}|(?:node|python3?|deno|bun|source|start-process)\b"
    r"|\.{1,2}[/\\]|/\S|[A-Za-z]:[/\\]|\$[A-Za-z_]|&[ \t]+[$'\"(])"
)

# ponytail: these patterns aid triage. Add a rule only for an observed gap.
RULES = {
    "hidden_markup": re.compile(r"<!--|\bdisplay\s*:\s*none\b|\bvisibility\s*:\s*hidden\b", re.I),
    "invisible_unicode": re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060\u2066-\u2069\ufeff]"),
    "inline_shell": re.compile(r"!`"),
    "encoded_execution": re.compile(
        rf"\bbase64\b[^|\r\n]{{0,200}}?[ \t](?:-d\b|--decode\b)[^|\r\n]{{0,200}}\|[ \t]*{SHELL}"
        r"|\b(?:pwsh|powershell)(?:\.exe)?\b[^\r\n;&|]{0,260}?[ \t]"
        r"-(?:enc(?:odedcommand)?|ec)[ \t:=]+['\"]?[A-Za-z0-9+/]{4,}"
        r"|\b(?:eval|exec|function|iex|invoke-expression)\s*\([^\r\n]{0,240}?"
        r"(?:\b(?:atob|b64decode)\s*\(|['\"]base64['\"])",
        re.I,
    ),
    "data_exfiltration": re.compile(
        r"\bcurl\b[^\r\n;&|]{0,360}?[ \t](?:"
        r"(?-i:-[fsSLkq]*[dFT])(?=[ \t@'\"]|$)"
        r"|--(?:data(?:-ascii|-binary|-raw|-urlencode)?|form(?:-string)?|upload-file|json)(?=[ \t=]|$))"
        r"|\bwget\b[^\r\n;&|]{0,360}?[ \t]--post-(?:data|file)(?=[ \t=]|$)"
        r"|\b(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\r\n;&|]{0,360}?"
        r"[ \t]-method[ \t]+['\"]?(?:post|put|patch)\b",
        re.I,
    ),
    "install_hook": re.compile(
        r"\b(?:preinstall|postinstall|prepare)['\"]?[ \t]*:"
        r"|\b(?:npm|pnpm|yarn|bun)\s+(?:run(?:-script)?\s+)?(?:preinstall|postinstall|prepare)\b"
        r"|\b(?:node|bash|sh|pwsh|powershell|python3?)\s+['\"]?"
        r"(?:[^ \t\r\n'\";&|]*[/\\])?(?:preinstall|postinstall|prepare)\.(?:[cm]?js|sh|ps1|py)\b",
        re.I,
    ),
    "persistence": re.compile(
        r"\bschtasks(?:\.exe)?[ \t]+/create\b|\bregister-scheduledtask\b"
        r"|\bsystemctl[ \t]+(?:--user[ \t]+)?enable\b|\blaunchctl[ \t]+(?:load|bootstrap|enable)\b"
        r"|@reboot\b|\bcrontab[ \t]+(?:-e\b|-(?=[ \t;&|\r\n]|$)|[^-\s;&|])"
        r"|currentversion[\\/]run(?:once)?\b|\.config[\\/]autostart\b",
        re.I,
    ),
    "credential_path": re.compile(
        r"(?<![\w-])(?:\.ssh|\.npmrc|\.netrc|\.git-credentials|\.aws[\\/]credentials"
        r"|\.kube[\\/]config|\.docker[\\/]config\.json|\.codex[\\/]auth\.json)(?![\w-])"
        r"|(?<![\w-])\.env(?![\w.-])|[\\/](?:cookies|login data)\b"
        r"|\b(?:cookies?|tokens?|credentials?)\.(?:json|txt|sqlite|db)\b"
        r"|\b(?:aws_secret_access_key|github_token|gh_token|npm_token|openai_api_key)\b",
        re.I,
    ),
}
INSTRUCTION_OVERRIDE = re.compile(
    r"\b(?:ignore|disregard|override)\s+(?:all\s+)?(?:the\s+)?"
    r"(?:previous|prior|above|system)\s+(?:instructions?|rules?|prompts?)\b"
    r"|<\s*(?:/\s*)?(?:system|developer|assistant)\s*>|\[/?INST\]"
    r"|(?:忽略|无视|覆盖)(?:\s*(?:此前|之前|以上|系统|所有|先前)){1,3}"
    r"\s*(?:的\s*)?(?:指令|规则|提示词)",
    re.I,
)
DOWNLOAD = re.compile(DOWNLOADER, re.I)
SHELL_PIPE = re.compile(rf"\|[ \t]*{SHELL}", re.I)
DOWNLOAD_THEN_EXECUTE = re.compile(
    rf"{DOWNLOADER}[^\r\n]{{0,400}}?{COMMAND_SEPARATOR}"
    rf"(?:chmod\b[^\r\n]{{0,240}}?{COMMAND_SEPARATOR})?{FILE_EXEC}"
    r"|\b(?:iex|invoke-expression)\b[^\r\n;&|]{0,320}?"
    r"\b(?:downloadstring|downloadfile|irm|iwr|invoke-restmethod|invoke-webrequest)\b",
    re.I,
)


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

    # Match wrapped signals once and report the line where they start.
    document_hits = {}
    for kind, rule in (
        ("instruction_override", INSTRUCTION_OVERRIDE),
        ("download_then_execute", DOWNLOAD_THEN_EXECUTE),
    ):
        number, offset = 1, 0
        for match in rule.finditer(content):
            number += content.count("\n", offset, match.start())
            hits = document_hits.setdefault(number, [])
            if kind not in hits:
                hits.append(kind)
            offset = match.start()

    lines = content.split("\n")
    if not lines[-1]:
        lines.pop()
    result["lines_scanned"] = len(lines)
    for number, line in enumerate(lines, 1):
        kinds = [kind for kind, rule in RULES.items() if rule.search(line)]
        kinds.extend(document_hits.get(number, ()))
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
