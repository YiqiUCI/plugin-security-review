# Plugin Security Review

A Codex skill for reviewing third-party plugins, MCP servers, and agent skills
from their source and configuration. It traces startup behavior, tool permissions,
delegated commands, and data flows, then reports findings with source locations,
severity, confidence, and what could not be verified.

## Install and use

Copy [SKILL.md](SKILL.md), the [references/](references/) directory, and the
[README inspector](scripts/readme_signals.py) into your personal Codex skills
directory as `plugin-security-review/`. Preserve `references/` and `scripts/`.
The optional inspector uses Python 3 with no package dependencies. Ask Codex:

> Use $plugin-security-review to review this plugin: <GitHub URL or local path>.

For a narrow review, ask for README, package metadata, entrypoints, and URLs
found in source. Specify any limits on review helpers and delegation. The
report traces outgoing data, file and credential access, install and startup
behavior, and any execution of decoded or downloaded content.

The review treats target files as data. It never installs, imports, builds, tests,
or runs target code and never connects to the target MCP server. No third-party
scanner is required. The skill describes how to review, and its findings reflect the source
and configuration available for inspection.

## README and handoffs

When permitted, the inspector reads README bytes and emits fixed labels,
line numbers, counts, and scan status. It flags patterns for prompt overrides,
downloaded or encoded execution, uploads, install hooks, persistence, and
credential paths. The reviewer shares evidence locations and written summaries
with authorized agents. The lead reviewer ranks findings and states what was
covered. A signal is a lead, and an empty scan cannot establish safety.

The review approach draws on
[Sentry's skill-scanner](https://github.com/getsentry/skills/blob/main/skills/skill-scanner/SKILL.md)
and [Cisco Skill Scanner](https://github.com/cisco-ai-defense/skill-scanner).
