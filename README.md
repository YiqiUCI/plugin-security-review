# Plugin Security Review

A Codex skill for reviewing third-party plugins, MCP servers, and agent skills
from their source and configuration. It traces startup behavior, tool permissions,
delegated commands, and data flows, then reports findings with source locations,
severity, confidence, and what could not be verified.

## Install and use

Copy [SKILL.md](SKILL.md) into the `plugin-security-review` folder inside your
personal Codex skills directory (normally `~/.codex/skills/`). Ask Codex:

> Use $plugin-security-review to review this plugin: <GitHub URL or local path>.

The review treats target files as data. It never installs, imports, builds, tests,
or runs target code and never connects to the target MCP server. No scanner is
required. The skill describes how to review, and its findings reflect the source
and configuration available for inspection.

The review approach draws on
[Sentry's skill-scanner](https://github.com/getsentry/skills/blob/main/skills/skill-scanner/SKILL.md)
and [Cisco Skill Scanner](https://github.com/cisco-ai-defense/skill-scanner).
