# Security review report

Lead with the risk and recommendation. Use evidence from the pinned revision. For each material finding, distinguish observed code, the conditions needed to trigger it, impact, and what remains unverified. Give severity, confidence, a file and line or pinned source link, and a concrete next step. A documented capability can be high impact without proving malicious intent. Never label a partial static review as safe.

For a quick review, answer these items in the user's language:

1. **Identity.** List the exact owner, repository, package name, publisher, and reviewed revision when available. Note same-name listings by different authors and directory warnings. Record the source and window of any stars or download counts and explain what each count measures. Mark missing or unverifiable information.
2. **Outbound data.** For each destination in scope, give host or URL template, location, trigger, and data sent. Group documentation URLs separately. Distinguish reachable network calls from examples, update/download URLs, and unresolved dynamic endpoints. Redact credentials and sensitive query parameters.
3. **Local access.** State which files, environment variables, key stores, cookies, or account sessions it can read, and under which settings or permissions. Explain whether any of those values reach an outbound request.
4. **Hidden and automatic execution.** Report whether encoded, encrypted, or downloaded bytes actually reach an interpreter or loader. Report install hooks and dependency downloads, then startup, background tasks, and any sending or posting without user action. Separate confirmed behavior from what cannot be established statically.
5. **Coverage.** List what was read and what was excluded or unavailable, including README scan status when applicable. State whether the review used a helper or transmitted any data to an external service.

In full mode, include material MCP findings, tool approval and transport limits, dependency advisory applicability, and any other confirmed security issues. Rank findings by potential impact and exposure, with confidence stated separately. End with one plain sentence saying whether to install and naming settings or tools to disable if that can reduce risk. If no verified setting can control a material risk, say that plainly.
