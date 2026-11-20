#!/usr/bin/env python3
"""SkillAudit — deterministic security scanner for AI agent skills.

Scans a skill folder (SKILL.md + scripts + references) for the patterns that
matter before you install or publish someone else's skill:
credential access, environment reads, network calls, code execution,
file writes, and dangerous combinations (env+network, write+network).

Stdlib only. Usage: python3 audit.py <skill-folder> [--out report.md]
"""
import json
import os
import re
import sys

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
TEXT_EXT = {".md", ".py", ".ts", ".js", ".mjs", ".json", ".sh", ".txt", ".yaml", ".yml", ".toml"}

RULES = [
    ("critical", "crypto_seed_phrase",
     re.compile(r"\b(seed phrase|mnemonic phrase|recovery phrase)\b", re.I),
     "Mentions a wallet seed/mnemonic phrase — a skill should never need one."),
    ("critical", "private_key_block",
     re.compile(r"BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY"),
     "Contains an embedded private key block."),
    ("critical", "credential_file_access",
     re.compile(r"(\.ssh/|id_rsa|\.aws/credentials|\.gnupg|/etc/passwd|\.env\b)"),
     "Touches credential or secret files on disk."),
    ("high", "shell_execution",
     re.compile(r"(os\.system|subprocess\.|child_process|execSync|spawn\(|popen)"),
     "Executes shell commands or child processes."),
    ("high", "dynamic_eval",
     re.compile(r"\b(eval|exec)\s*\("),
     "Uses eval/exec on dynamic input."),
    ("high", "network_post",
     re.compile(r"(requests\.post|fetch\([^)]*method:\s*['\"]POST|axios\.post|\.post\()"),
     "Sends data out with HTTP POST."),
    ("medium", "env_access",
     re.compile(r"(process\.env|os\.environ|os\.getenv|getenv\()"),
     "Reads environment variables — check the skill documents which ones and why."),
    ("medium", "network_call",
     re.compile(r"(https?://|requests\.|fetch\(|axios|urllib|WebSocket)"),
     "Makes network calls — domains should be listed in the inventory below."),
    ("medium", "file_write",
     re.compile(r"(open\([^)]*['\"][wa]['\"]|writeFile|fs\.write|os\.remove|shutil\.)"),
     "Writes or deletes files."),
    ("low", "base64_blob",
     re.compile(r"[A-Za-z0-9+/]{120,}={0,2}"),
     "Long base64-looking blob — verify it is data, not hidden code."),
    ("low", "obfuscation",
     re.compile(r"(atob\(|Buffer\.from\([^)]*base64|\\x[0-9a-f]{2}\\x[0-9a-f]{2})"),
     "Possible obfuscated payload."),
]

COMBO_RULES = [
    ("critical", "composite_env_exfil", {"env_access", "network_call"},
     "Same file reads environment variables AND makes network calls — classic secret-exfiltration shape."),
    ("high", "composite_write_exfil", {"file_write", "network_call"},
     "Same file writes files AND makes network calls — verify what is written is never uploaded."),
]


def scan_file(path, rel):
    findings, rule_ids = [], set()
    try:
        text = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return findings, rule_ids, set()
    domains = set(re.findall(r"https?://([a-zA-Z0-9.-]+)", text))
    for sev, rid, rx, why in RULES:
        for m in rx.finditer(text):
            line = text[: m.start()].count("\n") + 1
            findings.append({"severity": sev, "rule": rid, "file": rel, "line": line, "why": why})
            rule_ids.add(rid)
            break  # one finding per rule per file is enough for the report
    for sev, rid, needs, why in COMBO_RULES:
        if needs <= rule_ids:
            findings.append({"severity": sev, "rule": rid, "file": rel, "line": 0, "why": why})
    return findings, rule_ids, domains


def audit(root):
    all_findings, domains, files = [], set(), 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in {".git", "node_modules", "__pycache__"}]
        for fn in filenames:
            if os.path.splitext(fn)[1].lower() not in TEXT_EXT:
                continue
            p = os.path.join(dirpath, fn)
            files += 1
            f, _, dom = scan_file(p, os.path.relpath(p, root))
            all_findings += f
            domains |= dom
    all_findings.sort(key=lambda x: (SEV_ORDER[x["severity"]], x["file"]))
    return all_findings, sorted(domains), files


def grade(findings):
    c = sum(1 for f in findings if f["severity"] == "critical")
    h = sum(1 for f in findings if f["severity"] == "high")
    if c: return "F — do not install until fixed"
    if h >= 2: return "D — serious review needed"
    if h == 1: return "C — review the high finding before use"
    if findings: return "B — minor items to verify"
    return "A — clean scan"


def to_markdown(root, findings, domains, files):
    name = os.path.basename(os.path.abspath(root))
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEV_ORDER}
    out = [f"# SkillAudit Report — {name}", "",
           f"**Verdict: {grade(findings)}**", "",
           f"Files scanned: {files} · Critical: {counts['critical']} · High: {counts['high']} · "
           f"Medium: {counts['medium']} · Low: {counts['low']} · Info: {counts['info']}", "",
           "## Findings", ""]
    if not findings:
        out.append("No findings. The skill shows no credential access, execution, network, or write patterns.")
    for f in findings:
        loc = f"{f['file']}:{f['line']}" if f["line"] else f["file"]
        out.append(f"- **{f['severity'].upper()}** `{f['rule']}` — {loc} — {f['why']}")
    out += ["", "## Network inventory", ""]
    out.append(", ".join(domains) if domains else "No external domains referenced.")
    out += ["", "---", "Generated by SkillAudit (Kontenlaris Studio) — deterministic pattern scan; "
            "a clean result is evidence, not a guarantee. Pair with a human read of SKILL.md."]
    return "\n".join(out) + "\n"


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    root = sys.argv[1]
    out_path = None
    if "--out" in sys.argv:
        out_path = sys.argv[sys.argv.index("--out") + 1]
    findings, domains, files = audit(root)
    md = to_markdown(root, findings, domains, files)
    if out_path:
        open(out_path, "w").write(md)
    print(md)
    summary = {"files": files, "findings": len(findings), "verdict": grade(findings)}
    print(json.dumps(summary), file=sys.stderr)
    return 1 if any(f["severity"] == "critical" for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
