# SkillAudit — AI Skill Security Audit

**Service:** https://kontenlaris-studio.github.io/skill-audit/
**Order:** kontenlaris.studio@gmail.com · PayPal · report within 48 hours

Agent skills run with your credentials, files and network. SkillAudit tells you what a skill *really* does before you install or publish it: a deterministic pattern scan plus a human read of the code behind every finding.

## Run the scanner yourself (free, MIT)

```bash
python3 audit.py <skill-folder> [--out report.md]
```

Stdlib-only Python. Exit code 1 when a critical finding exists, so it drops straight into CI. It checks:

- credential & secret-file access (`.env`, SSH keys, cloud credentials)
- exfiltration shapes — env reads + network, file writes + network in the same file
- shell execution, `eval`/`exec`, obfuscated/base64 payloads
- HTTP POST exfil channels and a full external-domain inventory
- seed-phrase / private-key traps

## Sample reports

- `examples/sample-dirty-report.md` — a planted malicious skill: verdict **F**, 3 critical + 2 high
- `examples/sample-clean-report.md` — a real published skill: verdict **B**, minor notes only
- `examples/dirty-skill/` — the planted sample itself, so you can reproduce the F

## Paid service

| Package | Price | Includes |
|---|---|---|
| Scan + Report | $29 | Full scan, human SKILL.md review, verdict report with file-and-line evidence |
| Audit + Fix Guidance | $49 | Everything above + per-finding fix instructions + one free re-scan |

The scanner is the free tool; the service is the judgement, the documentation-honesty review, and a report a publisher can act on. Our own five registry-published skills passed a commercial security scan with zero critical findings using this exact process.

## Honest limits

A pattern scan is evidence, not a proof of safety. The paid report pairs the scan with a human read and says plainly what was and wasn't covered.

## License

MIT — see `LICENSE`.

---

<sub>Built by [Kontenlaris Studio](https://github.com/kontenlaris-studio) · More: [InvoiceKit](https://kontenlaris-studio.github.io/invoicekit/) · [PromptVault](https://github.com/kontenlaris-studio/promptkeep) · [SkillSafe apps](https://skillsafe.ai/share/shr_pm3czpuh2gr8)</sub>
