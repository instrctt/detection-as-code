# Detection-as-Code

![CI](https://github.com/instrctt/detection-as-code/actions/workflows/ci.yml/badge.svg)

A pipeline that treats security detection rules like software: version-controlled, automatically translated across SIEM platforms, and automatically tested, instead of being written by hand, once, for a single tool.

## The problem

Detection rules are usually written directly in one SIEM's query language (Splunk SPL, Microsoft Sentinel KQL, Elastic Lucene). If a team uses more than one SIEM, or switches tools, the same detection logic has to be manually rewritten and re-tested for each platform. That's slow, error-prone, and hard to keep consistent over time.

## The solution

This project writes each detection rule once, using the open-source [Sigma](https://sigmahq.io/) format, and automatically:

1. Translates it into Splunk, Microsoft Sentinel, and Elastic query syntax
2. Tests the rule's logic against sample logs to confirm it catches real malicious activity and ignores normal activity
3. Re-runs both of the above automatically on every code change, via GitHub Actions

## Example: PowerShell Encoded Command Detection

The included rule detects PowerShell being launched with an encoded/obfuscated command, a common technique attackers use to hide malicious commands from plain-text log review ([MITRE ATT&CK T1059.001](https://attack.mitre.org/techniques/T1059/001/)).

| Source | Path |
|---|---|
| Sigma rule (source of truth) | `sigma/windows/powershell_encoded_command.yml` |
| Translated Splunk query | `platform-translations/splunk-spl/` |
| Translated Sentinel query | `platform-translations/sentinel-kql/` |
| Translated Elastic query | `platform-translations/elastic-lucene/` |
| Test logs + validation script | `tests/` |

Read the full investigation write-up, including why this rule exists and how it was validated, in [`docs/writeup.md`](docs/writeup.md).

## Running it yourself

```bash
python3 -m venv venv
source venv/bin/activate

pip install sigma-cli
sigma plugin install splunk
sigma plugin install elasticsearch
sigma plugin install kusto

# Translate the rule to all three platforms
sigma convert -t splunk -p splunk_windows sigma/windows/powershell_encoded_command.yml
sigma convert -t kusto -p sentinel_asim sigma/windows/powershell_encoded_command.yml
sigma convert -t lucene -p ecs_windows sigma/windows/powershell_encoded_command.yml

# Run the tests
python3 tests/test_detection_rule.py
```

## Why this project

This was built to demonstrate a practical detection engineering workflow: writing portable, testable, automatically validated detection logic, rather than one-off queries manually pasted into a single SIEM.
