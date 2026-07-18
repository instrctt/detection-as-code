# Architecture

```
sigma/windows/*.yml  (source of truth — written once)
        |
        v
   sigma-cli convert
        |
        +---> platform-translations/splunk-spl/
        +---> platform-translations/sentinel-kql/
        +---> platform-translations/elastic-lucene/
        |
        v
tests/test_detection_rule.py
   (validates logic against sample logs)
        |
        v
GitHub Actions CI (.github/workflows/ci.yml)
   runs automatically on every push:
   1. sigma check   -> validates rule syntax
   2. pytest        -> confirms detection logic is correct
```

Every change to a rule automatically re-validates and re-tests across all three target platforms — no manual re-translation or re-testing required.
