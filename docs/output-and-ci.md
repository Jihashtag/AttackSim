# Output & CI Integration

## Output formats

| Format | Flag | Description |
|---|---|---|
| Console | *(default)* | Colorised per-module results + final verdict |
| JSON | `--json PATH` | Machine-readable report (for CI gating) |
| Markdown | `--markdown PATH` | Human-readable report |
| SARIF 2.1.0 | `--sarif PATH` | For code-scanning dashboards / SARIF viewers (carries `security-severity`, module, CWE, tags) |
| HTML | `--html PATH` | Standalone, shareable report (all finding text is escaped) |

Auto-generated JSON is always written to `report/last_run.json`.

## Console output

Each module reports one of:

- **`[ EXPLOITED ]`** — the attack succeeded; a usable weakness exists
- **`[ MITIGATED ]`** — the attack failed; that risk is mitigated

If **any** module wins, the run ends with a consolidated *"issues an attacker could use"*
summary and exits `1`. If **all** fail, it prints *"the assessed risks are MITIGATED"*
and exits `0`.

## Attack-chain correlation (post-pass)

After all modules run, `attack-chain` correlates individual findings into end-to-end
narratives, for example:

- *exposed `.git` → leaked HS256 secret → forged admin JWT*
- *open datastore → proof-of-access*
- *cloud admin identity → IAM privilege escalation*
- *exposed admin surface → default credentials accepted*

It only links findings that already exist — it performs no new probing — and is
appended to the report when a chain fires.

## Baseline comparison (CI drift gate)

```bash
# Compare against a previous JSON report; classify findings as new / fixed / unchanged:
python3 main.py https://target.example --baseline report/last_run.json

# Fail only when a NEW finding appears (ignore pre-existing ones):
python3 main.py https://target.example --baseline report/last_run.json \
  --fail-on-new-only --fail-on HIGH
```

## CI gate usage

```bash
python3 main.py --no-color || echo "Security gate failed: exploitable issues present"

# Gate only on serious issues (ignore LOW/INFO/MEDIUM-only wins):
python3 main.py --no-color --fail-on HIGH

# Live targets in CI (non-interactive): --yes acknowledges the pre-scan safety check
python3 main.py https://staging.example --scope staging.example --yes --fail-on HIGH
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | All assessed risks are mitigated (or below `--fail-on` threshold) |
| `1` | Exploitable issues found (per `--fail-on`) |
| `2` | Usage or runtime error (including a declined pre-scan safety check) |
