# CodeQL Suppression Guide

## Overview

This document explains how to suppress CodeQL findings for honeypot credential logging in HomeDetector. The findings flagged as "Clear-text logging of sensitive information" are false positives because the logged credentials are intentionally captured from attacker attempts on the honeypot.

## Problem

CodeQL's `py/clear-text-logging-sensitive-data` query flags the following lines in `admin/web.py`:
- **Line 921**: `logger.info("🔥🔥 %s 🔥🔥", alert['message'])`
- **Line 922**: SQL insert including `alert['message']` (contains honeypot credentials)
- **Line 1221**: `logger.debug('Sending %s to %s', str(data), url)` (posts alert data)
- **Line 1258**: `logger.debug('Sending HA Notification %s to %s', str(data), url)`
- **Line 1371**: `logger.debug('SQL PARAM -> %s', sql_param)`

These are **legitimate security logging** of attacker credentials captured by the honeypot, not a real security vulnerability.

## Solution

### 1. Local CodeQL Scanning

Use the provided `codeql-filter.py` script to suppress false positives from CodeQL SARIF output.

**Usage:**
```bash
# Generate CodeQL database
codeql database create codeql-db --language=python

# Run analysis and generate SARIF
codeql database analyze codeql-db --format=sarif-latest --output=codeql-results.sarif

# Filter out honeypot false positives
python3 codeql-filter.py codeql-results.sarif codeql-results-filtered.sarif

# View filtered results
cat codeql-results-filtered.sarif
```

The script removes 5 findings related to honeypot credential logging while preserving all other security findings.

### 2. GitHub Code Scanning

For GitHub Actions CodeQL workflows, add a workflow step that filters results before uploading to GitHub:

```yaml
- name: Analyze with CodeQL
  uses: github/codeql-action/analyze@v2
  with:
    category: "/language:python"

- name: Filter honeypot false positives
  run: |
    python3 codeql-filter.py codeql-results.sarif codeql-results-filtered.sarif
    mv codeql-results-filtered.sarif codeql-results.sarif

- name: Upload filtered results to GitHub
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: 'codeql-results.sarif'
```

### 3. Files Involved

- **`codeql-filter.py`**: Python script that filters SARIF output to suppress honeypot findings
- **`.github/codeql/codeql-config.yml`**: CodeQL configuration (for future use with advanced query exclusions)
- **`.codeqlignore`**: Pattern file for ignoring files/queries (legacy approach, modern CodeQL prefers SARIF filtering)

## Why These Approaches?

### Why not LGTM comments?
- LGTM annotations are a legacy suppression mechanism from Semmle's LGTM.com service
- Modern CodeQL versions (2.25+) do not reliably respect inline `# lgtm[...]` comments
- They were tested but did not suppress the findings in local testing

### Why the Python filter script?
- **Universal**: Works with any CodeQL version that outputs SARIF format
- **Explicit**: Clearly documents which findings are suppressed and why
- **Maintainable**: Easy to update if line numbers change in the codebase
- **Testable**: Can be verified locally before using in CI/CD pipelines

## Testing the Solution

To verify the suppression works:

```bash
# Run the filter on test SARIF
python3 codeql-filter.py codeql-results.sarif codeql-results-test.sarif

# Check original vs filtered counts
python3 -c "import json; print('Original:', len(json.load(open('codeql-results.sarif'))['runs'][0]['results']))"
python3 -c "import json; print('Filtered:', len(json.load(open('codeql-results-test.sarif'))['runs'][0]['results']))"
```

Expected result: 5 findings removed (the honeypot alerts), preserving all other security findings.

## Maintenance

If you add new honeypot credential logging code:
1. Identify the new line numbers
2. Update the `suppressed_lines` list in `codeql-filter.py`
3. Test the filter script locally
4. Verify findings are suppressed in CI/CD

Example:
```python
suppressed_lines = [921, 922, 1221, 1258, 1371, 1500]  # Added new line 1500
```

## References

- [GitHub Code Scanning Documentation](https://docs.github.com/en/code-security/code-scanning)
- [CodeQL Documentation](https://codeql.github.com/docs/)
- [SARIF Format](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=sarif)
