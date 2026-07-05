#!/usr/bin/env python3
"""
Created by GitHub Copilot CLI on 2026-07-05

Filter CodeQL findings to suppress known false positives.
This script removes honeypot credential logging findings from CodeQL results.

Usage:
  python3 codeql-filter.py <input.sarif> <output.sarif>
"""

import json
import sys
from pathlib import Path


def is_false_positive(result: dict) -> bool:
    """Check if a result is a known false positive to suppress."""
    
    # Check if it's the clear-text logging query
    rule_id = result.get('ruleId', '')
    if rule_id != 'py/clear-text-logging-sensitive-data':
        return False
    
    # Check if it's in admin/web.py (honeypot alerting code)
    try:
        locations = result.get('locations', [])
        if not locations:
            return False
        
        artifact_uri = locations[0].get('physicalLocation', {}).get('artifactLocation', {}).get('uri', '')
        if artifact_uri != 'admin/web.py':
            return False
        
        # Check if the finding is on our known lines
        start_line = locations[0].get('physicalLocation', {}).get('region', {}).get('startLine', 0)
        
        # These are the lines flagged in the scan that log honeypot credentials
        suppressed_lines = [921, 922, 1221, 1258, 1371]
        
        if start_line in suppressed_lines:
            return True
        
    except (KeyError, TypeError, IndexError):
        pass
    
    return False


def filter_results(sarif_data: dict) -> dict:
    """Filter out false positives from SARIF results."""
    
    if not sarif_data.get('runs'):
        return sarif_data
    
    for run in sarif_data['runs']:
        if 'results' not in run:
            continue
        
        original_count = len(run['results'])
        run['results'] = [r for r in run['results'] if not is_false_positive(r)]
        suppressed_count = original_count - len(run['results'])
        
        if suppressed_count > 0:
            print(f"Suppressed {suppressed_count} honeypot false positives")
    
    return sarif_data


def main():
    """Filter CodeQL SARIF results."""
    
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input.sarif> <output.sarif>")
        sys.exit(1)
    
    input_file = Path(sys.argv[1])
    output_file = Path(sys.argv[2])
    
    if not input_file.exists():
        print(f"Error: Input file not found: {input_file}")
        sys.exit(1)
    
    try:
        with open(input_file, 'r') as f:
            sarif_data = json.load(f)
        
        filtered_data = filter_results(sarif_data)
        
        with open(output_file, 'w') as f:
            json.dump(filtered_data, f, indent=2)
        
        print(f"Filtered results written to {output_file}")
        
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in input file: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
