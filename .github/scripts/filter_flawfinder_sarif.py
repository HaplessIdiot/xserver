#!/usr/bin/env python3
import re, json, sys
from collections import defaultdict

# Input and output file paths
infile, outfile = sys.argv[1], sys.argv[2]

# SARIF skeleton
sarif = {
    "version": "2.1.0",
    "runs": [{
        "tool": {
            "driver": {
                "name": "flawfinder",
                "rules": []
            }
        },
        "results": []
    }]
}

severity_map = {
    5: ("error",    "Critical"),
    4: ("warning",  "High"),
    3: ("warning",  "Medium"),
    2: ("note",     "Low"),
    1: ("note",     "Note")
}

# Parse Flawfinder output
pattern = re.compile(r'^(.+?):(\d+):\s*\((\d)\)\s*(.*)$')
rule_descriptions = defaultdict(lambda: {
    "shortDescription": {"text": "Potential security flaw"},
    "fullDescription": {"text": "Issue reported by Flawfinder"},
    "defaultConfiguration": {"level": "warning"}
})

for line in open(infile):
    m = pattern.match(line)
    if not m:
        continue
    path, line_no, risk, msg = m.groups()
    risk = int(risk)
    lvl, sev = severity_map[risk]

    # Extract rule ID from the start of the message (e.g., 'strcpy', 'gets')
    rule_id_match = re.match(r'(\w+)', msg)
    rule_id = rule_id_match.group(1) if rule_id_match else "flawfinder.unknown"

    rule_descriptions[rule_id]["name"] = rule_id
    rule_descriptions[rule_id]["fullDescription"]["text"] = msg.strip()
    rule_descriptions[rule_id]["defaultConfiguration"]["level"] = lvl

    sarif["runs"][0]["results"].append({
        "ruleId": rule_id,
        "level": lvl,
        "message": {"text": msg.strip()},
        "properties": {"security-severity": sev},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": path},
                "region": {"startLine": int(line_no)}
            }
        }]
    })

# Add rules metadata to SARIF
sarif["runs"][0]["tool"]["driver"]["rules"] = [
    {"id": rid, **meta} for rid, meta in rule_descriptions.items()
]

# Write out the final SARIF file
with open(outfile, "w") as f:
    json.dump(sarif, f, indent=2)
