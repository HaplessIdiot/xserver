#!/usr/bin/env python3
import re, json, sys, os
from collections import defaultdict

# ─── Inputs ────────────────────────────────────────────────────────────────────
infile, outfile = sys.argv[1], sys.argv[2]
repo_root = os.getcwd()  # GitHub runner's workspace root

# ─── SARIF skeleton ────────────────────────────────────────────────────────────
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
  5: ("error",   "Critical"),
  4: ("warning", "High"),
  3: ("warning", "Medium"),
  2: ("note",    "Low"),
  1: ("note",    "Note"),
}

# We'll collect one rule-metadata block per ruleId
rule_meta = defaultdict(lambda: {
  "shortDescription": {"text": "Potential security flaw"},
  "fullDescription":  {"text": ""},
  "defaultConfiguration": {"level": "warning"}
})

pattern = re.compile(r'^(.+?):(\d+):\s*\((\d)\)\s*(.*)$')
with open(infile) as inf:
  for line in inf:
    m = pattern.match(line)
    if not m:
      continue

    raw_path, line_no, risk, msg = m.groups()
    risk = int(risk)
    level, sev = severity_map[risk]

    # 1) Make the file path relative to the repo root
    norm = os.path.normpath(raw_path)
    rel  = os.path.relpath(norm, repo_root)

    # 2) Build a stable ruleId, e.g. 'flawfinder.strcpy'
    token = re.match(r'(\w+)', msg)
    rid   = f"flawfinder.{token.group(1) if token else 'unknown'}"

    # 3) Update rule metadata
    rule_meta[rid]["fullDescription"]["text"] = msg.strip()
    rule_meta[rid]["defaultConfiguration"]["level"] = level

    # 4) Emit the result
    sarif["runs"][0]["results"].append({
      "ruleId":    rid,
      "level":     level,
      "message":   {"text": msg.strip()},
      "properties":{"security-severity": sev},
      "locations": [{
        "physicalLocation": {
          "artifactLocation": {"uri": rel},
          "region":           {"startLine": int(line_no)}
        }
      }]
    })

# 5) Attach the rules array
sarif["runs"][0]["tool"]["driver"]["rules"] = [
  {"id": rid, **meta}
  for rid, meta in rule_meta.items()
]

# 6) Dump it out
with open(outfile, "w") as outf:
  json.dump(sarif, outf, indent=2)
