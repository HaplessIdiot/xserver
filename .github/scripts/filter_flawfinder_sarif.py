#!/usr/bin/env python3
import re, json, sys

infile, outfile = sys.argv[1], sys.argv[2]
data = {"version":"2.1.0","runs":[{"tool":{"driver":{"name":"flawfinder"}}, "results":[]}]}

severity_map = {
  5: ("error",    "Critical"),
  4: ("warning",  "High"),
  3: ("warning",  "Medium"),
  2: ("note",     "Low"),
  1: ("note",     "Note")
}

pattern = re.compile(r'^(.+?):(\d+):\s*\((\d)\)\s*(.*)$')
for line in open(infile):
    m = pattern.match(line)
    if not m:
        continue
    path, line_no, risk, msg = m.groups()
    lvl, sev = severity_map[int(risk)]
    data["runs"][0]["results"].append({
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

json.dump(data, open(outfile, "w"), indent=2)
