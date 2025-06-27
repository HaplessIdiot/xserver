#!/usr/bin/env python3
import json, re, sys

infile, outfile = sys.argv[1], sys.argv[2]
data = json.load(open(infile))

runs = data.get("runs", [])
if runs:
    out_results = []
    for r in runs[0]["results"]:
        msg = r["message"]["text"]
        # drop anything that looks like our known noise
        if re.search(r"\b(memcpy|strncpy|printf)\b", msg):
            continue
        out_results.append(r)
    runs[0]["results"] = out_results

json.dump(data, open(outfile, "w"), indent=2)
