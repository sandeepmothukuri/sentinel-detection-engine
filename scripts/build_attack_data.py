#!/usr/bin/env python3
"""Build the vendored ATT&CK technique dataset used by CI validation.

Downloads the official MITRE CTI enterprise bundle and writes a compact
scripts/attack_data.json: { technique_id: { name, tactics[] } }, excluding
revoked and deprecated objects. Run manually to refresh; CI never touches
the network.
"""
import json
import urllib.request

URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
OUT = "scripts/attack_data.json"


def main() -> None:
    d = json.load(urllib.request.urlopen(URL, timeout=120))
    objs = d["objects"]
    out = {}
    skipped = 0
    for o in objs:
        if o.get("type") != "attack-pattern":
            continue
        if o.get("revoked") or o.get("x_mitre_deprecated"):
            skipped += 1
            continue
        tid = None
        for r in o.get("external_references", []):
            if r.get("source_name") == "mitre-attack":
                tid = r.get("external_id")
                break
        if not tid:
            continue
        tactics = sorted({
            p["phase_name"] for p in o.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack"
        })
        out[tid] = {"name": o["name"], "tactics": tactics}
    json.dump(out, open(OUT, "w"), indent=0, sort_keys=True)
    print(f"techniques kept: {len(out)}, skipped revoked/deprecated: {skipped}")


if __name__ == "__main__":
    main()
