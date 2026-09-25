"""Score an `apiaxess analyze --json` surface against the reference ground truth.

Usage: python score.py ground-truth.json surface.json out.json
Matches each manifest endpoint by method + path skeleton (params collapse to {}),
falls back to the concrete sample path (under-templated) and to any method
(wrong method); every surface endpoint left unmatched is reported as a phantom.
"""
import json, re, sys
from urllib.parse import urlparse

gt = json.load(open(sys.argv[1]))
surf = json.load(open(sys.argv[2]))

def sel(fact):
    if not fact: return None
    res = fact.get("resolution") or {}
    sid = res.get("selected")
    for c in fact.get("candidates", []):
        if c["id"] == sid: return c["value"]
    return fact["candidates"][0]["value"] if fact.get("candidates") else None

def cands(fact):
    return [c["value"] for c in (fact or {}).get("candidates", [])]

def skel(p):  # template skeleton: params collapse to {}
    return re.sub(r"\{[^}]*\}", "{}", p.rstrip("/") or "/")

def body_keys(slot):
    keys = set()
    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if k == "properties" and isinstance(v, dict):
                    keys.update(v.keys())
                elif k == "properties" and isinstance(v, list):
                    keys.update(p["name"] for p in v if isinstance(p, dict) and "name" in p)
                walk(v)
        elif isinstance(o, list):
            for x in o: walk(x)
    walk(slot)
    return sorted(keys)

rec = []
for i, e in enumerate(surf["endpoints"]):
    ep = e["endpoint"]
    pt = sel(ep["path_template"]) or {}
    srcs = set()
    for f in e.get("fact_confidence", []):
        if f["path"].endswith(".presence") and f["path"].count(".") == 1:
            srcs.update(f.get("sources", []))
    base = sel(ep.get("base_url"))
    rec.append({
        "i": i,
        "method": ep["identity"]["method"],
        "path": ep["identity"]["path_template"],
        "origin": pt.get("origin"),
        "base": base,
        "bases": cands(ep.get("base_url")),
        "host": (urlparse(base).hostname if "://" in base else base) if base else None,
        "query": sorted(q["name"] for q in ep["query_parameters"]),
        "pparams": sorted(p["name"] for p in ep.get("path_parameters", [])),
        "headers": sorted(h["name"].lower() for h in ep["headers"]),
        "body": body_keys(ep.get("request_body")) if ep.get("request_body") else None,
        "has_body": ep.get("request_body") is not None,
        "sources": sorted(srcs),
    })

def match(g):
    exact = [r for r in rec if r["method"] == g["method"] and skel(r["path"]) == skel(g["path"])]
    exact.sort(key=lambda r: r["host"] != g["host"])
    if exact: return exact, "template"
    concrete = [r for r in rec if r["method"] == g["method"] and r["path"].rstrip("/") == g["sample_path"].split("?")[0]]
    if concrete: return concrete, "concrete"
    anymethod = [r for r in rec if skel(r["path"]) == skel(g["path"]) or r["path"] == g["sample_path"].split("?")[0]]
    if anymethod: return anymethod, "wrong-method"
    return [], None

used = set()
rows = []
for g in gt["endpoints"]:
    m, kind = match(g)
    for r in m: used.add(r["i"])
    r = m[0] if m else None
    row = {"id": g["id"], "style": g["style"], "trigger": g["trigger"], "gt": f'{g["method"]} {g["host"]}{g["path"]}',
           "kind": kind}
    if r:
        body_gt = sorted(g["body"].keys()) if g["body"] else None
        row.update({
            "got": f'{r["method"]} {r["host"]}{r["path"]}', "origin": r["origin"], "sources": r["sources"],
            "host_ok": r["host"] == g["host"],
            "query_ok": sorted(g["query"]) == r["query"], "query": r["query"],
            "headers": r["headers"],
            "gt_headers_ok": all(h.lower() in r["headers"] for h in g["headers"]),
            "body_gt": body_gt, "body": r["body"], "has_body": r["has_body"],
            "dups": len(m),
        })
    rows.append(row)

phantoms = [r for r in rec if r["i"] not in used]
out = {"rows": rows, "phantoms": phantoms, "recovered": sum(1 for r in rows if r["kind"]),
       "total": len(rows), "surface_endpoints": len(rec)}
json.dump(out, open(sys.argv[3], "w"), indent=1)

for r in rows:
    if not r["kind"]:
        print(f'{r["id"]} MISS  {r["gt"]:<62} [{r["style"]}; {r["trigger"]}]')
        continue
    print(f'{r["id"]} {r["kind"]:<9} {r["got"]:<62} src={",".join(s.replace("_analysis","").replace("_capture","") for s in r["sources"])} '
          f'origin={r["origin"]} host={"ok" if r["host_ok"] else "BAD"} q={"ok" if r["query_ok"] else r["query"]} '
          f'hdr={"ok" if r["gt_headers_ok"] else "MISS"} body={r["body"] if r["body_gt"] else ("-" if not r["has_body"] else r["body"])}/{r["body_gt"]} dups={r["dups"]}')
print(f'\nrecall {out["recovered"]}/{out["total"]}; surface endpoints {len(rec)}; phantoms {len(phantoms)}')
for p in phantoms:
    print(f'  PHANTOM {p["method"]} {p["host"]}{p["path"]} src={p["sources"]} bases={p["bases"]}')
