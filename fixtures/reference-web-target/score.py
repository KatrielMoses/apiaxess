"""Score a web-capture run against the reference web target's ground truth.

Usage:
  python score.py ground-truth.json surface.json out.json [--engine URL | --capture capture.json]
  python score.py --dump URL capture.json

`surface.json` is the fused surface (the body of POST /api/v1/web/fuse). The
capture side (HTTP flows, WebSocket connections and messages, SSE events) is
read live from a running engine (`--engine http://127.0.0.1:7777`) or from a
file written earlier by `--dump`, so a run can be re-scored offline.

REST endpoints match the manifest by method + host + path skeleton (params
collapse to {}), then by the concrete sample path (under-templated), then by
any method (wrong method). Surface endpoints left unmatched are phantoms; the
WebSocket handshake or the gRPC-Web call showing up as a REST endpoint is a
leak. Third-party endpoints only fuse once their host is in scope, so a
third-party miss with no endpoint on that host at all is reported as such.
"""
import base64
import json
import re
import sys
import urllib.request
from urllib.parse import urlparse

PAGE = 1000


def fetch(engine, path):
    request = urllib.request.Request(engine.rstrip("/") + path, headers={"Origin": engine.rstrip("/")})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def dump(engine):
    flows = fetch(engine, "/api/v1/workbench/flows")
    sse = {}
    for flow in flows:
        if flow.get("sse"):
            sse[str(flow["id"])] = fetch(engine, f"/api/v1/workbench/flows/{flow['id']}/sse-events?limit={PAGE}")
    connections = fetch(engine, "/api/v1/workbench/ws-connections")
    for connection in connections:
        connection["messages"] = fetch(engine, f"/api/v1/workbench/ws-connections/{connection['id']}/messages?limit={PAGE}")
    return {"engine": engine, "flows": flows, "sse_events": sse, "ws_connections": connections}


if len(sys.argv) >= 2 and sys.argv[1] == "--dump":
    capture = dump(sys.argv[2])
    json.dump(capture, open(sys.argv[3], "w"), indent=1)
    print(f'dumped {len(capture["flows"])} flows, {len(capture["ws_connections"])} WebSocket connections, '
          f'{len(capture["sse_events"])} event streams to {sys.argv[3]}')
    sys.exit(0)

gt = json.load(open(sys.argv[1]))
surf = json.load(open(sys.argv[2]))
out_path = sys.argv[3]
capture = None
if "--engine" in sys.argv:
    capture = dump(sys.argv[sys.argv.index("--engine") + 1])
elif "--capture" in sys.argv:
    capture = json.load(open(sys.argv[sys.argv.index("--capture") + 1]))


def authority(origin):
    return urlparse(origin).netloc.lower()


HOSTS = {"first": authority(gt["origins"]["first_party"]), "third": authority(gt["origins"]["third_party"])}
PARTY = {"first": "first_party", "third": "third_party"}


def skel(path):
    return re.sub(r"\{[^}]*\}", "{}", path.rstrip("/") or "/")


def pattern(path):
    return re.compile("^" + re.sub(r"\\\{[^}]*\\\}", "[^/]+", re.escape(path)) + "$")


def body_keys(slot):
    keys = set()

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "properties" and isinstance(value, dict):
                    keys.update(value.keys())
                elif key == "properties" and isinstance(value, list):
                    keys.update(p["name"] for p in value if isinstance(p, dict) and "name" in p)
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(slot)
    return sorted(keys)


def sources(entry):
    found = set()
    for fact in entry.get("fact_confidence", []):
        if fact["path"].endswith(".presence") and fact["path"].count(".") == 1:
            found.update(fact.get("sources", []))
    return sorted(found)


# ---------------------------------------------------------------- REST ----

rec = []
for index, entry in enumerate(surf.get("endpoints", [])):
    endpoint = entry["endpoint"]
    identity = endpoint["identity"]
    rec.append({
        "i": index,
        "method": identity["method"],
        "host": (identity.get("host") or "").lower() or None,
        "path": identity["path_template"],
        "query": sorted(q["name"] for q in endpoint.get("query_parameters", [])),
        "headers": sorted(h["name"].lower() for h in endpoint.get("headers", [])),
        "body": body_keys(endpoint.get("request_body")) if endpoint.get("request_body") else None,
        "responses": len(endpoint.get("responses", [])),
        "party": entry.get("party"),
        "sources": sources(entry),
    })


def host_of(g):
    return HOSTS[g["party"]]


def match(g):
    host = host_of(g)
    sample = g["sample_path"].split("?")[0]
    on_host = [r for r in rec if r["host"] == host]
    exact = [r for r in on_host if r["method"] == g["method"] and skel(r["path"]) == skel(g["path"])]
    if exact:
        return exact, "template"
    concrete = [r for r in on_host if r["method"] == g["method"] and (r["path"].rstrip("/") or "/") == (sample.rstrip("/") or "/")]
    if concrete:
        return concrete, "concrete"
    anymethod = [r for r in on_host if skel(r["path"]) == skel(g["path"]) or r["path"] == sample]
    if anymethod:
        return anymethod, "wrong-method"
    return [], None


used = set()
rows = []
leaks = []
for g in gt["endpoints"]:
    found, kind = match(g)
    if g["surface"] != "endpoint":
        # The WebSocket handshake and the gRPC-Web call are not REST endpoints.
        for r in found:
            used.add(r["i"])
            leaks.append({"id": g["id"], "protocol": g["protocol"], "got": f'{r["method"]} {r["host"]}{r["path"]}'})
        continue
    for r in found:
        used.add(r["i"])
    row = {"id": g["id"], "party": g["party"], "protocol": g["protocol"], "trigger": g["trigger"],
           "gt": f'{g["method"]} {host_of(g)}{g["path"]}', "kind": kind}
    if not found and g["party"] == "third" and not any(r["host"] == host_of(g) for r in rec):
        row["note"] = "third-party host not in the surface (out of scope unless added)"
    if found:
        r = found[0]
        body_gt = sorted(g["body"].keys()) if g["body"] else None
        row.update({
            "got": f'{r["method"]} {r["host"]}{r["path"]}', "sources": r["sources"],
            "party_got": r["party"], "party_ok": r["party"] == PARTY[g["party"]],
            "query": r["query"], "query_ok": sorted(g["query"]) == r["query"],
            "headers": r["headers"], "headers_ok": all(h.lower() in r["headers"] for h in g["headers"]),
            "body_gt": body_gt, "body": r["body"], "body_ok": body_gt is None or (r["body"] is not None and set(body_gt) <= set(r["body"])),
            "responses": r["responses"], "dups": len(found),
        })
    rows.append(row)
phantoms = [r for r in rec if r["i"] not in used]

# ---------------------------------------------------- protocol operations ----

ops = (surf.get("surface") or {}).get("protocol_operations", [])
got_graphql = []
got_grpc = []
for op in ops:
    identity = op.get("identity", {})
    if identity.get("kind") in ("graph_ql", "graphql"):
        got_graphql.append({"type": identity.get("operation_type"), "name": identity.get("operation_name"),
                            "url": identity.get("endpoint_url")})
    elif identity.get("kind") == "grpc":
        got_grpc.append({"service": identity.get("service"), "method": identity.get("method")})

endpoint_by_id = {e["id"]: e for e in gt["endpoints"]}
op_rows = []
for g in gt["graphql_operations"]:
    endpoint = endpoint_by_id[g["endpoint"]]
    want_url_path = endpoint["path"]
    hit = [o for o in got_graphql if o["type"] == g["type"] and o["name"] == g["name"]]
    url_ok = any(o["url"] and urlparse(o["url"]).netloc.lower() == host_of(endpoint) and urlparse(o["url"]).path == want_url_path for o in hit)
    op_rows.append({"id": g["id"], "gt": f'{g["type"]} {g["name"]}', "found": bool(hit), "url_ok": url_ok,
                    "trigger": g["trigger"]})
for g in gt["grpc_operations"]:
    hit = [o for o in got_grpc if o["service"] == g["service"] and o["method"] == g["method"]]
    op_rows.append({"id": g["id"], "gt": f'gRPC {g["service"]}/{g["method"]}', "found": bool(hit), "trigger": g["trigger"]})
expected_ops = {("graphql", g["type"], g["name"]) for g in gt["graphql_operations"]} | {("grpc", g["service"], g["method"]) for g in gt["grpc_operations"]}
phantom_ops = [o for o in got_graphql if ("graphql", o["type"], o["name"]) not in expected_ops] + \
              [o for o in got_grpc if ("grpc", o["service"], o["method"]) not in expected_ops]

# ------------------------------------------------------- capture side ----

flow_rows = ws_report = sse_report = None
if capture is not None:
    flows = [f for f in capture["flows"] if f.get("origin", "capture") == "capture" and f.get("method") != "CONNECT"]

    def flow_authority(flow):
        url = flow.get("url") or ""
        return urlparse(url).netloc.lower() if "://" in url else (flow.get("host") or "").lower()

    flow_rows = []
    for g in gt["endpoints"]:
        test = pattern(g["path"])
        hits = [f for f in flows if f.get("method") == g["method"] and flow_authority(f) == host_of(g)
                and test.match((f.get("path") or "").split("?")[0])]
        flow_rows.append({"id": g["id"], "gt": f'{g["method"]} {host_of(g)}{g["sample_path"]}', "captured": len(hits),
                          "status": sorted({f.get("status") for f in hits}, key=str)})
    documented = [pattern(g["path"]) for g in gt["endpoints"]]
    extra_flows = [f'{f.get("method")} {flow_authority(f)}{f.get("path")}' for f in flows
                   if flow_authority(f) in HOSTS.values()
                   and not any(p.match((f.get("path") or "").split("?")[0]) for p in documented)]

    # WebSocket: the connection to the manifest's path, message by message.
    ws_gt = gt["websocket"]
    ws_path = endpoint_by_id[ws_gt["endpoint"]]["path"]
    connections = [c for c in capture["ws_connections"]
                   if urlparse(c["url"]).netloc.lower() == HOSTS["first"] and urlparse(c["url"]).path == ws_path]
    ws_report = {"connections": len(connections), "messages": []}
    if connections:
        connection = connections[-1]
        got = {m["sequence"]: m for m in connection["messages"]}
        for want in ws_gt["messages"]:
            m = got.get(want["seq"])
            ok = m is not None and m["direction"] == want["direction"] and m["kind"] == want["kind"]
            if ok and want["kind"] == "text":
                ok = base64.b64decode(m["payloadBase64"]).decode("utf-8", "replace") == want["payload"]
            elif ok and want["kind"] == "binary":
                ok = base64.b64decode(m["payloadBase64"]).hex() == want["payload_hex"]
            ws_report["messages"].append({"seq": want["seq"], "direction": want["direction"], "kind": want["kind"], "ok": ok,
                                          "got": None if m is None else f'{m["direction"]} {m["kind"]}'})
        ws_report.update({"url": connection["url"], "captured_messages": len(connection["messages"]),
                          "closed": connection.get("closedAt") is not None, "close_code": connection.get("closeCode"),
                          "party": connection.get("party")})

    # SSE: the stream flow's state and its events.
    sse_gt = gt["sse"]
    sse_endpoint = endpoint_by_id[sse_gt["endpoint"]]
    test = pattern(sse_endpoint["path"])
    streams = [f for f in flows if f.get("method") == "GET" and flow_authority(f) == HOSTS["first"]
               and test.match((f.get("path") or "").split("?")[0])]
    sse_report = {"flows": len(streams), "events": []}
    if streams:
        stream = streams[-1]
        events = {e["sequence"]: e for e in capture["sse_events"].get(str(stream["id"]), [])}
        for want in sse_gt["events"]:
            e = events.get(want["seq"])
            ok = e is not None and e.get("event") == want["event"] and e.get("id") == want["id"] and e.get("data") == want["data"]
            sse_report["events"].append({"seq": want["seq"], "ok": ok, "got": e and {k: e.get(k) for k in ("event", "id", "data")}})
        sse_report.update({"state": stream.get("sse"), "captured_events": len(events)})

# --------------------------------------------------------------- report ----

first = [r for r in rows if r["party"] == "first"]
third = [r for r in rows if r["party"] == "third"]
summary = {
    "rest_first_party": f'{sum(1 for r in first if r["kind"])}/{len(first)}',
    "rest_first_party_templated": f'{sum(1 for r in first if r["kind"] == "template")}/{len(first)}',
    "rest_third_party": f'{sum(1 for r in third if r["kind"])}/{len(third)}',
    "party_labels_ok": f'{sum(1 for r in rows if r.get("party_ok"))}/{sum(1 for r in rows if r["kind"])}',
    "phantoms": len(phantoms),
    "leaks": len(leaks),
    "protocol_operations": f'{sum(1 for r in op_rows if r["found"])}/{len(op_rows)}',
    "phantom_operations": len(phantom_ops),
    "surface_endpoints": len(rec),
}
if flow_rows is not None:
    summary["captured_flows"] = f'{sum(1 for r in flow_rows if r["captured"])}/{len(flow_rows)}'
    summary["undocumented_flows"] = len(extra_flows)
    summary["websocket_messages"] = f'{sum(1 for m in ws_report["messages"] if m["ok"])}/{len(gt["websocket"]["messages"])}'
    summary["sse_events"] = f'{sum(1 for e in sse_report["events"] if e["ok"])}/{len(gt["sse"]["events"])}'

out = {"summary": summary, "rows": rows, "phantoms": phantoms, "leaks": leaks, "operations": op_rows,
       "phantom_operations": phantom_ops}
if flow_rows is not None:
    out.update({"flows": flow_rows, "undocumented_flows": extra_flows, "websocket": ws_report, "sse": sse_report})
json.dump(out, open(out_path, "w"), indent=1)

print("REST endpoints (fused surface)")
for r in rows:
    if not r["kind"]:
        print(f'  {r["id"]} MISS      {r["gt"]:<52} [{r["protocol"]}; {r["trigger"]}]' + (f'  ({r["note"]})' if r.get("note") else ""))
        continue
    print(f'  {r["id"]} {r["kind"]:<9} {r["got"]:<52} src={",".join(s.replace("_analysis", "").replace("_capture", "") for s in r["sources"])} '
          f'party={"ok" if r["party_ok"] else r["party_got"]} q={"ok" if r["query_ok"] else r["query"]} '
          f'hdr={"ok" if r["headers_ok"] else "MISS"} body={"ok" if r["body_ok"] else r["body"]} resp={r["responses"]} dups={r["dups"]}')
for leak in leaks:
    print(f'  LEAK {leak["id"]} {leak["protocol"]} surfaced as REST endpoint {leak["got"]}')
for p in phantoms:
    print(f'  PHANTOM {p["method"]} {p["host"]}{p["path"]} src={p["sources"]}')
print("Protocol operations")
for r in op_rows:
    extra = "" if "url_ok" not in r else f' url={"ok" if r["url_ok"] else "BAD"}'
    print(f'  {r["id"]} {"found" if r["found"] else "MISS "} {r["gt"]}{extra}')
for o in phantom_ops:
    print(f"  PHANTOM-OP {o}")
if flow_rows is not None:
    print("Captured HTTP flows")
    for r in flow_rows:
        print(f'  {r["id"]} {"ok  " if r["captured"] else "MISS"} x{r["captured"]} {r["gt"]} status={r["status"]}')
    for f in extra_flows:
        print(f"  UNDOCUMENTED {f}")
    print(f'WebSocket: {ws_report["connections"]} connection(s)' + ("" if not ws_report["connections"] else
          f', {ws_report["captured_messages"]} messages, closed={ws_report["closed"]} code={ws_report["close_code"]} party={ws_report["party"]}'))
    for m in ws_report["messages"]:
        print(f'  #{m["seq"]} {"ok  " if m["ok"] else "BAD "} {m["direction"]} {m["kind"]}' + ("" if m["ok"] else f' (got {m["got"]})'))
    print(f'SSE: {sse_report["flows"]} stream flow(s)' + ("" if not sse_report["flows"] else f', state={sse_report["state"]}'))
    for e in sse_report["events"]:
        print(f'  #{e["seq"]} {"ok  " if e["ok"] else "BAD "}' + ("" if e["ok"] else f' (got {e["got"]})'))
print("\nSummary: " + "; ".join(f"{k} {v}" for k, v in summary.items()))
