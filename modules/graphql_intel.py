"""GraphQL Intel — introspection, query depth, IDOR"""
from core.config import GRAPHQL_PATHS, INTROSPECTION_QUERY, R, R2, B, B2, W, Y, G, D, N
from core.engine import http_get, http_post, save_report, vuln
import json

def run(target):
    print(f"\n{B2}  GraphQL intel on {W}{target}{N}")
    vulns = 0; findings = []
    gql_url = None

    # Find GraphQL endpoint
    print(f"\n{D}  Discovering GraphQL endpoints...{N}")
    for path in GRAPHQL_PATHS:
        url = target + path
        # Test with introspection
        code, body = http_post(url, INTROSPECTION_QUERY, timeout=8)
        if code == 200 and ("__schema" in body or "types" in body or "queryType" in body):
            gql_url = url
            vuln("INFO", f"GraphQL endpoint found: {path}", "")
            findings.append({"type":"gql_endpoint","url":url})
            break
        # GET test
        code, hdrs, body = http_get(url + "?query={__typename}", timeout=6)
        if code == 200 and ("data" in body and "__typename" in body):
            gql_url = url
            vuln("INFO", f"GraphQL endpoint (GET): {path}", "")
            findings.append({"type":"gql_endpoint","url":url})
            break

    if not gql_url:
        print(f"{Y}  [!] No GraphQL endpoint found{N}")
        return 0

    # Introspection enabled?
    print(f"\n{D}  Testing introspection...{N}")
    code, body = http_post(gql_url, INTROSPECTION_QUERY, timeout=10)
    if code == 200 and "__schema" in body:
        vuln("HIGH", "GraphQL introspection enabled!", "Full schema exposed")
        vulns += 1; findings.append({"type":"introspection","url":gql_url})
        try:
            data = json.loads(body)
            types = data.get("data",{}).get("__schema",{}).get("types",[])
            print(f"   {D}  └─ {len(types)} types exposed{N}")
            for t in types[:10]:
                name = t.get("name","")
                if not name.startswith("__"):
                    fields = [f.get("name","") for f in t.get("fields",[]) or []]
                    print(f"   {D}     {name}: {', '.join(fields[:5])}{N}")
        except: pass

    # Query depth abuse
    print(f"\n{D}  Testing query depth limit...{N}")
    deep = '{"query":"{ a { b { c { d { e { f { g { h { i { j { k { l { m { n { o { p { q { r { s { t { u { v { w { x { y { z { __typename } } } } } } } } } } } } } } } } } } } } } } } } } } }"}'
    code, body = http_post(gql_url, deep, timeout=10)
    if code == 200 and "data" in body and "error" not in body.lower():
        vuln("MEDIUM", "No query depth limit!", "DoS via deep nested queries")
        vulns += 1; findings.append({"type":"depth_limit","url":gql_url})

    # Batch query abuse
    print(f"\n{D}  Testing batch query limit...{N}")
    batch = "[" + ",".join(['{"query":"{__typename}"}'] * 50) + "]"
    code, body = http_post(gql_url, batch, timeout=10)
    if code == 200 and body.count("__typename") > 10:
        vuln("MEDIUM", "No batch query limit!", "DoS via batched queries")
        vulns += 1; findings.append({"type":"batch_limit","url":gql_url})

    # IDOR via GraphQL
    print(f"\n{D}  Testing GraphQL IDOR...{N}")
    for q in ['{"query":"{ user(id: 1) { id name email } }"}',
              '{"query":"{ users { id name email password } }"}',
              '{"query":"{ admin { id name role } }"}']:
        code, body = http_post(gql_url, q, timeout=8)
        if code == 200 and "data" in body:
            if any(m in body for m in ["email","password","token","secret"]):
                vuln("HIGH", "GraphQL IDOR — sensitive data!", q[:50])
                vulns += 1; findings.append({"type":"gql_idor","query":q[:80]})

    print(f"\n{G}  [✓] GraphQL scan done — {vulns} findings{N}")
    if findings: save_report("graphql", {"target":target,"findings":findings})
    return vulns
