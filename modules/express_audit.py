"""Express.js Audit — CORS, headers, routes, middleware"""
from core.config import EXPRESS_PATHS, EXPRESS_HEADERS_CHECK, R, R2, B, B2, W, Y, G, D, N
from core.engine import http_get, save_report, vuln

def run(target):
    print(f"\n{B2}  Express.js audit on {W}{target}{N}")
    vulns = 0; findings = []

    # Main page headers
    code, hdrs, body = http_get(target)
    if code == 0:
        print(f"{Y}  [!] Target unreachable{N}"); return 0

    # Header analysis
    print(f"\n{D}  Analyzing security headers...{N}")
    for h, info in EXPRESS_HEADERS_CHECK.items():
        val = hdrs.get(h, "")
        if h == "x-powered-by":
            if val and "express" in val.lower():
                vuln("MEDIUM", "Express.js fingerprint", f"X-Powered-By: {val}")
                vulns += 1; findings.append({"type":"express_fp","header":val})
        elif h == "access-control-allow-origin":
            if val == "*":
                vuln("HIGH", "CORS wildcard!", "Any origin can make requests")
                vulns += 1; findings.append({"type":"cors_wildcard"})
            elif val:
                vuln("INFO", f"CORS configured: {val}", "")
        else:
            if not val:
                vuln("LOW", f"Missing: {h}", info["msg"])
                vulns += 1; findings.append({"type":"missing_header","header":h})

    # CORS misconfiguration test
    print(f"\n{D}  Testing CORS misconfiguration...{N}")
    evil = "https://evil.node2shell.com"
    code, hdrs, body = http_get(target, headers={"Origin": evil})
    acao = hdrs.get("access-control-allow-origin", "")
    acac = hdrs.get("access-control-allow-credentials", "")
    if acao == evil or acao == "*":
        vuln("CRITICAL", "CORS reflects attacker origin!", f"ACAO: {acao}, ACAC: {acac}")
        vulns += 1; findings.append({"type":"cors_reflect","origin":acao})

    # Route enumeration
    print(f"\n{D}  Enumerating {len(EXPRESS_PATHS)} routes...{N}")
    live_routes = []
    for path in EXPRESS_PATHS:
        url = target + path; code, hdrs, body = http_get(url, timeout=6)
        if code == 0: continue
        if code in (200, 201, 301, 302, 401, 403, 405, 500):
            live_routes.append({"path": path, "code": code, "size": len(body)})
            if code == 401:
                vuln("INFO", f"Auth-protected route: {path}", "")
            elif code == 500 and len(body) < 500:
                if "Error" in body or "stack" in body or "at " in body:
                    vuln("HIGH", f"Stack trace leak on {path}!", "Error details exposed")
                    vulns += 1; findings.append({"type":"stack_trace","url":url})

    if live_routes:
        print(f"   {G}[+]{W} {len(live_routes)} live routes found{N}")
        for r in live_routes[:10]:
            c = G if r["code"] == 200 else Y if r["code"] in (401,403) else R if r["code"] == 500 else D
            print(f"   {c}  {r['code']} {r['path']} ({r['size']}b){N}")
        findings.append({"type":"routes","count":len(live_routes),"routes":live_routes[:20]})

    # Check for verbose errors
    bad_url = target + "/api/nonexistent'\"\\><script>alert(1)</script>"
    code, hdrs, body = http_get(bad_url, timeout=6)
    if code > 0 and any(x in body for x in ["SyntaxError","TypeError","ReferenceError",
                                              "at Object.","node_modules","Cannot GET"]):
        vuln("MEDIUM", "Verbose error messages", "Node.js error details in response")
        vulns += 1; findings.append({"type":"verbose_errors"})

    print(f"\n{G}  [✓] Express audit done — {vulns} findings{N}")
    if findings: save_report("express_audit", {"target":target,"findings":findings})
    return vulns
