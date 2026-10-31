"""Node.js Recon — fingerprint, env leak, debug port, source maps"""
from core.config import NODE_PATHS, SOURCEMAP_PATHS, DEBUG_PORTS, R, R2, B, B2, W, Y, G, D, N
from core.engine import http_get, check_port, detect_node, save_report, vuln, get_host

def run(target):
    print(f"\n{B2}  Recon on {W}{target}{N}")
    vulns = 0; findings = []

    # Fingerprint
    code, hdrs, body = http_get(target)
    if code > 0:
        info = detect_node(hdrs, body)
        if info.get("runtime"):
            vuln("INFO", f"Node.js detected: {info['runtime']}", info.get("framework",""))
            vulns += 1; findings.append({"type":"fingerprint","info":info})
        if info.get("framework") and info["framework"] != "unknown":
            vuln("INFO", f"Framework: {info['framework']}", f"Server: {info.get('server','?')}")
            vulns += 1
        if info.get("x-powered-by"):
            vuln("LOW", "X-Powered-By exposed", info["x-powered-by"])
            vulns += 1; findings.append({"type":"x-powered-by","val":info["x-powered-by"]})

    # Scan paths
    print(f"\n{D}  Checking {len(NODE_PATHS)} paths...{N}")
    for path in NODE_PATHS:
        url = target + path; code, hdrs, body = http_get(url, timeout=7)
        if code == 0 or code == 404: continue

        if ".env" in path and code == 200:
            if any(k in body for k in ["DB_","MONGO","PORT=","NODE_ENV","SECRET","API_KEY","JWT","REDIS","AWS_"]):
                vuln("CRITICAL", "Environment file leaked!", "Credentials/secrets exposed", url)
                vulns += 1; findings.append({"type":"env_leak","url":url})

        elif path == "/package.json" and code == 200 and "dependencies" in body:
            vuln("HIGH", "package.json exposed!", "Dependencies & versions visible", url)
            vulns += 1; findings.append({"type":"package_json","url":url})
            try:
                import json; pkg = json.loads(body)
                deps = pkg.get("dependencies",{})
                for d in ["express","mongoose","jsonwebtoken","lodash","axios","helmet"]:
                    if d in deps:
                        print(f"   {D}  └─ {d}: {deps[d]}{N}")
            except: pass

        elif ".git" in path and code == 200 and len(body) > 5:
            vuln("HIGH", "Git exposed!", url)
            vulns += 1; findings.append({"type":"git","url":url})

        elif path in ("/health","/healthz","/status","/ready","/metrics"):
            if code == 200 and len(body) < 2000:
                vuln("MEDIUM", f"Debug endpoint open: {path}", f"{len(body)}b", url)
                vulns += 1; findings.append({"type":"debug_endpoint","url":url})

        elif path in ("/api-docs","/swagger.json","/openapi.json"):
            if code == 200 and ("swagger" in body.lower() or "openapi" in body.lower() or "paths" in body):
                vuln("HIGH", "API docs exposed!", url)
                vulns += 1; findings.append({"type":"api_docs","url":url})

    # Source maps
    print(f"\n{D}  Checking source maps...{N}")
    for path in SOURCEMAP_PATHS:
        url = target + path; code, hdrs, body = http_get(url, timeout=6)
        if code == 200 and ("sources" in body or "mappings" in body):
            vuln("HIGH", "Source map leaked!", "Original source code recoverable", url)
            vulns += 1; findings.append({"type":"sourcemap","url":url})
            break

    # Debug port
    host = get_host(target)
    print(f"\n{D}  Checking Node debug ports on {host}...{N}")
    for port in DEBUG_PORTS:
        if check_port(host, port, timeout=2):
            vuln("CRITICAL", f"Node.js debug port open: {port}!",
                 "RCE via chrome-devtools:// or --inspect", f"{host}:{port}")
            vulns += 1; findings.append({"type":"debug_port","port":port})

    print(f"\n{G}  [✓] Recon done — {vulns} findings{N}")
    if findings: save_report("node_recon", {"target":target,"findings":findings})
    return vulns
