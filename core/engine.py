import urllib.request, urllib.parse, urllib.error, ssl, json, os, time, re
import socket, datetime
from core.config import R, R2, B, B2, W, Y, O, G, D, N

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

def http_get(url, timeout=10, headers=None):
    hdrs = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Accept": "application/json, text/html, */*"}
    if headers: hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs)
    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=CTX)
        body = resp.read().decode(errors="replace")
        rh = {k.lower(): v for k, v in resp.getheaders()}
        return resp.getcode(), rh, body
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode(errors="replace")
            rh = {k.lower(): v for k, v in e.headers.items()}
        except: body = ""; rh = {}
        return e.code, rh, body
    except: return 0, {}, ""

def http_post(url, data, timeout=10, ctype="application/json"):
    hdrs = {"User-Agent": "Mozilla/5.0", "Content-Type": ctype,
            "Accept": "application/json"}
    if isinstance(data, str): data = data.encode()
    req = urllib.request.Request(url, data=data, headers=hdrs)
    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=CTX)
        return resp.getcode(), resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        try: return e.code, e.read().decode(errors="replace")
        except: return e.code, ""
    except: return 0, ""

def check_port(host, port, timeout=3):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.close()
        return True
    except: return False

def detect_node(headers, body):
    info = {}
    xpb = headers.get("x-powered-by", "")
    if "express" in xpb.lower():
        info["framework"] = "Express.js"
    elif "koa" in xpb.lower():
        info["framework"] = "Koa"
    elif "fastify" in xpb.lower():
        info["framework"] = "Fastify"
    elif "hapi" in xpb.lower():
        info["framework"] = "Hapi"
    else:
        info["framework"] = "unknown"
    info["x-powered-by"] = xpb
    srv = headers.get("server", "")
    info["server"] = srv
    if "node" in srv.lower() or "node" in xpb.lower():
        info["runtime"] = "Node.js"
    elif body and ("__NEXT_DATA__" in body or "_next/static" in body):
        info["framework"] = "Next.js"
        info["runtime"] = "Node.js"
    elif body and ("__NUXT__" in body or "_nuxt/" in body):
        info["framework"] = "Nuxt.js"
        info["runtime"] = "Node.js"
    elif body and ("react" in body.lower() and "webpack" in body.lower()):
        info["runtime"] = "likely Node.js"
    return info

def save_report(name, data):
    loot = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "loot")
    os.makedirs(loot, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"{name}_{ts}.json"
    with open(os.path.join(loot, fname), "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"\n{G}  [✓] Saved: loot/{fname}{N}")

def vuln(sev, title, detail="", url=""):
    c = {"CRITICAL": R, "HIGH": R2, "MEDIUM": O, "LOW": Y, "INFO": B2}.get(sev, W)
    print(f"  {c}[{sev}]{W} {title}{N}")
    if detail: print(f"   {D}└─ {detail}{N}")
    if url: print(f"   {D}   {url}{N}")

def get_host(url):
    try: return urllib.parse.urlparse(url).hostname
    except: return "127.0.0.1"
