import re

TOKENS = [
    ("a private key", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")),
    ("an AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("a GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})")),
    ("a GitLab token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}")),
    ("a Slack token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}")),
    ("a Stripe key", re.compile(r"\b[rs]k_live_[A-Za-z0-9]{20,}")),
    ("a Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}")),
    ("an Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    ("an OpenAI API key", re.compile(r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}")),
    ("an npm token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("a PyPI token", re.compile(r"\bpypi-AgE[A-Za-z0-9_-]{50,}")),
    ("a SendGrid key", re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}")),
    ("a Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{30,}")),
    ("a JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
]
URL_PASSWORD = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:/@]+:([^\s/@]+)@", re.I)

SECRET_NAME = re.compile(
    r"passw(?:or)?d|passwd|(?:^|_)pwd$|secret|token|api_?key|private_?key|access_?key|auth_?key|"
    r"signing_?key|encryption_?key|master_?key|session_?key|credentials?|conn(?:ection)?_?str(?:ing)?",
    re.I,
)
HARMLESS_SUFFIXES = (
    "_FILE", "_PATH", "_DIR", "_ID", "_NAME", "_USER", "_USERNAME", "_URL", "_URI", "_ENDPOINT",
    "_HOST", "_PORT", "_TTL", "_TIMEOUT", "_EXPIRY", "_EXPIRES", "_EXPIRATION", "_LIFETIME", "_SECONDS",
    "_LENGTH", "_SIZE", "_MIN", "_MAX", "_COUNT", "_LIMIT", "_RETRIES", "_TYPE", "_METHOD", "_MODE",
    "_ENABLED", "_REQUIRED", "_HEADER", "_ALGORITHM", "_ALGO", "_ROUNDS", "_POLICY", "_PROVIDER",
    "_BACKEND", "_VERSION", "_FORMAT", "_PREFIX",
)
PLACEHOLDER = re.compile(r"^(?:<[^>]*>|\{\{.*\}\}|%\w+%)$")
BORING_VALUES = {
    "true", "false", "yes", "no", "on", "off", "none", "null", "nil",
    "enabled", "disabled", "required", "optional",
}

ANY_VALUE = None
INSECURE_SETTINGS = {
    "POSTGRES_HOST_AUTH_METHOD": ({"trust"}, "PostgreSQL accepts logins without a password"),
    "MYSQL_ALLOW_EMPTY_PASSWORD": (ANY_VALUE, "MySQL root may have an empty password"),
    "MARIADB_ALLOW_EMPTY_ROOT_PASSWORD": (ANY_VALUE, "MariaDB root may have an empty password"),
    "MARIADB_ALLOW_EMPTY_PASSWORD": (ANY_VALUE, "MariaDB root may have an empty password"),
    "ALLOW_EMPTY_PASSWORD": ({"yes", "true", "1"}, "the service accepts an empty password"),
    "NODE_TLS_REJECT_UNAUTHORIZED": ({"0"}, "Node.js skips TLS certificate checks"),
    "PYTHONHTTPSVERIFY": ({"0"}, "Python skips TLS certificate checks"),
    "GIT_SSL_NO_VERIFY": (ANY_VALUE, "git skips TLS certificate checks"),
    "NPM_CONFIG_STRICT_SSL": ({"false"}, "npm skips TLS certificate checks"),
    "XPACK.SECURITY.ENABLED": ({"false"}, "Elasticsearch runs without authentication or TLS"),
    "XPACK_SECURITY_ENABLED": ({"false"}, "Elasticsearch runs without authentication or TLS"),
}


def find_tokens(text):
    if not text:
        return []
    found = [label for label, pattern in TOKENS if pattern.search(text)]
    for match in URL_PASSWORD.finditer(text):
        if not _placeholder(match.group(1)):
            found.append("a password in a URL")
            break
    return found


def secret_name(name):
    key = name.upper().replace("-", "_").replace(".", "_")
    if key in ("PWD", "OLDPWD") or key.endswith(HARMLESS_SUFFIXES):
        return False
    if "PUBLIC" in key or "PUBLISHABLE" in key:
        return False
    return bool(SECRET_NAME.search(key))


def check_variable(name, value):
    value = (value or "").strip()
    if not value:
        return None
    tokens = find_tokens(value)
    if tokens:
        return f"contains {tokens[0]}"
    if not secret_name(name) or _placeholder(value):
        return None
    if value.lower() in BORING_VALUES or value.isdigit():
        return None
    if value.startswith(("/", "./", "~/", "file:")) and " " not in value:
        return None
    return "looks like a credential"


def insecure_setting(name, value):
    rule = INSECURE_SETTINGS.get(name.upper())
    value = (value or "").strip().lower()
    if not rule or not value:
        return None
    bad_values, message = rule
    if bad_values is ANY_VALUE or value in bad_values:
        return message
    return None


def _placeholder(value):
    return bool(PLACEHOLDER.match(value)) or value.startswith("$") or set(value) <= {"*", "x", "X"}
