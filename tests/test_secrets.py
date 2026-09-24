import pytest

from dvscan.secrets import check_variable, find_tokens, insecure_setting


@pytest.mark.parametrize("name, value", [
    ("DB_PASSWORD", "hunter2"),
    ("MYSQL_ROOT_PASSWORD", "root"),
    ("API_KEY", "abc123def456"),
    ("STRIPE_SECRET", "whatever-value"),
    ("app.client-secret", "s3cr3t"),
    ("anything", "AKIAIOSFODNN7EXAMPLE"),
    ("DATABASE_URL", "postgres://app:s3cret@db:5432/app"),
    ("DEPLOY_KEY", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA=="),
])
def test_flags_secrets(name, value):
    assert check_variable(name, value)


@pytest.mark.parametrize("name, value", [
    ("DB_PASSWORD", ""),
    ("DB_PASSWORD_FILE", "/run/secrets/db_password"),
    ("PASSWORD_MIN_LENGTH", "12"),
    ("TOKEN_TTL", "3600"),
    ("API_TOKEN", "${API_TOKEN}"),
    ("SECRET_KEY", "<change me>"),
    ("GPG_KEY", "A035C8C19219BA821ECEA86B64E628F8D684696D"),
    ("PWD", "/app"),
    ("STRIPE_PUBLISHABLE_KEY", "pk_live_abc"),
    ("TOKEN_ENABLED", "true"),
    ("DATABASE_URL", "postgres://app:${DB_PASSWORD}@db/app"),
    ("NGINX_VERSION", "1.27.3"),
])
def test_ignores_things_that_are_not_secrets(name, value):
    assert check_variable(name, value) is None


def test_token_patterns():
    assert find_tokens("export GH=ghp_" + "a" * 36) == ["a GitHub token"]
    assert find_tokens("curl https://user:${PASS}@example.com") == []
    assert find_tokens("nothing to see here") == []


@pytest.mark.parametrize("name, value, flagged", [
    ("POSTGRES_HOST_AUTH_METHOD", "trust", True),
    ("POSTGRES_HOST_AUTH_METHOD", "scram-sha-256", False),
    ("MYSQL_ALLOW_EMPTY_PASSWORD", "yes", True),
    ("MYSQL_ALLOW_EMPTY_PASSWORD", "", False),
    ("NODE_TLS_REJECT_UNAUTHORIZED", "0", True),
    ("NODE_TLS_REJECT_UNAUTHORIZED", "1", False),
    ("xpack.security.enabled", "false", True),
])
def test_insecure_settings(name, value, flagged):
    assert bool(insecure_setting(name, value)) is flagged
