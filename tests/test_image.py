from datetime import datetime, timezone

from dvscan.checks.image import check_age, check_history, check_image_config


def test_secrets_leaking_into_history():
    history = [
        {"CreatedBy": "RUN |2 NPM_TOKEN=npm_" + "a" * 36 + " NODE_ENV=production /bin/sh -c npm ci # buildkit"},
        {"CreatedBy": "/bin/sh -c #(nop)  ARG DB_PASSWORD=letmein123"},
        {"CreatedBy": "ENV API_KEY=abcdef123456"},
        {"CreatedBy": "RUN /bin/sh -c echo AKIAIOSFODNN7EXAMPLE > /root/.aws # buildkit"},
        {"CreatedBy": "RUN /bin/sh -c echo AKIAIOSFODNN7EXAMPLE > /root/.aws2 # buildkit"},
    ]
    assert [h.detail for h in check_history(history)] == [
        "Build argument NPM_TOKEN contains an npm token",
        "ARG DB_PASSWORD default looks like a credential",
        "A layer's build command contains an AWS access key",
    ]


def test_image_age():
    now = datetime(2026, 9, 1, tzinfo=timezone.utc)
    assert [h.rule.id for h in check_age("2024-06-01T12:00:00.123456789Z", now)] == ["stale-image"]
    assert list(check_age("2026-05-01T00:00:00Z", now)) == []
    assert list(check_age("1970-01-01T00:00:00Z", now)) == []
    assert list(check_age("", now)) == []


def test_image_config():
    data = {"Config": {"User": "", "Env": ["PATH=/usr/bin", "PGPASSWORD=postgres"], "ExposedPorts": {"22/tcp": {}}}}
    assert sorted(h.rule.id for h in check_image_config("myapp", data)) == [
        "latest-tag", "no-healthcheck", "root-user", "secret-in-env", "ssh-port",
    ]
