import pytest
from git_exposure.rules import (
    Severity,
    Category,
    find_matching_rule,
    get_default_rules,
)


def test_default_rules_exist():
    rules = get_default_rules()
    assert len(rules) >= 7
    ids = [r.rule_id for r in rules]
    assert "SEC-001" in ids
    assert "SEC-002" in ids
    assert "SEC-003" in ids


@pytest.mark.parametrize(
    "filename,expected_rule_id,expected_severity",
    [
        (".env", "SEC-001", Severity.CRITICAL),
        (".env.production", "SEC-001", Severity.CRITICAL),
        (".env.local", "SEC-001", Severity.CRITICAL),
        ("id_rsa", "SEC-002", Severity.CRITICAL),
        ("server.key", "SEC-002", Severity.CRITICAL),
        ("cert.pem", "SEC-002", Severity.CRITICAL),
        ("credentials.json", "SEC-003", Severity.CRITICAL),
        ("client_secret_xyz.json", "SEC-003", Severity.CRITICAL),
        ("database.sqlite3", "SEC-004", Severity.HIGH),
        ("app.db", "SEC-004", Severity.HIGH),
        ("dump.sql", "SEC-004", Severity.HIGH),
        (".bash_history", "SEC-005", Severity.HIGH),
        ("secret.tfvars", "SEC-006", Severity.HIGH),
        ("npm-debug.log", "SEC-007", Severity.MEDIUM),
    ]
)
def test_sensitive_files_match(filename, expected_rule_id, expected_severity):
    rule = find_matching_rule(filename)
    assert rule is not None, f"Arquivo {filename} deveria casar com uma regra."
    assert rule.rule_id == expected_rule_id
    assert rule.severity == expected_severity


@pytest.mark.parametrize(
    "safe_filename",
    [
        (".env.example"),
        (".env.sample"),
        (".env.template"),
        (".env.dist"),
        ("id_rsa.pub"),
        ("server.pub"),
        ("credentials.example.json"),
        ("schema.sql"),
        ("main.py"),
        ("README.md"),
        ("requirements.txt"),
    ]
)
def test_safe_files_do_not_trigger_false_positives(safe_filename):
    rule = find_matching_rule(safe_filename)
    assert rule is None, f"Arquivo seguro {safe_filename} gerou falso positivo com regra {rule.rule_id if rule else ''}"
