from pathlib import Path
import pytest
from git_exposure.scanner import FindingStatus, Scanner


def test_scanner_detects_unignored_sensitive_files(tmp_path: Path):
    # Cria arquivos de teste
    (tmp_path / ".env").write_text("API_KEY=123456", encoding="utf-8")
    (tmp_path / "server.key").write_text("-----BEGIN PRIVATE KEY-----", encoding="utf-8")
    (tmp_path / "safe.py").write_text("print('hello')", encoding="utf-8")
    (tmp_path / ".env.example").write_text("API_KEY=YOUR_KEY", encoding="utf-8")

    # .gitignore sem cobrir .env e .key
    (tmp_path / ".gitignore").write_text("*.log\nnode_modules/\n", encoding="utf-8")

    scanner = Scanner(tmp_path)
    report = scanner.scan()

    assert report.has_gitignore
    assert report.total_unprotected_count == 2

    # Verifica se encontrou .env e server.key como EXPOSED_UNIGNORED
    findings_files = {f.relative_path: f for f in report.findings}
    assert ".env" in findings_files
    assert findings_files[".env"].status == FindingStatus.UNIGNORED

    assert "server.key" in findings_files
    assert findings_files["server.key"].status == FindingStatus.UNIGNORED

    # Garante que .env.example e safe.py não estão nos achados
    assert ".env.example" not in findings_files
    assert "safe.py" not in findings_files


def test_scanner_recognizes_protected_files(tmp_path: Path):
    # Cria arquivo sensível
    (tmp_path / ".env").write_text("SECRET=xyz", encoding="utf-8")

    # .gitignore cobre adequadamente
    (tmp_path / ".gitignore").write_text(".env*\n", encoding="utf-8")

    scanner = Scanner(tmp_path)
    report = scanner.scan()

    assert report.total_unprotected_count == 0
    findings_files = {f.relative_path: f for f in report.findings}
    assert ".env" in findings_files
    assert findings_files[".env"].status == FindingStatus.PROTECTED


def test_scanner_custom_exclude(tmp_path: Path):
    # Cria pasta excluída e arquivo sensível dentro
    mock_dir = tmp_path / "mock_fixtures"
    mock_dir.mkdir()
    (mock_dir / ".env").write_text("TEST_SECRET=123", encoding="utf-8")

    # Scanner sem exclusão deve encontrar
    scanner_default = Scanner(tmp_path)
    assert scanner_default.scan().total_unprotected_count == 1

    # Scanner com exclusão não deve encontrar
    scanner_excluded = Scanner(tmp_path, exclude_patterns=["mock_fixtures"])
    assert scanner_excluded.scan().total_unprotected_count == 0
