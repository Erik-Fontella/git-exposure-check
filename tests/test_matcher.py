from pathlib import Path
import pytest
from git_exposure.matcher import GitignoreMatcher


def test_matcher_without_gitignore(tmp_path: Path):
    matcher = GitignoreMatcher(tmp_path)
    assert not matcher.has_gitignore
    assert not matcher.is_ignored("some_file.env")


def test_matcher_with_gitignore(tmp_path: Path):
    gitignore_file = tmp_path / ".gitignore"
    gitignore_file.write_text(
        "# Regras de teste\n"
        "*.log\n"
        ".env*\n"
        "!.env.example\n"
        "secrets/\n"
        "build/\n",
        encoding="utf-8"
    )

    matcher = GitignoreMatcher(tmp_path)
    assert matcher.has_gitignore

    # Casos que devem ser ignorados
    assert matcher.is_ignored(".env")
    assert matcher.is_ignored(".env.local")
    assert matcher.is_ignored("debug.log")
    assert matcher.is_ignored("logs/app.log")
    assert matcher.is_ignored("secrets/passwords.txt")

    # Casos que NÃO devem ser ignorados
    assert not matcher.is_ignored(".env.example")
    assert not matcher.is_ignored("src/main.py")
    assert not matcher.is_ignored("id_rsa")


def test_matcher_missing_recommendations(tmp_path: Path):
    gitignore_file = tmp_path / ".gitignore"
    gitignore_file.write_text("*.log\nnode_modules/\n", encoding="utf-8")

    matcher = GitignoreMatcher(tmp_path)
    missing = matcher.find_missing_recommendations()

    # Recomendações críticas esperadas ausentes
    assert any(".env" in m for m in missing)
    assert any("*.key" in m or "*.pem" in m for m in missing)
