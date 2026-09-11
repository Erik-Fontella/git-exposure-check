"""
Módulo Scanner de Exposição de Arquivos.
Percorre a árvore de diretórios do repositório, identifica arquivos que casam
com as regras de segredos e avalia se estão protegidos pelo .gitignore ou rastreados pelo Git.
"""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import subprocess
import time
from typing import Dict, List, Optional, Set

from git_exposure.matcher import GitignoreMatcher
from git_exposure.rules import Rule, Severity, find_matching_rule, get_default_rules


class FindingStatus(str, Enum):
    TRACKED = "TRACKED_IN_GIT"             # Arquivo já adicionado/commitado no Git (CRÍTICO)
    UNIGNORED = "EXPOSED_UNIGNORED"        # Arquivo existe e NÃO está coberto pelo .gitignore (ALTO)
    PROTECTED = "IGNORED_PROTECTED"        # Arquivo existe fisicamente, mas está coberto pelo .gitignore (OK)


@dataclass
class Finding:
    relative_path: str
    absolute_path: Path
    rule: Rule
    status: FindingStatus
    size_bytes: int
    recommendation: str


@dataclass
class ScanReport:
    target_path: str
    scanned_files_count: int
    findings: List[Finding]
    missing_recommendations: List[str]
    has_gitignore: bool
    is_git_repo: bool
    scan_duration_ms: float
    rules_applied_count: int

    @property
    def critical_or_high_unprotected_count(self) -> int:
        return sum(
            1 for f in self.findings
            if f.status in (FindingStatus.TRACKED, FindingStatus.UNIGNORED)
            and f.rule.severity in (Severity.CRITICAL, Severity.HIGH)
        )

    @property
    def total_unprotected_count(self) -> int:
        return sum(
            1 for f in self.findings
            if f.status in (FindingStatus.TRACKED, FindingStatus.UNIGNORED)
        )

    @property
    def status_counts(self) -> Dict[str, int]:
        counts = {
            FindingStatus.TRACKED.value: 0,
            FindingStatus.UNIGNORED.value: 0,
            FindingStatus.PROTECTED.value: 0,
        }
        for f in self.findings:
            counts[f.status.value] = counts.get(f.status.value, 0) + 1
        return counts


class Scanner:
    """Realiza varredura no sistema de arquivos e auditoria de segurança Git."""

    IGNORED_DIRS: Set[str] = {
        ".git", "node_modules", "venv", ".venv", "env",
        "__pycache__", ".tox", ".idea", ".vscode", "dist", "build",
        ".pytest_cache", ".mypy_cache"
    }

    def __init__(
        self,
        target_path: Path,
        rules: Optional[List[Rule]] = None,
        exclude_patterns: Optional[Iterable[str]] = None
    ):
        self.target_path = target_path.resolve()
        self.rules = rules if rules is not None else get_default_rules()
        self.matcher = GitignoreMatcher(self.target_path)
        self.ignored_dirs = set(self.IGNORED_DIRS)
        if exclude_patterns:
            for p in exclude_patterns:
                self.ignored_dirs.add(p.strip().rstrip("/\\"))
        self.tracked_files: Set[str] = set()
        self.is_git_repo = False
        self._detect_git_repo_and_tracked_files()

    def _detect_git_repo_and_tracked_files(self) -> None:
        """Detecta se o alvo é um repositório Git e obtém lista de arquivos já rastreados."""
        git_dir = self.target_path / ".git"
        if not git_dir.exists():
            return

        try:
            cmd = ["git", "-C", str(self.target_path), "ls-files"]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                encoding="utf-8",
                errors="replace"
            )
            if result.returncode == 0:
                self.is_git_repo = True
                for line in result.stdout.splitlines():
                    clean = line.strip().replace("\\", "/")
                    if clean:
                        self.tracked_files.add(clean.lower())
        except (FileNotFoundError, PermissionError, subprocess.SubprocessError):
            # Caso o comando git não esteja disponível no PATH, segue apenas com checagem local
            self.is_git_repo = git_dir.exists()

    def scan(self) -> ScanReport:
        """Executa a varredura completa da pasta alvo."""
        start_time = time.perf_counter()
        findings: List[Finding] = []
        scanned_count = 0

        if not self.target_path.exists():
            raise FileNotFoundError(f"Caminho especificado não existe: {self.target_path}")

        # Varredura recursiva de arquivos
        for file_path in self._walk_files():
            scanned_count += 1
            filename = file_path.name

            matching_rule = find_matching_rule(filename, self.rules)
            if not matching_rule:
                continue

            # Calcula caminho relativo
            try:
                rel_path = file_path.relative_to(self.target_path).as_posix()
            except ValueError:
                rel_path = file_path.name

            # Determina o status da exposição
            status = self._evaluate_status(rel_path)
            file_size = file_path.stat().st_size if file_path.is_file() else 0

            # Monta a recomendação de remediação
            recommendation = self._build_recommendation(matching_rule, status, rel_path)

            findings.append(Finding(
                relative_path=rel_path,
                absolute_path=file_path,
                rule=matching_rule,
                status=status,
                size_bytes=file_size,
                recommendation=recommendation
            ))

        # Recomendações ausentes no .gitignore
        missing_recs = self.matcher.find_missing_recommendations(self.rules)

        duration_ms = (time.perf_counter() - start_time) * 1000

        return ScanReport(
            target_path=str(self.target_path),
            scanned_files_count=scanned_count,
            findings=findings,
            missing_recommendations=missing_recs,
            has_gitignore=self.matcher.has_gitignore,
            is_git_repo=self.is_git_repo,
            scan_duration_ms=round(duration_ms, 2),
            rules_applied_count=len(self.rules)
        )

    def _walk_files(self):
        """Gerador que percorre arquivos ignorando diretórios ruidosos ou excluídos."""
        for item in self.target_path.rglob("*"):
            # Pula pastas ignoradas por nome de parte ou correspondência de caminho
            try:
                rel = item.relative_to(self.target_path).as_posix()
            except ValueError:
                rel = item.name

            if any(part in self.ignored_dirs for part in item.parts):
                continue

            if any(rel == excl or rel.startswith(f"{excl}/") for excl in self.ignored_dirs):
                continue

            if item.is_file():
                yield item

    def _evaluate_status(self, rel_path: str) -> FindingStatus:
        """Determina se o arquivo está rastreado, exposto ou protegido."""
        normalized = rel_path.lower()
        if normalized in self.tracked_files:
            return FindingStatus.TRACKED

        if self.matcher.is_ignored(rel_path):
            return FindingStatus.PROTECTED

        return FindingStatus.UNIGNORED

    def _build_recommendation(self, rule: Rule, status: FindingStatus, rel_path: str) -> str:
        """Gera texto de remediação específico para a situação."""
        filename = rel_path.split("/")[-1]
        best_rec = rule.recommended_gitignore[0] if rule.recommended_gitignore else filename

        # Tenta encontrar a recomendação mais específica que casa com o arquivo
        import fnmatch
        for rec in rule.recommended_gitignore:
            if fnmatch.fnmatch(filename.lower(), rec.lower()):
                best_rec = rec
                break

        rec_patterns = ", ".join(f"`{p}`" for p in rule.recommended_gitignore)
        if status == FindingStatus.TRACKED:
            return (
                f"[URGENTE] Arquivo rastreado no Git! Remova do repositório: `git rm --cached {rel_path}`, "
                f"adicione {rec_patterns} ao `.gitignore`, faça commit e revogue as credenciais imediatamente."
            )
        elif status == FindingStatus.UNIGNORED:
            return (
                f"[AÇÃO NECESSÁRIA] Arquivo local sensível não ignorado. "
                f"Adicione a regra `{best_rec}` ao seu `.gitignore` para evitar vazamento acidental."
            )
        else:
            return "Arquivo protegido pelo .gitignore. Mantenha as regras ativas."
