"""
Módulo de Análise e Casamento de Regras do .gitignore.
Permite carregar arquivos .gitignore e verificar se um determinado
caminho relativo de arquivo é ignorado pelas regras do repositório.
"""

from pathlib import Path
from typing import Iterable, List, Optional, Set
import fnmatch

try:
    import pathspec
    HAS_PATHSPEC = True
except ImportError:
    HAS_PATHSPEC = False

from git_exposure.rules import Rule, get_default_rules


class GitignoreMatcher:
    """
    Gerenciador de regras .gitignore com suporte a padrões gitwildmatch
    e compatibilidade multiplataforma (Windows e POSIX).
    """

    def __init__(self, root_path: Path, gitignore_path: Optional[Path] = None):
        self.root_path = root_path.resolve()
        self.gitignore_path = (gitignore_path or (self.root_path / ".gitignore")).resolve()
        self.raw_rules: List[str] = []
        self._pathspec = None
        self.has_gitignore = self.gitignore_path.is_file()

        if self.has_gitignore:
            self._load_gitignore()

    def _load_gitignore(self) -> None:
        """Carrega e compila as regras do arquivo .gitignore."""
        try:
            with open(self.gitignore_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.read().splitlines()
        except OSError:
            lines = []

        self.raw_rules = [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]

        if HAS_PATHSPEC:
            try:
                self._pathspec = pathspec.PathSpec.from_lines("gitignore", lines)
            except Exception:
                self._pathspec = pathspec.PathSpec.from_lines("gitwildmatch", lines)

    def is_ignored(self, relative_path: str) -> bool:
        """
        Determina se um caminho relativo está ignorado pelo .gitignore.
        Normaliza os separadores para barras comuns ('/'), evitando bugs no Windows.
        """
        if not self.has_gitignore or not self.raw_rules:
            return False

        # Converte separadores de caminho do Windows para POSIX
        normalized = relative_path.replace("\\", "/").lstrip("/")

        if self._pathspec is not None:
            return bool(self._pathspec.match_file(normalized))

        # Fallback nativo caso pathspec não esteja disponível
        return self._fallback_match(normalized)

    def _fallback_match(self, normalized_path: str) -> bool:
        """Mecanismo simples de fallback usando fnmatch."""
        filename = normalized_path.split("/")[-1]
        for rule in self.raw_rules:
            clean = rule.rstrip("/")
            if clean.startswith("/"):
                clean = clean[1:]
            if fnmatch.fnmatch(normalized_path, clean) or fnmatch.fnmatch(filename, clean):
                return True
        return False

    def find_missing_recommendations(self, rules: Optional[Iterable[Rule]] = None) -> List[str]:
        """
        Analisa as regras sensíveis e retorna quais recomendações de .gitignore
        estão ausentes no arquivo analisado.
        """
        target_rules = rules if rules is not None else get_default_rules()
        missing: List[str] = []

        # Conjunto de regras já presentes (limpas)
        normalized_existing: Set[str] = {r.strip().lower() for r in self.raw_rules}

        for rule in target_rules:
            for rec in rule.recommended_gitignore:
                clean_rec = rec.strip()
                # Verifica se a recomendação ou algo equivalente já existe
                if clean_rec.lower() not in normalized_existing:
                    # Checagem adicional: se for *.key e tiver *.key no gitignore
                    matched = False
                    for existing in normalized_existing:
                        if existing == clean_rec.lower() or existing == f"/{clean_rec.lower()}":
                            matched = True
                            break
                    if not matched and clean_rec not in missing:
                        missing.append(clean_rec)

        return missing
