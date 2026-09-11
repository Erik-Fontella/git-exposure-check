#!/usr/bin/env python3
"""
git-exposure-check
Ponto de entrada da CLI para auditoria de arquivos sensíveis e .gitignore.

Uso:
    python main.py [caminho] [opções]

Exemplos:
    python main.py
    python main.py tests/fixtures/test_repo
    python main.py . --format json --output audit.json
    python main.py . --fix-gitignore
"""

import argparse
from pathlib import Path
import sys

# Garante saída UTF-8 no terminal mesmo no Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


from git_exposure import __version__
from git_exposure.reporter import Reporter
from git_exposure.scanner import Scanner


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="git-exposure-check",
        description="Auditoria de Segurança: Detecta arquivos sensíveis expostos e valida cobertura de regras do .gitignore.",
        epilog="Exemplo de uso: python main.py tests/fixtures/test_repo --format cli"
    )

    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Caminho do repositório ou diretório a ser auditado (padrão: diretório atual)."
    )

    parser.add_argument(
        "--format",
        choices=["cli", "json", "markdown"],
        default="cli",
        help="Formato do relatório de saída (padrão: cli)."
    )

    parser.add_argument(
        "-o", "--output",
        help="Caminho do arquivo para salvar o relatório (opcional)."
    )

    parser.add_argument(
        "--strict",
        action="store_true",
        default=True,
        help="Retorna código de saída 1 se arquivos sensíveis desprotegidos forem encontrados (ativado por padrão)."
    )

    parser.add_argument(
        "--no-strict",
        dest="strict",
        action="store_false",
        help="Retorna código 0 mesmo se houver achados de segurança (útil para auditoria não bloqueante)."
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Modo detalhado: exibe também arquivos sensíveis que já estão protegidos pelo .gitignore."
    )

    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Diretório ou padrão relativo a ser desconsiderado na varredura (ex: --exclude tests/fixtures)."
    )

    parser.add_argument(
        "--fix-gitignore",
        action="store_true",
        help="Adiciona automaticamente as regras preventivas recomendadas ao final do arquivo .gitignore."
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}"
    )

    return parser.parse_args()


def handle_fix_gitignore(target_dir: Path, missing_rules: list) -> None:
    """Acrescenta as regras recomendadas ao .gitignore do projeto."""
    if not missing_rules:
        print("\nO .gitignore já cobre todas as recomendações de segurança essenciais!")
        return

    gitignore_path = target_dir / ".gitignore"
    header = "\n\n# --- Regras adicionadas pelo git-exposure-check ---\n"
    content_to_append = header + "\n".join(missing_rules) + "\n"

    try:
        mode = "a" if gitignore_path.exists() else "w"
        with open(gitignore_path, mode, encoding="utf-8") as f:
            f.write(content_to_append)
        print(f"\n[SUCESSO] {len(missing_rules)} regras de segurança foram adicionadas ao {gitignore_path.name}.")
    except OSError as e:
        print(f"\n[ERRO] Não foi possível atualizar o .gitignore: {e}", file=sys.stderr)


def main() -> int:
    args = parse_arguments()
    target_dir = Path(args.path).resolve()

    if not target_dir.exists():
        print(f"[ERRO] O caminho especificado não existe: {target_dir}", file=sys.stderr)
        return 2

    try:
        scanner = Scanner(target_dir, exclude_patterns=args.exclude)
        report = scanner.scan()
    except Exception as e:
        print(f"[ERRO FATAL] Falha durante a varredura: {e}", file=sys.stderr)
        return 2

    # Geração e exibição do relatório
    if args.format == "cli":
        Reporter.print_cli_report(report, verbose=args.verbose)
    elif args.format == "json":
        json_output = Reporter.to_json(report)
        if args.output:
            Path(args.output).write_text(json_output, encoding="utf-8")
            print(f"Relatório JSON salvo em: {args.output}")
        else:
            print(json_output)
    elif args.format == "markdown":
        md_output = Reporter.to_markdown(report)
        if args.output:
            Path(args.output).write_text(md_output, encoding="utf-8")
            print(f"Relatório Markdown salvo em: {args.output}")
        else:
            print(md_output)

    # Aplicação da correção automática se solicitada
    if args.fix_gitignore:
        handle_fix_gitignore(target_dir, report.missing_recommendations)

    # Código de saída
    if args.strict and report.total_unprotected_count > 0:
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
