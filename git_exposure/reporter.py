"""
Módulo Formatador e Gerador de Relatórios (CLI, JSON e Markdown).
Apresenta visualmente os achados no terminal com suporte a cores e
gera relatórios estruturados para auditoria e automação em CI/CD.
"""

import json
from datetime import datetime, timezone
from typing import Optional

try:
    import colorama
    colorama.init(autoreset=True)
    GREEN = colorama.Fore.GREEN
    RED = colorama.Fore.RED
    YELLOW = colorama.Fore.YELLOW
    CYAN = colorama.Fore.CYAN
    MAGENTA = colorama.Fore.MAGENTA
    BOLD = colorama.Style.BRIGHT
    RESET = colorama.Style.RESET_ALL
except ImportError:
    GREEN = RED = YELLOW = CYAN = MAGENTA = BOLD = RESET = ""

from git_exposure.scanner import FindingStatus, ScanReport


class Reporter:
    """Gerador de relatórios para o git-exposure-check."""

    @staticmethod
    def print_cli_report(report: ScanReport, verbose: bool = False) -> None:
        """Exibe o relatório formatado no terminal com cores."""
        print(f"\n{BOLD}{CYAN}=============================================================={RESET}")
        print(f"{BOLD}{CYAN}       git-exposure-check :: Auditoria de Segurança Git       {RESET}")
        print(f"{BOLD}{CYAN}=============================================================={RESET}\n")

        print(f"{BOLD}Diretório analisado:{RESET} {report.target_path}")
        print(f"{BOLD}Arquivos varridos:{RESET}   {report.scanned_files_count}")
        print(f"{BOLD}Regras aplicadas:{RESET}    {report.rules_applied_count}")
        print(f"{BOLD}Tempo de varredura:{RESET}  {report.scan_duration_ms} ms")
        print(f"{BOLD}Arquivo .gitignore:{RESET}  {'Presente' if report.has_gitignore else RED + 'NÃO ENCONTRADO' + RESET}")
        print(f"{BOLD}Repositório Git:{RESET}     {'Detectado' if report.is_git_repo else 'Pasta local simples'}\n")

        # Exibição dos achados
        if not report.findings:
            print(f"{GREEN}[OK] Nenhum arquivo sensível ou credencial foi encontrado no diretório.{RESET}\n")
        else:
            print(f"{BOLD}--- Arquivos Sensíveis Identificados ({len(report.findings)}) ---{RESET}\n")
            for idx, finding in enumerate(report.findings, start=1):
                if finding.status == FindingStatus.TRACKED:
                    status_badge = f"{RED}{BOLD}[CRÍTICO - RASTREADO NO GIT]{RESET}"
                elif finding.status == FindingStatus.UNIGNORED:
                    status_badge = f"{YELLOW}{BOLD}[ALERTA - NÃO IGNORADO]{RESET}"
                else:
                    if not verbose:
                        continue  # Oculta itens protegidos no modo padrão para não poluir
                    status_badge = f"{GREEN}[PROTEGIDO PELO .GITIGNORE]{RESET}"

                print(f"{idx}. {status_badge} {BOLD}{finding.relative_path}{RESET}")
                print(f"   Categoria: {finding.rule.category.value} | Severidade: {finding.rule.severity.value}")
                print(f"   Descrição: {finding.rule.description}")
                print(f"   Tamanho:   {finding.size_bytes} bytes")
                print(f"   Ação:      {finding.recommendation}\n")

        # Exibição de recomendações preventivas para o .gitignore
        if report.missing_recommendations:
            print(f"{BOLD}--- Recomendações Preventivas para o .gitignore ---{RESET}")
            print(f"{YELLOW}As seguintes regras de segurança estão ausentes no seu .gitignore:{RESET}")
            for rec in report.missing_recommendations[:10]:
                print(f"  + {rec}")
            if len(report.missing_recommendations) > 10:
                print(f"  ... e mais {len(report.missing_recommendations) - 10} padrões recomendados.")
            print()

        # Resumo final
        print(f"{BOLD}{CYAN}-------------------------- Resumo ----------------------------{RESET}")
        print(f"Rastreados no Git (Comitados): {RED if report.status_counts[FindingStatus.TRACKED.value] > 0 else GREEN}{report.status_counts[FindingStatus.TRACKED.value]}{RESET}")
        print(f"Expostos no disco (Sem ignore): {RED if report.status_counts[FindingStatus.UNIGNORED.value] > 0 else GREEN}{report.status_counts[FindingStatus.UNIGNORED.value]}{RESET}")
        print(f"Protegidos pelo .gitignore:     {GREEN}{report.status_counts[FindingStatus.PROTECTED.value]}{RESET}")
        print(f"{BOLD}{CYAN}--------------------------------------------------------------{RESET}")

        if report.total_unprotected_count > 0:
            print(f"\n{RED}{BOLD}[FALHA] Foram encontrados {report.total_unprotected_count} arquivo(s) sensíveis expostos ou rastreados!{RESET}")
            print(f"{RED}Corrija os problemas apontados antes de efetuar commits ou publicar seu código.{RESET}\n")
        else:
            print(f"\n{GREEN}{BOLD}[SUCESSO] Auditoria concluída. Repositório seguro contra exposição acidental de segredos.{RESET}\n")

    @staticmethod
    def to_json(report: ScanReport) -> str:
        """Converte o relatório para formato JSON estruturado."""
        data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target_path": report.target_path,
            "has_gitignore": report.has_gitignore,
            "is_git_repo": report.is_git_repo,
            "scanned_files_count": report.scanned_files_count,
            "scan_duration_ms": report.scan_duration_ms,
            "total_unprotected_count": report.total_unprotected_count,
            "status_counts": report.status_counts,
            "passed": report.total_unprotected_count == 0,
            "findings": [
                {
                    "file": f.relative_path,
                    "status": f.status.value,
                    "severity": f.rule.severity.value,
                    "category": f.rule.category.value,
                    "rule_id": f.rule.rule_id,
                    "rule_name": f.rule.name,
                    "size_bytes": f.size_bytes,
                    "recommendation": f.recommendation,
                }
                for f in report.findings
            ],
            "missing_recommendations": report.missing_recommendations
        }
        return json.dumps(data, indent=2, ensure_ascii=False)

    @staticmethod
    def to_markdown(report: ScanReport) -> str:
        """Gera um relatório completo em formato Markdown."""
        lines = [
            "# Relatório de Auditoria de Exposição de Arquivos Git",
            f"**Data da Auditoria:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
            f"**Diretório Alvo:** `{report.target_path}`  ",
            f"**Status da Auditoria:** {'✅ APROVADO' if report.total_unprotected_count == 0 else '❌ FALHA (Riscos Detectados)'}",
            "",
            "## 1. Visão Geral da Execução",
            "| Métrica | Valor |",
            "| :--- | :--- |",
            f"| Total de Arquivos Varridos | {report.scanned_files_count} |",
            f"| Tempo de Execução | {report.scan_duration_ms} ms |",
            f"| Presença de `.gitignore` | {'Sim' if report.has_gitignore else 'Não'} |",
            f"| Repositório Git | {'Sim' if report.is_git_repo else 'Não'} |",
            f"| Arquivos Rastreados no Git | **{report.status_counts[FindingStatus.TRACKED.value]}** |",
            f"| Arquivos Expostos Desprotegidos | **{report.status_counts[FindingStatus.UNIGNORED.value]}** |",
            f"| Arquivos Protegidos por Ignore | {report.status_counts[FindingStatus.PROTECTED.value]} |",
            ""
        ]

        lines.extend([
            "## 2. Achados de Segurança (Findings)",
            ""
        ])

        if not report.findings:
            lines.append("Nenhum arquivo sensível detectado.")
        else:
            lines.extend([
                "| Arquivo | Severidade | Status | Categoria | Ação Recomendada |",
                "| :--- | :--- | :--- | :--- | :--- |"
            ])
            for f in report.findings:
                lines.append(
                    f"| `{f.relative_path}` | **{f.rule.severity.value}** | `{f.status.value}` | "
                    f"{f.rule.category.value} | {f.recommendation} |"
                )

        if report.missing_recommendations:
            lines.extend([
                "",
                "## 3. Recomendações Preventivas para o `.gitignore`",
                "As seguintes regras deveriam constar no `.gitignore` para prevenir inclusões futuras:",
                ""
            ])
            for rec in report.missing_recommendations:
                lines.append(f"- `{rec}`")

        lines.extend([
            "",
            "---",
            "*Gerado automaticamente por git-exposure-check.*"
        ])

        return "\n".join(lines)
