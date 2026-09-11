# git-exposure-check

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/Tests-32%20passed-success.svg)](tests/)
[![SBSeg Artifacts](https://img.shields.io/badge/SBSeg%202026-Artifact%20Compliant-orange.svg)](https://doc-artefatos.github.io/sbseg2026/)

> **Validador Estático de Arquivos Sensíveis e Análise de Cobertura de Regras do `.gitignore` para Prevenção de Vazamento de Segredos.**

---

## 1. Descrição do Problema e Motivação

O vazamento acidental de credenciais e arquivos de configuração em sistemas de controle de versão (como o Git) representa um dos incidentes de cibersegurança mais recorrentes e críticos em ambientes modernos de desenvolvimento de software (DevSecOps). Chaves privadas SSH/TLS (`*.pem`, `*.key`, `id_rsa`), credenciais de acesso a provedores em nuvem (`credentials.json`, `service-account.json`), arquivos de variáveis de ambiente com senhas em texto puro (`.env`), bancos de dados locais (`*.sqlite3`) e arquivos de histórico de shell frequentemente são comitados inadvertidamente por desenvolvedores ao utilizarem comandos globais como `git add .` ou `git commit -a`.

Embora o arquivo `.gitignore` seja o mecanismo padrão para evitar que arquivos locais sejam rastreados pelo Git, projetos frequentemente:
1. **Não possuem `.gitignore` configurado** no início do desenvolvimento;
2. **Possuem regras incompletas ou sintaticamente imprecisas**, deixando brechas para inclusão de extensões perigosas;
3. **Mantêm segredos físicos já rastreados no índice Git**, onde a simples adição ao `.gitignore` posterior não remove os arquivos já versionados no histórico.

Esse cenário se enquadra na fraqueza de segurança catalogada pela MITRE como **CWE-200: Exposure of Sensitive Information to an Unauthorized Actor** e no **OWASP Top 10: Security Misconfiguration / Cryptographic Failures**.

---

## 2. Objetivo do Artefato

O **`git-exposure-check`** é uma ferramenta de linha de comando (CLI) modular em Python desenvolvida para mitigar esse problema através de uma abordagem preventiva e proativa. A ferramenta audita repositórios locais para:
- Detectar a presença física de arquivos e extensões sensíveis no diretório de trabalho;
- Avaliar cruzadamente se tais arquivos estão devidamente cobertos pelas diretivas do `.gitignore`;
- Identificar arquivos sensíveis que já foram indexados ou comitados no Git (`git ls-files`);
- Emitir recomendações preventivas de regras para blindagem do repositório;
- Possibilitar aplicação de correção automática (`--fix-gitignore`) e relatórios legíveis por humanos e máquinas (JSON/Markdown) para integração contínua (CI/CD).

---

## 3. Principais Funcionalidades

- **Varredura Estática de Padrões Sensíveis:** Catálogo modular de regras cobrindo chaves criptográficas, arquivos de ambiente, credenciais em nuvem, bancos locais, variáveis IaC e históricos de shell.
- **Tolerância a Falsos Positivos:** Suporte a listas de permissão segura (ex.: `.env.example`, `.env.sample`, `*.pub`, `schema.sql` são reconhecidos como legítimos e não geram alertas).
- **Classificação Tríplice de Severidade e Status:**
  - `TRACKED_IN_GIT` (**CRÍTICO**): Arquivo sensível já comitado ou adicionado ao índice Git.
  - `EXPOSED_UNIGNORED` (**ALTO**): Arquivo sensível presente fisicamente no disco e ausente no `.gitignore` (risco iminente de commit acidental).
  - `IGNORED_PROTECTED` (**INFORMATIVO/SEGURO**): Arquivo sensível presente no disco, porém devidamente blindado pelas regras do `.gitignore`.
- **Análise Preditiva de Regras Ausentes:** Aponta quais padrões defensivos essenciais estão faltando no `.gitignore`, mesmo antes de o desenvolvedor criar o arquivo sensível.
- **Correção Automática (`--fix-gitignore`):** Concatena de forma idempotente as regras ausentes diretamente no arquivo `.gitignore` do projeto.
- **Múltiplos Formatos de Saída:** Terminal interativo com cores ANSI, exportação estruturada em **JSON** e relatórios executivos em **Markdown**.
- **Exit Codes Padronizados para CI/CD:** Retorna código `0` em caso de conformidade e código `1` na detecção de exposições desprotegidas (compatível com GitHub Actions, pre-commit e GitLab CI).
- **Filtro de Exclusão Customizada (`--exclude`):** Permite desconsiderar pastas de mock, fixtures ou subdiretórios de testes.

---

## 4. Estrutura do Repositório

```text
Atividade_3/
├── git_exposure/                 # Pacote principal do artefato
│   ├── __init__.py               # Metadados e versão do pacote
│   ├── rules.py                  # Banco de assinaturas de segredos e severidades
│   ├── matcher.py                # Mecanismo de parsing do .gitignore e matching
│   ├── scanner.py                # Varredura do sistema de arquivos e cruzamento de regras
│   └── reporter.py               # Formatadores de saída (Terminal, JSON e Markdown)
├── tests/                        # Suíte de testes automatizados
│   ├── __init__.py
│   ├── test_rules.py             # Testes das regras e de falsos positivos
│   ├── test_matcher.py           # Testes do motor de avaliação de .gitignore
│   ├── test_scanner.py           # Testes de integração e exclusões customizadas
│   └── fixtures/                 # Repositório de teste vulnerável para reprodutibilidade
│       └── test_repo/
│           ├── .env              # Arquivo vulnerável exposto (simulação)
│           ├── .env.example      # Arquivo de exemplo seguro
│           ├── server.key        # Chave privada vulnerável exposta (simulação)
│           ├── app.sqlite3       # Banco de dados vulnerável exposto (simulação)
│           ├── debug.log         # Arquivo ignorado pelo .gitignore
│           ├── main.py           # Código de aplicação legítimo
│           └── .gitignore        # Regras parciais de exclusão
├── main.py                       # Interface CLI executável (ponto de entrada)
├── requirements.txt              # Especificação de dependências do Python
├── LICENSE                       # Licença de código aberto (MIT)
└── README.md                     # Documentação científica do artefato
```

---

## 5. Dependências e Requisitos de Execução

### Requisitos de Sistema
- **Sistema Operacional:** Linux, macOS ou Microsoft Windows (10/11);
- **Python:** Versão `3.9` ou superior (testado e validado em Python `3.14`);
- **Git:** Instalado e disponível no `PATH` (opcional, utilizado para checagem de arquivos comitados).

### Dependências Externas (`requirements.txt`)
- `pathspec>=0.11.0`: Implementação da especificação de padrões do Git (`gitwildmatch`/`gitignore`);
- `colorama>=0.4.6`: Compatibilidade multiplataforma para terminal com cores ANSI;
- `pytest>=7.0.0`: Framework para execução da suíte de testes unitários e de integração.

---

## 6. Instruções de Instalação

Recomenda-se a utilização de um ambiente virtual (`venv`):

### No Linux / macOS:
```bash
# 1. Clonar o repositório
git clone <https://github.com/Erik-Fontella/git-exposure-check>
cd <git-exposure-check>

# 2. Criar e ativar o ambiente virtual
python3 -m venv .venv
source .venv/bin/activate

# 3. Instalar as dependências
pip install -r requirements.txt
```

### No Microsoft Windows (PowerShell):
```powershell
# 1. Clonar o repositório
git clone <https://github.com/Erik-Fontella/git-exposure-check>
cd <git-exposure-check>

# 2. Criar e ativar o ambiente virtual
python -m venv .venv
.venv\Scripts\Activate.ps1

# 3. Instalar as dependências
python -m pip install -r requirements.txt
```

---

## 7. Instruções de Execução e Exemplos

A ferramenta é invocada através de `python main.py [caminho] [opções]`.

### Opções Disponíveis:
| Parâmetro | Tipo | Descrição |
| :--- | :--- | :--- |
| `path` | Posicional | Diretório ou repositório a auditar (padrão: diretório atual `.`) |
| `--format` | Opção | Formato de saída: `cli` (padrão), `json` ou `markdown` |
| `-o`, `--output` | Opção | Caminho para gravar o relatório gerado em arquivo |
| `--strict` / `--no-strict` | Flag | Se ativado (padrão), retorna código 1 ao detectar achados não protegidos |
| `-v`, `--verbose` | Flag | Exibe também os arquivos sensíveis que já se encontram protegidos |
| `--exclude` | Opção | Desconsidera diretórios adicionais da varredura (ex: `--exclude tests/fixtures`) |
| `--fix-gitignore` | Flag | Acrescenta automaticamente as regras ausentes ao `.gitignore` do alvo |
| `--version` | Flag | Exibe a versão instalada da ferramenta |

---

## 8. Cenário de Validação e Reprodutibilidade (Guia Passo a Passo)

Para validar a ferramenta de forma rápida e reprodutível, o repositório acompanha um diretório sintético vulnerável preparado em `tests/fixtures/test_repo`.

### 1. Auditoria no terminal interativo:
```bash
python main.py tests/fixtures/test_repo
```
**Resultado Esperado:**
- Detecção imediata de 3 exposições críticas/altas desprotegidas: `.env`, `server.key` e `app.sqlite3`;
- Ausência de falsos positivos: `.env.example` e `main.py` não são marcados;
- O arquivo `debug.log` é reconhecido como seguro/ignorado;
- Apresentação de recomendações preventivas para o `.gitignore`;
- Código de saída `1` (indicando falha de segurança para automações).

### 2. Exportação de Relatório Estruturado em JSON (para CI/CD):
```bash
python main.py tests/fixtures/test_repo --format json -o relatorio.json --no-strict
```
Gera um arquivo `relatorio.json` padronizado contendo carimbo de data/hora, lista detalhada de achados e contadores de status.

### 3. Exportação de Relatório em Markdown (para Auditoria e Documentação):
```bash
python main.py tests/fixtures/test_repo --format markdown -o auditoria.md --no-strict
```

### 4. Aplicação de Correção Automática no `.gitignore`:
```bash
python main.py tests/fixtures/test_repo --fix-gitignore --no-strict
```
O arquivo `.gitignore` do repositório alvo é automaticamente enriquecido com as regras defensivas faltantes.

---

## 9. Execução dos Testes Automatizados

O projeto conta com uma suíte de testes com cobertura completa das regras, análise sintática do `.gitignore` e integração de varredura.

Para executar os testes:
```bash
python -m pytest -p no:cacheprovider -v tests/
```
**Saída esperada:**
```text
============================= test session starts =============================
collected 32 items

tests/test_matcher.py::test_matcher_without_gitignore PASSED             [  3%]
tests/test_matcher.py::test_matcher_with_gitignore PASSED                [  6%]
tests/test_matcher.py::test_matcher_missing_recommendations PASSED       [  9%]
tests/test_rules.py::test_default_rules_exist PASSED                     [ 12%]
tests/test_rules.py::test_sensitive_files_match[...] PASSED              [ 56%]
tests/test_rules.py::test_safe_files_do_not_trigger_false_positives[...] PASSED [ 90%]
tests/test_scanner.py::test_scanner_detects_unignored_sensitive_files PASSED [ 93%]
tests/test_scanner.py::test_scanner_recognizes_protected_files PASSED    [ 96%]
tests/test_scanner.py::test_scanner_custom_exclude PASSED                [100%]

============================= 32 passed in 0.16s ==============================
```

---

## 10. Avaliação do Artefato segundo Critérios Científicos (SBSeg)

| Critério | Atendimento no Artefato |
| :--- | :--- |
| **Disponibilidade** | Repositório público no GitHub com documentação aberta, estrutura padronizada e licença permissiva de código aberto (MIT). |
| **Funcionalidade** | Ferramenta completamente executável, com CLI interativa, exportações JSON e Markdown, código de saída semântico e mecanismo de correção automática do `.gitignore`. |
| **Sustentabilidade** | Código modular com separação clara de responsabilidades (`rules`, `matcher`, `scanner`, `reporter`), tipagem estática (type hints), documentação em docstrings e dependências mínimas explicitadas em `requirements.txt`. |
| **Reprodutibilidade** | Instruções de instalação detalhadas para múltiplos sistemas operacionais, ambiente virtual isolado, suíte automatizada com 32 testes unitários e fixture de dados sintéticos (`tests/fixtures/test_repo`) pronta para execução imediata. |

---

## 11. Limitações Conhecidas

- **Análise Baseada em Nomes e Extensões:** A versão atual analisa padrões de arquivos e diretivas de ignore. Não realiza inspeção profunda de conteúdo (DLP - *Data Loss Prevention* ou cálculo de entropia de Shannon dentro de arquivos de código-fonte).
- **Histórico Pretérito do Git:** Para repositórios onde um segredo já foi commitado e posteriormente deletado em commits seguintes, a ferramenta aponta arquivos presentes no estado atual (`HEAD` / *working tree*), não realizando a varredura retrospectiva em commits antigos (função delegada a ferramentas complementares como `git-filter-repo` ou `trufflehog`).

---

## 12. Licença

Este projeto é distribuído sob os termos da licença **MIT**. Consulte o arquivo [LICENSE](LICENSE) para obter mais detalhes.

---

## 13. Referências

1. **SBSeg (2026):** *Diretrizes para Avaliação de Artefatos Científicos*. Disponível em: [https://doc-artefatos.github.io/sbseg2026/](https://doc-artefatos.github.io/sbseg2026/)
2. **The MITRE Corporation:** *CWE-200: Exposure of Sensitive Information to an Unauthorized Actor*. Common Weakness Enumeration.
3. **OWASP Foundation:** *OWASP Top 10: Security Misconfiguration*.
4. **Git Documentation:** *gitignore - Specifies intentionally untracked files to ignore*. Disponível em: [https://git-scm.com/docs/gitignore](https://git-scm.com/docs/gitignore)
5. **PathSpec Documentation:** *Utility library for pattern matching of file paths based on gitwildmatch*.
