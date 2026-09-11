"""
Módulo de Regras e Assinaturas de Arquivos Sensíveis.
Define padrões conhecidos de arquivos que contêm credenciais, segredos,
chaves criptográficas ou dados locais que nunca devem ser expostos no Git.
"""

from dataclasses import dataclass, field
from enum import Enum
import fnmatch
from typing import List, Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Category(str, Enum):
    ENV = "Environment & Secrets"
    KEYS = "Private Keys & Certificates"
    CLOUD = "Cloud & API Credentials"
    DATABASE = "Databases & Backups"
    HISTORY = "Shell & System History"
    IAC = "Infrastructure as Code Secrets"
    LOGS = "Sensitive Logs & Core Dumps"


@dataclass
class Rule:
    rule_id: str
    name: str
    patterns: List[str]
    severity: Severity
    category: Category
    description: str
    recommended_gitignore: List[str]
    allow_patterns: List[str] = field(default_factory=list)

    def matches(self, filename: str) -> bool:
        """
        Verifica se o nome base do arquivo corresponde a algum padrão da regra,
        garantindo que exceções seguras (allow_patterns) sejam desconsideradas.
        """
        lower_name = filename.lower()

        # Verifica se corresponde a um padrão permitido/seguro (ex: .env.example)
        for allow_pat in self.allow_patterns:
            if fnmatch.fnmatch(lower_name, allow_pat.lower()):
                return False

        # Verifica se corresponde a algum padrão sensível
        for pat in self.patterns:
            if fnmatch.fnmatch(lower_name, pat.lower()):
                return True

        return False


def get_default_rules() -> List[Rule]:
    """Retorna a coleção padrão de regras de detecção de arquivos sensíveis."""
    return [
        Rule(
            rule_id="SEC-001",
            name="Environment Configuration with Secrets",
            patterns=[".env", ".env.*"],
            allow_patterns=[
                ".env.example", "*.env.example", ".env.sample", "*.env.sample",
                ".env.template", "*.env.template", ".env.dist", "*.env.dist"
            ],
            severity=Severity.CRITICAL,
            category=Category.ENV,
            description="Arquivos de ambiente frequentemente contêm chaves de API, tokens e senhas de banco de dados.",
            recommended_gitignore=[".env", ".env.*", "!.env.example"]
        ),
        Rule(
            rule_id="SEC-002",
            name="Cryptographic Private Keys & Certificates",
            patterns=[
                "*.pem", "*.key", "*.pkcs12", "*.pfx", "*.p12",
                "id_rsa", "id_rsa.*", "id_dsa", "id_dsa.*",
                "id_ed25519", "id_ed25519.*", "id_ecdsa", "id_ecdsa.*"
            ],
            allow_patterns=["*.pub", "*.pub.key", "known_hosts*"],
            severity=Severity.CRITICAL,
            category=Category.KEYS,
            description="Chaves privadas criptográficas e certificados digitais que permitem autenticação ou descriptografia não autorizada.",
            recommended_gitignore=["*.pem", "*.key", "*.pfx", "id_rsa*", "id_ed25519*"]
        ),
        Rule(
            rule_id="SEC-003",
            name="Cloud Provider & Service Account Credentials",
            patterns=[
                "credentials.json", "client_secret*.json", "service-account*.json",
                "service_account*.json", "*aws*credentials*", "*gcp*secret*.json"
            ],
            allow_patterns=["*.example.json", "*.template.json", "*.sample.json"],
            severity=Severity.CRITICAL,
            category=Category.CLOUD,
            description="Credenciais e contas de serviço de provedores em nuvem (GCP, AWS, Firebase).",
            recommended_gitignore=["credentials.json", "client_secret*.json", "service-account*.json"]
        ),
        Rule(
            rule_id="SEC-004",
            name="Local Databases & SQL Dumps",
            patterns=["*.sqlite", "*.sqlite3", "*.db", "dump.sql", "backup.sql", "*.rdb"],
            allow_patterns=["schema.sql", "init.sql"],
            severity=Severity.HIGH,
            category=Category.DATABASE,
            description="Bancos de dados locais ou cópias de segurança com registros reais ou informações confidenciais.",
            recommended_gitignore=["*.sqlite3", "*.db", "dump.sql", "backup.sql"]
        ),
        Rule(
            rule_id="SEC-005",
            name="Interactive Shell & Command History",
            patterns=[".bash_history", ".zsh_history", ".node_repl_history", ".python_history", ".sh_history"],
            severity=Severity.HIGH,
            category=Category.HISTORY,
            description="Históricos de comandos de terminal que frequentemente contêm comandos executados com tokens inline e senhas.",
            recommended_gitignore=[".bash_history", ".zsh_history", ".*_history"]
        ),
        Rule(
            rule_id="SEC-006",
            name="Infrastructure as Code Secret Variables",
            patterns=["*.tfvars", "terraform.tfstate", "terraform.tfstate.backup"],
            allow_patterns=["*.example.tfvars", "terraform.tfvars.example"],
            severity=Severity.HIGH,
            category=Category.IAC,
            description="Variáveis do Terraform ou arquivos de estado que mantêm segredos de provisionamento de infraestrutura.",
            recommended_gitignore=["*.tfvars", "*.tfstate*"]
        ),
        Rule(
            rule_id="SEC-007",
            name="Sensitive Debug Logs & Core Dumps",
            patterns=["npm-debug.log*", "yarn-error.log*", "core.*", "*.dump"],
            severity=Severity.MEDIUM,
            category=Category.LOGS,
            description="Arquivos de despejo de memória ou logs que podem conter trechos de dados confidenciais.",
            recommended_gitignore=["*.log", "core.*"]
        )
    ]


def find_matching_rule(filename: str, rules: Optional[List[Rule]] = None) -> Optional[Rule]:
    """Retorna a primeira regra que casa com o arquivo fornecido, ou None."""
    rules_list = rules if rules is not None else get_default_rules()
    for rule in rules_list:
        if rule.matches(filename):
            return rule
    return None
