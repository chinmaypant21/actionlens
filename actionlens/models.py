"""Pydantic data models for ActionLens normalized AST, rules, and findings."""

# Used Claude Opus 4.6 for brainstorming models architecture, cleaning the code and documenting it

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RuleCategory(str, Enum):
    LINT = "Linter"
    CODE_ANALYSIS = "Code Analysis"


class SourcePosition(BaseModel):
    line: int = 0
    col: int = 0


class Trigger(BaseModel):
    event: str
    types: list[str] = Field(default_factory=list)
    branches: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    paths: list[str] = Field(default_factory=list)


class PermissionsConfig(BaseModel):
    all: Optional[str] = None
    scopes: dict[str, str] = Field(default_factory=dict)
    pos: Optional[SourcePosition] = None


class RunnerConfig(BaseModel):
    labels: list[str] = Field(default_factory=list)
    group: Optional[str] = None
    pos: Optional[SourcePosition] = None


class ActionRef(BaseModel):
    raw: str
    owner: Optional[str] = None
    repo: Optional[str] = None
    ref: Optional[str] = None
    is_sha: bool = False


class ExpressionInfo(BaseModel):
    context: str
    location: Optional[str] = None


class StepAST(BaseModel):
    id: Optional[str] = None
    name: Optional[str] = None
    if_: Optional[str] = Field(default=None, alias="if")
    exec_type: str = "run"
    run: Optional[str] = None
    shell: Optional[str] = None
    uses: Optional[ActionRef] = None
    with_: dict[str, Any] = Field(default_factory=dict, alias="with")
    env: dict[str, str] = Field(default_factory=dict)
    expressions: list[ExpressionInfo] = Field(default_factory=list)
    pos: SourcePosition = Field(default_factory=SourcePosition)

    model_config = {"populate_by_name": True}


class JobAST(BaseModel):
    id: str
    name: Optional[str] = None
    runs_on: Optional[RunnerConfig] = None
    permissions: Optional[PermissionsConfig] = None
    needs: list[str] = Field(default_factory=list)
    if_: Optional[str] = Field(default=None, alias="if")
    env: dict[str, str] = Field(default_factory=dict)
    outputs: dict[str, str] = Field(default_factory=dict)
    steps: list[StepAST] = Field(default_factory=list)
    pos: SourcePosition = Field(default_factory=SourcePosition)

    model_config = {"populate_by_name": True}


class WorkflowAST(BaseModel):
    file_path: str = ""
    name: str = ""
    triggers: list[Trigger] = Field(default_factory=list)
    permissions: Optional[PermissionsConfig] = None
    env: dict[str, str] = Field(default_factory=dict)
    jobs: list[JobAST] = Field(default_factory=list)
    pos: SourcePosition = Field(default_factory=SourcePosition)


class Finding(BaseModel):
    """Standardized vulnerability finding format."""
    rule_id: str
    severity: Severity
    file_path: str
    line: int
    message: str
    remediation: str
    cwe: str
    owasp_cicd: str


class RuleMetadata(BaseModel):
    """Static, descriptive metadata for a rule. Defined centrally in actionlens.sast.rules.catalog."""
    rule_id: str
    name: str
    severity: Severity  # default severity; individual findings may override
    category: RuleCategory
    description: str
    cwe: str         # Common Weakness Enumeration
    owasp_cicd: str  # OWASP Top 10 CI/CD Security Risks category
    remediation: str

    model_config = {"frozen": True}


class Rule(ABC):
    """Abstract base class for all ActionLens detection rules.

    Subclasses set ``metadata`` (from the rule catalog) and implement ``check``.
    """
    metadata: RuleMetadata

    @property
    def rule_id(self) -> str:
        return self.metadata.rule_id

    @property
    def name(self) -> str:
        return self.metadata.name

    @property
    def severity(self) -> Severity:
        return self.metadata.severity

    @property
    def category(self) -> RuleCategory:
        return self.metadata.category

    @property
    def description(self) -> str:
        return self.metadata.description

    @property
    def cwe(self) -> str:
        return self.metadata.cwe

    @property
    def owasp_cicd(self) -> str:
        return self.metadata.owasp_cicd

    @property
    def remediation(self) -> str:
        return self.metadata.remediation

    @abstractmethod
    def check(self, ast: WorkflowAST) -> list[Finding]:
        """Inspect the normalized workflow AST and return findings."""
        raise NotImplementedError
