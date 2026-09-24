from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum

MODES = ("basic", "full", "paranoid")


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self):
        return self.name.lower()

    @classmethod
    def parse(cls, value):
        if isinstance(value, cls):
            return value
        name = str(value).strip().upper()
        name = {"MODERATE": "MEDIUM", "NEGLIGIBLE": "LOW", "UNKNOWN": "LOW", "INFO": "LOW"}.get(name, name)
        if name not in cls.__members__:
            raise ValueError(f"unknown severity '{value}' (use low, medium, high or critical)")
        return cls[name]


@dataclass(frozen=True)
class Rule:
    id: str
    severity: Severity
    level: str
    title: str
    fix: str

    def hit(self, detail=None, severity=None, line=None, fix=None, vuln_id=""):
        return Hit(self, detail or self.title, severity or self.severity, line, fix or self.fix, vuln_id)


@dataclass
class Hit:
    rule: Rule
    detail: str
    severity: Severity
    line: int | None = None
    fix: str = ""
    vuln_id: str = ""


@dataclass
class Target:
    kind: str
    name: str
    ref: str = ""
    image: str = ""
    file: str = ""
    line: int | None = None
    status: str = ""
    quiet: bool = False
    hits: list = field(default_factory=list)
    ignore: set = field(default_factory=set)
    line_ignores: dict = field(default_factory=dict)
    used_by: list = field(default_factory=list)

    def ignores(self, hit):
        return hit.rule.id in self.ignore or hit.rule.id in self.line_ignores.get(hit.line, ())


@dataclass
class Report:
    mode: str
    targets: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    meta: dict = field(default_factory=dict)
    ignored: int = 0
    min_severity: Severity = Severity.LOW

    def add(self, target):
        self.targets.append(target)
        return target

    def findings(self):
        for target in self.targets:
            for hit in target.hits:
                yield target, hit

    def counts(self):
        counts = {str(s): 0 for s in sorted(Severity, reverse=True)}
        for _, hit in self.findings():
            counts[str(hit.severity)] += 1
        return counts

    def worst(self):
        return max((hit.severity for _, hit in self.findings()), default=None)

    def apply_filters(self, ignore=(), min_severity=Severity.LOW):
        self.min_severity = min_severity
        depth = MODES.index(self.mode)
        for target in self.targets:
            kept = []
            for hit in target.hits:
                if MODES.index(hit.rule.level) > depth:
                    continue
                if hit.rule.id in ignore or (hit.vuln_id and hit.vuln_id in ignore) or target.ignores(hit):
                    self.ignored += 1
                    continue
                if hit.severity >= min_severity:
                    kept.append(hit)
            target.hits = kept
        self.targets = [t for t in self.targets if t.hits or not t.quiet]
