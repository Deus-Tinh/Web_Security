from dataclasses import dataclass, field


@dataclass(slots=True)
class DiscoveredForm:
    action: str
    method: str
    inputs: list[str] = field(default_factory=list)


@dataclass(slots=True)
class CrawlResult:
    pages: set[str] = field(default_factory=set)
    forms: list[DiscoveredForm] = field(default_factory=list)
    parameters: dict[str, list[str]] = field(default_factory=dict)
    login_pages: set[str] = field(default_factory=set)

