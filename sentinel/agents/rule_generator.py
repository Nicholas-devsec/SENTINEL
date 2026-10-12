from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from jinja2 import Environment, StrictUndefined

from sentinel.agents.base import BaseAgent
from sentinel.agents.scorer import ScoredIOC
from sentinel.config import SentinelSettings, get_settings


TEMPLATE_RE = re.compile(
    r"### (?P<name>[A-Za-z0-9_ ]+)\n```jinja\n(?P<body>.*?)\n```",
    re.DOTALL,
)
HASH_TYPES = {"md5", "sha1", "sha256"}
TYPE_CLASSES = {
    "ipv4": "ip",
    "ipv6": "ip",
    "domain": "domain",
    "url": "url",
    "md5": "hash",
    "sha1": "hash",
    "sha256": "hash",
}
KQL_HASH_FIELDS = {"md5": "MD5", "sha1": "SHA1", "sha256": "SHA256"}


@dataclass(slots=True)
class GeneratedArtifacts:
    value: str
    severity: str
    sigma_rule: str
    kql_query: str
    spl_query: str
    yara_rule: str | None
    files_written: list[str]


class RuleGeneratorAgent(BaseAgent):
    def __init__(
        self,
        skill_path: str = "skills/detection/SKILL.md",
        *,
        settings: SentinelSettings | None = None,
        output_dir: str = "generated/detections",
    ) -> None:
        super().__init__(skill_path)
        self.settings = settings or get_settings()
        self.output_dir = Path(output_dir)
        self._environment = Environment(undefined=StrictUndefined, trim_blocks=True, lstrip_blocks=True)

    def _parse_templates(self) -> dict[str, str]:
        templates = {match.group("name").strip().lower(): match.group("body") for match in TEMPLATE_RE.finditer(self.skill_prompt)}
        if not templates:
            raise ValueError("No detection templates found in skills/detection/SKILL.md")
        return templates

    def _slugify(self, value: str) -> str:
        return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")[:80] or "indicator"

    def _sigma_field_for_type(self, indicator_type: str) -> str:
        mapping = {
            "domain": "QueryName",
            "url": "c-uri",
            "ipv4": "DestinationIp",
            "ipv6": "DestinationIp",
            "md5": "Hashes",
            "sha1": "Hashes",
            "sha256": "Hashes",
        }
        return mapping.get(indicator_type, "DestinationHostname")

    def _spl_field_for_type(self, indicator_type: str) -> str:
        mapping = {
            "domain": "query",
            "url": "url",
            "ipv4": "dest_ip",
            "ipv6": "dest_ip",
            "md5": "file_hash",
            "sha1": "file_hash",
            "sha256": "file_hash",
        }
        return mapping.get(indicator_type, "indicator")

    def _render_template(self, template_body: str, context: dict[str, Any]) -> str:
        return self._environment.from_string(template_body).render(indicator=context).strip() + "\n"

    def _coerce_ioc(self, item: ScoredIOC | dict[str, Any]) -> dict[str, Any]:
        if isinstance(item, ScoredIOC):
            return asdict(item)
        return {
            "value": item["value"],
            "type": item["type"],
            "source": item["source"],
            "risk_score": float(item["risk_score"]),
            "severity": item["severity"],
            "mitre_techniques": list(item.get("mitre_techniques", [])),
            "mitre_tactics": list(item.get("mitre_tactics", [])),
        }

    def _build_context(self, ioc: dict[str, Any]) -> dict[str, Any]:
        ioc_type = ioc["type"]
        value = ioc["value"]
        return {
            **ioc,
            "slug": self._slugify(value),
            "type_class": TYPE_CLASSES.get(ioc_type, "domain"),
            "hash_algo": ioc_type if ioc_type in HASH_TYPES else None,
            "kql_hash_field": KQL_HASH_FIELDS.get(ioc_type),
            "sigma_field": self._sigma_field_for_type(ioc_type),
            "spl_field": self._spl_field_for_type(ioc_type),
        }

    def _select_template(self, templates: dict[str, str], platform: str, type_class: str) -> str:
        specific = templates.get(f"{platform}_{type_class}")
        if specific is not None:
            return specific
        return templates[platform]

    def _write_artifact(self, relative_path: str, content: str) -> str:
        target = self.output_dir / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return str(target)

    async def generate_for_ioc(self, item: ScoredIOC | dict[str, Any], templates: dict[str, str]) -> GeneratedArtifacts:
        ioc = self._coerce_ioc(item)
        context = self._build_context(ioc)
        type_class = context["type_class"]
        sigma_rule = self._render_template(self._select_template(templates, "sigma", type_class), context)
        kql_query = self._render_template(self._select_template(templates, "kql", type_class), context)
        spl_query = self._render_template(self._select_template(templates, "spl", type_class), context)
        yara_rule = (
            self._render_template(self._select_template(templates, "yara", type_class), context)
            if ioc["type"] in HASH_TYPES
            else None
        )

        files_written = [
            self._write_artifact(f"sigma/{context['slug']}.yml", sigma_rule),
            self._write_artifact(f"kql/{context['slug']}.kql", kql_query),
            self._write_artifact(f"spl/{context['slug']}.spl", spl_query),
        ]
        if yara_rule is not None:
            files_written.append(self._write_artifact(f"yara/{context['slug']}.yar", yara_rule))

        return GeneratedArtifacts(
            value=ioc["value"],
            severity=ioc["severity"],
            sigma_rule=sigma_rule,
            kql_query=kql_query,
            spl_query=spl_query,
            yara_rule=yara_rule,
            files_written=files_written,
        )

    async def run(self, scored_iocs: list[ScoredIOC | dict[str, Any]], *args: Any, **kwargs: Any) -> list[GeneratedArtifacts]:
        self.reload_skill()
        templates = self._parse_templates()
        eligible = [
            self._coerce_ioc(ioc)
            for ioc in scored_iocs
            if float(self._coerce_ioc(ioc)["risk_score"]) >= self.settings.thresholds.rule_score
        ]
        generated: list[GeneratedArtifacts] = []
        for item in eligible:
            artifacts = await self.generate_for_ioc(item, templates)
            generated.append(artifacts)
        return generated

    async def aclose(self) -> None:
        return None
