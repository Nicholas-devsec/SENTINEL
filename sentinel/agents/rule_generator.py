from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from git import Actor, InvalidGitRepositoryError, Repo
from jinja2 import Environment, StrictUndefined

from sentinel.agents.base import BaseAgent
from sentinel.agents.scorer import ScoredIOC
from sentinel.config import SentinelSettings, _is_missing_secret, get_settings
from sentinel.integrations.crowdstrike import CrowdStrikeClient


TEMPLATE_RE = re.compile(
    r"### (?P<name>[A-Za-z0-9_ ]+)\n```jinja\n(?P<body>.*?)\n```",
    re.DOTALL,
)
HASH_TYPES = {"md5", "sha1", "sha256"}
# CrowdStrike's IOC management API accepts these indicator types only.
CROWDSTRIKE_SUPPORTED_TYPES = {"domain", "ipv4", "ipv6", "md5", "sha256"}
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
    crowdstrike_payload: dict[str, Any] | None
    kql_query: str
    spl_query: str
    yara_rule: str | None
    files_written: list[str]
    crowdstrike_response: dict[str, Any] | None = None
    crowdstrike_skipped_reason: str | None = None


class RuleGeneratorAgent(BaseAgent):
    def __init__(
        self,
        skill_path: str = "skills/detection/SKILL.md",
        *,
        settings: SentinelSettings | None = None,
        crowdstrike_client: CrowdStrikeClient | None = None,
        output_dir: str = "generated/detections",
        repo_path: str | None = None,
    ) -> None:
        super().__init__(skill_path)
        self.settings = settings or get_settings()
        self.output_dir = Path(output_dir)
        self.repo_path = Path(repo_path) if repo_path is not None else Path.cwd()
        self._environment = Environment(undefined=StrictUndefined, trim_blocks=True, lstrip_blocks=True)
        self.crowdstrike_client = crowdstrike_client
        self._owns_crowdstrike_client = False
        if self.crowdstrike_client is None and self.settings.crowdstrike.enabled:
            if not _is_missing_secret(self.settings.crowdstrike.client_id) and not _is_missing_secret(self.settings.crowdstrike.client_secret):
                self.crowdstrike_client = CrowdStrikeClient(
                    client_id=self.settings.crowdstrike.client_id,
                    client_secret=self.settings.crowdstrike.client_secret,
                    base_url=self.settings.crowdstrike.base_url,
                )
                self._owns_crowdstrike_client = True

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

    def _crowdstrike_type_for(self, indicator_type: str) -> str | None:
        """CrowdStrike-supported IOC type, or None when the API cannot take it.

        URLs degrade to a domain indicator on the URL's hostname; sha1 has no
        Falcon IOC type at all.
        """
        if indicator_type == "url":
            return "domain"
        if indicator_type in CROWDSTRIKE_SUPPORTED_TYPES:
            return indicator_type
        return None

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
        from urllib.parse import urlparse

        ioc_type = ioc["type"]
        value = ioc["value"]
        hostname = value
        if ioc_type == "url":
            hostname = urlparse(value).hostname or value
        crowdstrike_type = self._crowdstrike_type_for(ioc_type)
        return {
            **ioc,
            "slug": self._slugify(value),
            "type_class": TYPE_CLASSES.get(ioc_type, "domain"),
            "hostname": hostname,
            "hash_algo": ioc_type if ioc_type in HASH_TYPES else None,
            "kql_hash_field": KQL_HASH_FIELDS.get(ioc_type),
            "sigma_field": self._sigma_field_for_type(ioc_type),
            "spl_field": self._spl_field_for_type(ioc_type),
            "crowdstrike_type": crowdstrike_type,
            "crowdstrike_value": hostname if ioc_type == "url" else value,
        }

    def _select_template(self, templates: dict[str, str], platform: str, type_class: str) -> str:
        specific = templates.get(f"{platform}_{type_class}")
        if specific is not None:
            return specific
        return templates[platform]

    async def _push_crowdstrike(self, payload: dict[str, Any]) -> dict[str, Any] | None:
        if self.crowdstrike_client is None:
            return None
        try:
            return await self.crowdstrike_client.push_ioc(payload)
        except Exception as exc:
            self.logger.exception("Failed to push IOC to CrowdStrike", exc_info=exc)
            return None

    def _write_artifact(self, relative_path: str, content: str) -> str:
        target = self.output_dir / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return str(target)

    def _commit_artifacts(self, files_written: list[str]) -> None:
        try:
            repo = Repo(self.repo_path, search_parent_directories=True)
        except InvalidGitRepositoryError:
            self.logger.warning("Skipping git commit because %s is not inside a git repository", self.repo_path)
            return
        relative_files = [str(Path(file).resolve().relative_to(Path(repo.working_tree_dir).resolve())) for file in files_written]
        repo.index.add(relative_files)
        actor = Actor(self.settings.git.author_name, self.settings.git.author_email)
        message = f"rules: {datetime.now(UTC).date().isoformat()} generated {len(files_written)} detection artifacts"
        repo.index.commit(message, author=actor, committer=actor)

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

        crowdstrike_payload: dict[str, Any] | None = None
        crowdstrike_skipped_reason: str | None = None
        if context["crowdstrike_type"] is not None:
            crowdstrike_payload = json.loads(
                self._render_template(self._select_template(templates, "crowdstrike", type_class), context)
            )
        else:
            crowdstrike_skipped_reason = (
                f"CrowdStrike IOC API does not support indicator type '{ioc['type']}'"
            )

        files_written = [
            self._write_artifact(f"sigma/{context['slug']}.yml", sigma_rule),
            self._write_artifact(f"kql/{context['slug']}.kql", kql_query),
            self._write_artifact(f"spl/{context['slug']}.spl", spl_query),
        ]
        if crowdstrike_payload is not None:
            files_written.append(
                self._write_artifact(
                    f"crowdstrike/{context['slug']}.json",
                    json.dumps(crowdstrike_payload, indent=2, sort_keys=True) + "\n",
                )
            )
        if yara_rule is not None:
            files_written.append(self._write_artifact(f"yara/{context['slug']}.yar", yara_rule))

        crowdstrike_response = (
            await self._push_crowdstrike(crowdstrike_payload) if crowdstrike_payload is not None else None
        )
        return GeneratedArtifacts(
            value=ioc["value"],
            severity=ioc["severity"],
            sigma_rule=sigma_rule,
            crowdstrike_payload=crowdstrike_payload,
            kql_query=kql_query,
            spl_query=spl_query,
            yara_rule=yara_rule,
            files_written=files_written,
            crowdstrike_response=crowdstrike_response,
            crowdstrike_skipped_reason=crowdstrike_skipped_reason,
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
        all_files: list[str] = []
        for item in eligible:
            artifacts = await self.generate_for_ioc(item, templates)
            generated.append(artifacts)
            all_files.extend(artifacts.files_written)
        if all_files:
            self._commit_artifacts(all_files)
        return generated

    async def aclose(self) -> None:
        if self._owns_crowdstrike_client:
            await self.crowdstrike_client.aclose()
