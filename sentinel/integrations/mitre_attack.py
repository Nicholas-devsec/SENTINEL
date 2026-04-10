from __future__ import annotations

import json
import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mitreattack.stix20 import MitreAttackData


TOKEN_RE = re.compile(r"[a-z0-9]{2,}")


@dataclass(slots=True)
class TechniqueEntry:
    attack_id: str
    stix_id: str
    name: str
    description: str
    tactics: list[str]
    document: str


@dataclass(slots=True)
class TechniqueMatch:
    attack_id: str
    name: str
    tactics: list[str]
    score: float


class MitreAttackRepository:
    """Loads MITRE ATT&CK techniques and serves TF-IDF similarity queries."""

    def __init__(
        self,
        *,
        stix_path: str | Path | None = None,
        attack_data: MitreAttackData | None = None,
        techniques: list[TechniqueEntry] | None = None,
    ) -> None:
        self.stix_path = Path(stix_path) if stix_path is not None else None
        self.attack_data = attack_data
        self.techniques = techniques or self._load_techniques()
        self._idf, self._vectors = self._build_index(self.techniques)

    def _load_techniques(self) -> list[TechniqueEntry]:
        if self.attack_data is None and self.stix_path is None:
            # Assumption: runtime provides a local ATT&CK enterprise STIX bundle path when not injecting test data.
            raise ValueError("A local MITRE ATT&CK STIX path or preloaded attack_data is required.")

        if self.stix_path is not None:
            parsed = self._load_from_stix_bundle(self.stix_path)
            if parsed:
                return parsed

        attack_data = self.attack_data or MitreAttackData(str(self.stix_path))
        techniques = attack_data.get_techniques(include_subtechniques=True, remove_revoked_deprecated=True)
        entries: list[TechniqueEntry] = []
        for technique in techniques:
            attack_id = self._extract_attack_id(technique)
            tactics = self._extract_tactics(attack_data, technique)
            description = getattr(technique, "description", "") or ""
            name = getattr(technique, "name", "") or attack_id
            document = f"{name}\n{description}\n{' '.join(tactics)}"
            entries.append(
                TechniqueEntry(
                    attack_id=attack_id,
                    stix_id=getattr(technique, "id", attack_id),
                    name=name,
                    description=description,
                    tactics=tactics,
                    document=document,
                )
            )
        return entries

    def _load_from_stix_bundle(self, stix_path: Path) -> list[TechniqueEntry]:
        payload = json.loads(stix_path.read_text(encoding="utf-8"))
        objects = payload.get("objects", [])
        if not isinstance(objects, list):
            return []
        techniques = [
            obj
            for obj in objects
            if isinstance(obj, dict)
            and obj.get("type") == "attack-pattern"
            and not obj.get("revoked", False)
            and not obj.get("x_mitre_deprecated", False)
        ]
        entries: list[TechniqueEntry] = []
        for technique in techniques:
            attack_id = self._extract_attack_id_from_dict(technique)
            if attack_id is None:
                continue
            name = str(technique.get("name", attack_id))
            description = str(technique.get("description", "") or "")
            tactics = [
                str(phase.get("phase_name", "")).replace("-", " ")
                for phase in technique.get("kill_chain_phases", [])
                if isinstance(phase, dict) and phase.get("phase_name")
            ]
            document = f"{name}\n{description}\n{' '.join(tactics)}"
            entries.append(
                TechniqueEntry(
                    attack_id=attack_id,
                    stix_id=str(technique.get("id", attack_id)),
                    name=name,
                    description=description,
                    tactics=tactics,
                    document=document,
                )
            )
        return entries

    def _extract_attack_id(self, technique: Any) -> str:
        for ref in getattr(technique, "external_references", []) or []:
            source_name = (ref.get("source_name") or "").lower()
            external_id = ref.get("external_id")
            if source_name.startswith("mitre-attack") and external_id:
                return external_id
        return getattr(technique, "id", "unknown-technique")

    def _extract_attack_id_from_dict(self, technique: dict[str, Any]) -> str | None:
        for ref in technique.get("external_references", []) or []:
            if not isinstance(ref, dict):
                continue
            source_name = str(ref.get("source_name", "")).lower()
            external_id = ref.get("external_id")
            if source_name.startswith("mitre-attack") and external_id:
                return str(external_id)
        return None

    def _extract_tactics(self, attack_data: MitreAttackData, technique: Any) -> list[str]:
        tactic_names = [
            phase.get("phase_name", "").replace("-", " ")
            for phase in getattr(technique, "kill_chain_phases", []) or []
            if phase.get("phase_name")
        ]
        if tactic_names:
            return tactic_names
        try:
            tactics = attack_data.get_tactics_by_technique(technique.id)
        except Exception:
            return []
        return [getattr(tactic, "name", "").replace("-", " ") for tactic in tactics if getattr(tactic, "name", None)]

    def _tokenize(self, text: str) -> list[str]:
        return TOKEN_RE.findall(text.lower())

    def _build_index(self, techniques: list[TechniqueEntry]) -> tuple[dict[str, float], list[dict[str, float]]]:
        doc_freq: Counter[str] = Counter()
        tokenized_docs: list[list[str]] = []
        for entry in techniques:
            tokens = self._tokenize(entry.document)
            tokenized_docs.append(tokens)
            doc_freq.update(set(tokens))
        total_docs = max(len(techniques), 1)
        idf = {token: math.log((1 + total_docs) / (1 + freq)) + 1 for token, freq in doc_freq.items()}
        vectors = [self._tfidf(tokens, idf) for tokens in tokenized_docs]
        return idf, vectors

    def _tfidf(self, tokens: list[str], idf: dict[str, float]) -> dict[str, float]:
        if not tokens:
            return {}
        counts = Counter(tokens)
        total = len(tokens)
        return {token: (count / total) * idf.get(token, 0.0) for token, count in counts.items()}

    def _cosine_similarity(self, left: dict[str, float], right: dict[str, float]) -> float:
        if not left or not right:
            return 0.0
        shared_tokens = set(left) & set(right)
        numerator = sum(left[token] * right[token] for token in shared_tokens)
        left_norm = math.sqrt(sum(weight * weight for weight in left.values()))
        right_norm = math.sqrt(sum(weight * weight for weight in right.values()))
        if not left_norm or not right_norm:
            return 0.0
        return numerator / (left_norm * right_norm)

    def search(self, context: str, *, limit: int = 3) -> list[TechniqueMatch]:
        query_vector = self._tfidf(self._tokenize(context), self._idf)
        matches: list[TechniqueMatch] = []
        for entry, vector in zip(self.techniques, self._vectors, strict=True):
            score = self._cosine_similarity(query_vector, vector)
            matches.append(
                TechniqueMatch(
                    attack_id=entry.attack_id,
                    name=entry.name,
                    tactics=entry.tactics,
                    score=score,
                )
            )
        matches.sort(key=lambda item: item.score, reverse=True)
        return matches[:limit]
