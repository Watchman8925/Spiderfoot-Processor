#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LLM integration helpers for generating long-form investigative reports."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import importlib

_litellm = None
completion = None
try:  # Optional dependency managed here to keep import errors local
    _litellm = importlib.import_module("litellm")
    completion = getattr(_litellm, "completion", None)
except ImportError:  # pragma: no cover - handled gracefully by callers
    completion = None  # type: ignore


class LLMReportError(RuntimeError):
    """Raised when LLM report generation fails or is misconfigured."""


FORENSIC_SYSTEM_PROMPT = (
    "You are a forensic intelligence analyst LLM. Your job is to analyze uploaded "
    "SpiderFoot CSV exports and produce full-length, evidence-based intelligence "
    "reports and investigative journalism narratives. You must:\n\n"
    "- Parse and normalize all data\n"
    "- Detect entities, resolve duplicates, and construct a relationship graph\n"
    "- Identify hidden connections, suspicious patterns, and TOC-corruption indicators\n"
    "- List exact SpiderFoot rows (filename:row:column) supporting every claim\n"
    "- Produce two PDFs:\n"
    "  1. An intelligence report (structured, with provenance)\n"
    "  2. A narrative investigative exposé (journalistic style)\n\n"
    "Every claim must be traceable. Do not hallucinate. If no evidence exists, state so. "
    "Highlight red flags, typologies, and jurisdictional risks. Graphs and timelines must "
    "match your analysis. Do not omit source details."
)

DEFAULT_SYSTEM_PROMPT = (
    f"{FORENSIC_SYSTEM_PROMPT}\n\n"
    "You are an elite intelligence analyst building a comprehensive "
    "investigative report based on OSINT-derived SpiderFoot findings. "
    "Produce a JSON object with these keys: executive_summary (string), "
    "detailed_report (list of sections with title/content), pivots "
    "(list of leads with title, summary, rationale, recommended_actions, "
    "confidence, supporting_evidence), strategic_recommendations (list of strings). "
    "The combined narrative should approximate 30 pages (target 350+ words per section). "
    "Make pivots actionable and explain why each matters."
)


@dataclass
class LLMReportConfig:
    """Configuration container for LLM report generation."""

    model: str
    api_key: str
    base_url: Optional[str] = None
    provider: Optional[str] = None
    organization: Optional[str] = None
    temperature: float = 0.2
    max_output_tokens: int = 8192
    top_p: Optional[float] = None
    system_prompt: Optional[str] = None
    user_prompt_prefix: Optional[str] = None
    fallback_model: Optional[str] = None
    fallback_system_prompt: Optional[str] = None
    max_sample_records: int = 50

    @classmethod
    def from_environment(cls) -> "LLMReportConfig":
        """Build configuration from environment variables."""
        model = os.getenv("SPIDERFOOT_LLM_MODEL") or os.getenv("LLM_MODEL")
        if not model:
            raise LLMReportError(
                "LLM model not configured. Set SPIDERFOOT_LLM_MODEL or LLM_MODEL."
            )

        api_key = os.getenv("SPIDERFOOT_LLM_API_KEY") or os.getenv("LLM_API_KEY")
        if not api_key:
            raise LLMReportError(
                "LLM API key not configured. Set SPIDERFOOT_LLM_API_KEY or LLM_API_KEY."
            )

        base_url = os.getenv("SPIDERFOOT_LLM_BASE_URL") or os.getenv("LLM_BASE_URL")
        provider = os.getenv("SPIDERFOOT_LLM_PROVIDER") or os.getenv("LLM_PROVIDER")
        organization = os.getenv("SPIDERFOOT_LLM_ORG") or os.getenv("LLM_ORG")
        temperature = float(
            os.getenv("SPIDERFOOT_LLM_TEMPERATURE")
            or os.getenv("LLM_TEMPERATURE")
            or 0.2
        )
        max_output_tokens = int(
            os.getenv("SPIDERFOOT_LLM_MAX_OUTPUT_TOKENS")
            or os.getenv("LLM_MAX_OUTPUT_TOKENS")
            or 8192
        )
        top_p_env = os.getenv("SPIDERFOOT_LLM_TOP_P") or os.getenv("LLM_TOP_P")
        top_p = float(top_p_env) if top_p_env else None

        system_prompt = cls._load_prompt("SPIDERFOOT_LLM_SYSTEM_PROMPT", "SPIDERFOOT_LLM_SYSTEM_PROMPT_FILE")
        user_prompt_prefix = cls._load_prompt(
            "SPIDERFOOT_LLM_USER_INSTRUCTIONS", "SPIDERFOOT_LLM_USER_INSTRUCTIONS_FILE"
        )
        fallback_model = os.getenv("SPIDERFOOT_LLM_FALLBACK_MODEL") or os.getenv("LLM_FALLBACK_MODEL")
        fallback_system_prompt = cls._load_prompt(
            "SPIDERFOOT_LLM_FALLBACK_SYSTEM_PROMPT", "SPIDERFOOT_LLM_FALLBACK_SYSTEM_PROMPT_FILE"
        )

        max_sample_records_env = (
            os.getenv("SPIDERFOOT_LLM_MAX_SAMPLE_RECORDS")
            or os.getenv("LLM_MAX_SAMPLE_RECORDS")
        )
        if max_sample_records_env:
            try:
                max_sample_records = int(max_sample_records_env)
            except ValueError as exc:
                raise LLMReportError(
                    "LLM sample record limit must be an integer."
                ) from exc
            if max_sample_records <= 0:
                max_sample_records = 50
        else:
            max_sample_records = 50

        return cls(
            model=model,
            api_key=api_key,
            base_url=base_url or None,
            provider=provider or None,
            organization=organization or None,
            temperature=temperature,
            max_output_tokens=max_output_tokens,
            top_p=top_p,
            system_prompt=system_prompt,
            user_prompt_prefix=user_prompt_prefix,
            fallback_model=fallback_model or None,
            fallback_system_prompt=fallback_system_prompt,
            max_sample_records=max_sample_records,
        )

    @staticmethod
    def _load_prompt(text_env: str, file_env: str) -> Optional[str]:
        """Load a prompt either from direct env text or file path."""
        prompt = os.getenv(text_env)
        file_path = os.getenv(file_env)
        if file_path:
            path = Path(file_path).expanduser()
            try:
                prompt = path.read_text(encoding="utf-8")
            except OSError as exc:
                raise LLMReportError(f"Failed to read prompt file '{file_path}': {exc}") from exc
        if prompt:
            prompt = prompt.strip()
        return prompt or None


@dataclass
class PivotLead:
    """Represents a potential investigative pivot or lead."""

    title: str
    summary: str
    rationale: str
    recommended_actions: str
    confidence: str
    supporting_evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "summary": self.summary,
            "rationale": self.rationale,
            "recommended_actions": self.recommended_actions,
            "confidence": self.confidence,
            "supporting_evidence": self.supporting_evidence,
        }


@dataclass
class LLMReportResult:
    """Structured result returned by the LLM."""

    executive_summary: str
    narrative_sections: List[Dict[str, str]]
    pivots_and_leads: List[PivotLead]
    recommendations: List[str]
    metadata: Dict[str, Any]
    raw_payload: Dict[str, Any]

    def to_markdown(self) -> str:
        """Render the report as Markdown for archival/download."""
        lines: List[str] = []
        lines.append("# AI-Generated Investigative Report")
        lines.append("")
        lines.append(f"_Generated on {datetime.utcnow().isoformat()}Z_")
        lines.append("")

        if self.metadata:
            lines.append("<!-- LLM Metadata -->")
            for key, value in self.metadata.items():
                clean_value = value if isinstance(value, str) else json.dumps(value)
                lines.append(f"- **{key}**: {clean_value}")
            lines.append("")

        lines.append("## Executive Summary")
        lines.append(self.executive_summary.strip())
        lines.append("")

        lines.append("## Detailed Narrative")
        for idx, section in enumerate(self.narrative_sections, start=1):
            title = section.get("title") or f"Section {idx}"
            content = section.get("content") or section.get("body") or ""
            lines.append(f"### {idx}. {title}")
            lines.append(content.strip())
            lines.append("")

        if self.pivots_and_leads:
            lines.append("## Investigative Pivots & Leads")
            for lead in self.pivots_and_leads:
                lines.append(f"### {lead.title}")
                lines.append(f"**Confidence:** {lead.confidence}")
                lines.append(f"**Summary:** {lead.summary}")
                lines.append(f"**Rationale:** {lead.rationale}")
                lines.append(f"**Recommended Actions:** {lead.recommended_actions}")
                if lead.supporting_evidence:
                    lines.append("**Supporting Evidence:**")
                    for evidence in lead.supporting_evidence:
                        lines.append(f"- {evidence}")
                lines.append("")

        if self.recommendations:
            lines.append("## Strategic Recommendations")
            for rec in self.recommendations:
                lines.append(f"- {rec}")
            lines.append("")

        return "\n".join(lines).strip() + "\n"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "executive_summary": self.executive_summary,
            "narrative_sections": self.narrative_sections,
            "pivots_and_leads": [lead.to_dict() for lead in self.pivots_and_leads],
            "recommendations": self.recommendations,
            "metadata": self.metadata,
            "raw_payload": self.raw_payload,
        }


class BaseReportBuilder:
    """Interface for report builders used by the reporting pipeline."""

    def generate_report(
        self,
        analysis_data: Dict[str, Any],
        sample_records: Optional[List[Dict[str, Any]]] = None,
        target_sections: int = 30,
    ) -> LLMReportResult:
        raise NotImplementedError


class LLMReportBuilder(BaseReportBuilder):
    """High-level helper to construct detailed reports via LLM."""

    def __init__(self, config: LLMReportConfig):
        self.config = config
        if completion is None:  # pragma: no cover - depends on optional deps
            raise LLMReportError(
                "litellm is not installed. Install it or disable LLM reporting."
            )

    @classmethod
    def from_environment(cls) -> "LLMReportBuilder":
        config = LLMReportConfig.from_environment()
        return cls(config)

    def generate_report(
        self,
        analysis_data: Dict[str, Any],
        sample_records: Optional[List[Dict[str, Any]]] = None,
        target_sections: int = 30,
    ) -> LLMReportResult:
        """Generate a structured long-form report using the configured LLM."""
        payload = self._build_prompt_payload(analysis_data, sample_records, target_sections)
        try:
            response_text, raw_response = self._invoke_llm(payload)
            structured_payload = self._parse_llm_response(response_text)
        except LLMReportError as primary_error:
            if not self.config.fallback_model:
                raise
            try:
                response_text, raw_response = self._invoke_llm(
                    payload,
                    model_override=self.config.fallback_model,
                    system_prompt_override=self.config.fallback_system_prompt,
                )
                structured_payload = self._parse_llm_response(response_text)
            except LLMReportError as fallback_error:
                combined_message = (
                    f"Primary model '{self.config.model}' failed: {primary_error}. "
                    f"Fallback model '{self.config.fallback_model}' failed: {fallback_error}."
                )
                raise LLMReportError(combined_message) from fallback_error
        return self._build_result(structured_payload, raw_response)

    def _build_prompt_payload(
        self,
        analysis_data: Dict[str, Any],
        sample_records: Optional[List[Dict[str, Any]]],
        target_sections: int,
    ) -> Dict[str, Any]:
        """Assemble the contextual payload provided to the LLM."""
        sample_records = sample_records or []
        trimmed_records = sample_records[: self.config.max_sample_records]

        return {
            "generation_directives": {
                "target_sections": target_sections,
                "target_min_words": target_sections * 350,
                "tone": "professional investigative intelligence",
                "focus": [
                    "Corruption indicators",
                    "Threat-of-compromise signals",
                    "Attribution pivots",
                    "Operational impact",
                    "Recommended mitigations",
                ],
                "include_structured_json": True,
                "explain_significance": True,
            },
            "analysis_snapshot": self._shrink_analysis(analysis_data),
            "sample_records": trimmed_records,
        }

    def _shrink_analysis(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Reduce analysis payload to essentials for prompt efficiency."""
        def top_items(sequence: List[Any], limit: int = 10) -> List[Any]:
            return sequence[:limit] if isinstance(sequence, list) else sequence

        snapshot = {
            "summary": analysis.get("summary", {}),
            "event_distribution": {
                "total_events": analysis.get("event_distribution", {}).get("total_events"),
                "most_common": top_items(
                    analysis.get("event_distribution", {}).get("most_common", []),
                    15,
                ),
            },
            "module_activity": {
                "most_active": top_items(
                    analysis.get("module_activity", {}).get("most_active", []),
                    15,
                )
            },
            "corruption_patterns": {
                "total_indicators": analysis.get("corruption_patterns", {}).get("total_indicators"),
                "most_common_keywords": top_items(
                    analysis.get("corruption_patterns", {}).get("most_common_keywords", []),
                    20,
                ),
            },
            "toc_patterns": {
                "total_indicators": analysis.get("toc_patterns", {}).get("total_indicators"),
                "most_common_keywords": top_items(
                    analysis.get("toc_patterns", {}).get("most_common_keywords", []),
                    20,
                ),
            },
            "risk_domains": analysis.get("risk_domains", {}),
            "compromised_assets": analysis.get("compromised_assets", {}),
            "timeline": analysis.get("timeline", {}),
            "pivots_and_leads": analysis.get("pivots_and_leads", []),
        }

        web_research = analysis.get("web_research") or {}
        if web_research:
            trimmed_queries: List[Dict[str, Any]] = []
            for item in (web_research.get("queries") or [])[: self.config.max_sample_records // 5 or 5]:
                trimmed_item = {
                    "query": item.get("query"),
                    "fetched_at": item.get("fetched_at"),
                    "results": (item.get("results") or [])[:3],
                }
                trimmed_queries.append(trimmed_item)
            snapshot["web_research"] = {
                "provider": web_research.get("provider", "duckduckgo"),
                "executed_at": web_research.get("executed_at"),
                "queries": trimmed_queries,
                "errors": web_research.get("errors", []),
            }
        return snapshot

    def _invoke_llm(
        self,
        payload: Dict[str, Any],
        model_override: Optional[str] = None,
        system_prompt_override: Optional[str] = None,
    ) -> Tuple[str, Dict[str, Any]]:
        """Invoke the configured LLM and return raw response data."""
        system_prompt = system_prompt_override or self.config.system_prompt or DEFAULT_SYSTEM_PROMPT

        user_payload = json.dumps(payload, ensure_ascii=False, indent=2)
        if self.config.user_prompt_prefix:
            prefix = self.config.user_prompt_prefix.strip()
            if prefix:
                user_payload = f"{prefix}\n\n{user_payload}"

        messages = [
            {
                "role": "system",
                "content": system_prompt,
            },
            {
                "role": "user",
                "content": user_payload,
            },
        ]

        kwargs: Dict[str, Any] = {
            "model": model_override or self.config.model,
            "messages": messages,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_output_tokens,
        }

        # Optional parameters when supported by provider
        if self.config.api_key:
            kwargs["api_key"] = self.config.api_key
        if self.config.base_url:
            kwargs["base_url"] = self.config.base_url
        if self.config.organization:
            kwargs["organization"] = self.config.organization
        if self.config.provider:
            kwargs["custom_llm_provider"] = self.config.provider
        if self.config.top_p is not None:
            kwargs["top_p"] = self.config.top_p

        try:
            raw_response = completion(**kwargs)
        except Exception as exc:  # pragma: no cover - network dependent
            raise LLMReportError(f"LLM request failed: {exc}") from exc

        content = self._extract_content(raw_response)
        return content, self._normalize_raw_response(raw_response)

    def _extract_content(self, response: Any) -> str:
        """Extract the text payload from a litellm response object."""
        try:
            if hasattr(response, "choices"):
                content = response.choices[0].message["content"]
            else:
                content = response["choices"][0]["message"]["content"]
        except (KeyError, AttributeError, IndexError) as exc:
            raise LLMReportError("Unexpected response format from LLM") from exc

        return content or ""

    def _normalize_raw_response(self, response: Any) -> Dict[str, Any]:
        """Convert provider-specific response objects into serialisable dicts."""
        if isinstance(response, dict):
            return response

        # Attempt to convert dataclass-like responses
        normalised: Dict[str, Any] = {}
        for attr in ("id", "model", "created", "usage"):
            if hasattr(response, attr):
                normalised[attr] = getattr(response, attr)
        try:
            if hasattr(response, "choices"):
                normalised["choices"] = [
                    {
                        "message": choice.message if hasattr(choice, "message") else None,
                        "finish_reason": getattr(choice, "finish_reason", None),
                    }
                    for choice in response.choices
                ]
        except Exception:  # pragma: no cover
            pass
        return normalised

    def _parse_llm_response(self, content: str) -> Dict[str, Any]:
        """Parse the JSON response emitted by the LLM."""
        text = content.strip()
        if not text:
            raise LLMReportError("Empty response from LLM")

        if text.startswith("```"):
            # Handle "```json ... ```" style wrappers
            text = text.strip("`").split("json", 1)[-1].strip()

        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise LLMReportError(
                "Failed to parse LLM response as JSON. Enable debug logging to inspect output."
            ) from exc

    def _build_result(
        self,
        payload: Dict[str, Any],
        raw_response: Dict[str, Any],
    ) -> LLMReportResult:
        """Convert parsed payload into strongly-typed result."""
        executive_summary = payload.get("executive_summary") or payload.get("summary") or ""
        narrative_sections = payload.get("detailed_report") or payload.get("sections") or []
        recommendations = payload.get("strategic_recommendations") or payload.get("recommendations") or []
        pivots_payload = payload.get("pivots") or payload.get("pivots_and_leads") or []

        pivots: List[PivotLead] = []
        for item in pivots_payload:
            pivots.append(
                PivotLead(
                    title=item.get("title", "Lead"),
                    summary=item.get("summary", ""),
                    rationale=item.get("rationale", ""),
                    recommended_actions=item.get("recommended_actions", item.get("next_steps", "")),
                    confidence=item.get("confidence", "moderate"),
                    supporting_evidence=item.get("supporting_evidence", []) or [],
                )
            )

        metadata = {
            "model": raw_response.get("model", self.config.model),
            "provider": self.config.provider or "auto",
            "tokens": raw_response.get("usage", {}),
        }

        return LLMReportResult(
            executive_summary=executive_summary,
            narrative_sections=narrative_sections,
            pivots_and_leads=pivots,
            recommendations=recommendations,
            metadata=metadata,
            raw_payload=payload,
        )


class LocalLLMReportBuilder(BaseReportBuilder):
    """Deterministic fallback generator when no external LLM is configured."""

    def __init__(self, system_prompt: str, user_instructions: Optional[str] = None):
        self.system_prompt = system_prompt.strip() or FORENSIC_SYSTEM_PROMPT
        self.user_instructions = user_instructions.strip() if user_instructions else None

    @classmethod
    def from_environment(cls) -> "LocalLLMReportBuilder":
        system_prompt = (
            LLMReportConfig._load_prompt(  # pylint: disable=protected-access
                "SPIDERFOOT_LLM_SYSTEM_PROMPT",
                "SPIDERFOOT_LLM_SYSTEM_PROMPT_FILE",
            )
            or FORENSIC_SYSTEM_PROMPT
        )
        user_instructions = LLMReportConfig._load_prompt(  # pylint: disable=protected-access
            "SPIDERFOOT_LLM_USER_INSTRUCTIONS",
            "SPIDERFOOT_LLM_USER_INSTRUCTIONS_FILE",
        )
        return cls(system_prompt=system_prompt, user_instructions=user_instructions)

    def generate_report(
        self,
        analysis_data: Dict[str, Any],
        sample_records: Optional[List[Dict[str, Any]]] = None,
        target_sections: int = 12,
    ) -> LLMReportResult:
        dataset_label = self._resolve_dataset_label(analysis_data, sample_records)
        sample_records = sample_records or []

        executive_summary = self._build_executive_summary(analysis_data)
        narrative_sections = self._build_narrative_sections(
            analysis_data, sample_records, dataset_label, target_sections
        )
        pivots = self._build_pivots(analysis_data, sample_records, dataset_label)
        recommendations = self._build_recommendations(analysis_data)

        metadata = {
            "engine": "local-template",
            "system_prompt": self.system_prompt,
            "user_instructions": self.user_instructions or "",
            "sample_records_used": len(sample_records),
        }

        raw_payload = {
            "analysis_snapshot": analysis_data,
            "sample_records": sample_records[:5],
            "dataset_label": dataset_label,
        }

        return LLMReportResult(
            executive_summary=executive_summary,
            narrative_sections=narrative_sections,
            pivots_and_leads=pivots,
            recommendations=recommendations,
            metadata=metadata,
            raw_payload=raw_payload,
        )

    def _resolve_dataset_label(
        self,
        analysis_data: Dict[str, Any],
        sample_records: Optional[List[Dict[str, Any]]],
    ) -> str:
        sample_records = sample_records or []
        summary = analysis_data.get("summary", {})
        label = (
            summary.get("source_filename")
            or summary.get("source_file")
            or (sample_records[0].get("__source_file") if sample_records else None)
        )
        return str(label or "uploaded.csv")

    def _build_executive_summary(self, analysis_data: Dict[str, Any]) -> str:
        summary = analysis_data.get("summary", {})
        total_records = summary.get("total_records", 0)
        total_events = analysis_data.get("event_distribution", {}).get("total_events", 0)
        corruption_total = analysis_data.get("corruption_patterns", {}).get("total_indicators", 0)
        toc_total = analysis_data.get("toc_patterns", {}).get("total_indicators", 0)
        risk_domains = analysis_data.get("risk_domains", {}).get("total_risk_domains", 0)
        compromised_assets = analysis_data.get("compromised_assets", {}).get("total_compromised", 0)

        lines = [
            "### Collection Synopsis",
            f"Dataset contains {total_records:,} SpiderFoot observations spanning {total_events:,} discrete events.",
            f"Detected {corruption_total:,} corruption indicators and {toc_total:,} threat-of-compromise alerts.",
            f"Flagged {risk_domains:,} high-risk domains and {compromised_assets:,} potentially compromised assets requiring review.",
        ]

        timeline = analysis_data.get("timeline", {})
        if timeline.get("has_timeline") and timeline.get("total_days"):
            lines.append(
                f"Timeline coverage spans {timeline['total_days']} days with recorded event activity."
            )

        web_research = analysis_data.get("web_research") or {}
        if web_research.get("queries"):
            lines.append(
                f"Enriched reporting with {len(web_research['queries'])} open-source query set(s)."
            )

        return "\n".join(lines).strip()

    def _build_narrative_sections(
        self,
        analysis_data: Dict[str, Any],
        sample_records: List[Dict[str, Any]],
        dataset_label: str,
        target_sections: int,
    ) -> List[Dict[str, str]]:
        sections: List[Dict[str, str]] = []

        corruption = analysis_data.get("corruption_patterns", {})
        if corruption.get("total_indicators"):
            sections.append(
                {
                    "title": "Corruption Typologies",
                    "content": self._compose_section(
                        dataset_label,
                        corruption.get("events", []),
                        topic="Corruption indicators",
                        keywords=corruption.get("most_common_keywords", []),
                    ),
                }
            )

        toc = analysis_data.get("toc_patterns", {})
        if toc.get("total_indicators"):
            sections.append(
                {
                    "title": "Threat-of-Compromise Surface",
                    "content": self._compose_section(
                        dataset_label,
                        toc.get("events", []),
                        topic="Threat-of-compromise signals",
                        keywords=toc.get("most_common_keywords", []),
                    ),
                }
            )

        risk_domains = analysis_data.get("risk_domains", {})
        if risk_domains.get("total_risk_domains"):
            sections.append(
                {
                    "title": "High-Risk Domain Footprint",
                    "content": self._compose_section(
                        dataset_label,
                        risk_domains.get("records", []),
                        topic="High-risk domains",
                        keywords=list((risk_domains.get("risk_reasons") or {}).keys()),
                    ),
                }
            )

        compromised = analysis_data.get("compromised_assets", {})
        if compromised.get("total_compromised"):
            sections.append(
                {
                    "title": "Compromised Asset Exposure",
                    "content": self._compose_section(
                        dataset_label,
                        compromised.get("records", []),
                        topic="Compromised assets and malicious affiliates",
                        keywords=list((compromised.get("by_type") or {}).keys()),
                    ),
                }
            )

        module_activity = analysis_data.get("module_activity", {})
        if module_activity.get("most_active"):
            sections.append(
                {
                    "title": "Collection Sources & Modules",
                    "content": self._build_module_section(module_activity, dataset_label, sample_records),
                }
            )

        if analysis_data.get("timeline", {}).get("has_timeline"):
            sections.append(
                {
                    "title": "Temporal Observations",
                    "content": self._build_timeline_section(analysis_data.get("timeline", {})),
                }
            )

        web_research = analysis_data.get("web_research") or {}
        if web_research:
            sections.append(
                {
                    "title": "Open-Source Context Enrichment",
                    "content": self._build_web_research_section(web_research),
                }
            )

        if not sections:
            sections.append(
                {
                    "title": "Data Sufficiency",
                    "content": "No investigative signals surfaced in this dataset. Documenting absence of evidence per instructions.",
                }
            )

        return sections[: target_sections]

    def _build_web_research_section(self, web_research: Dict[str, Any]) -> str:
        queries = web_research.get("queries") or []
        if not queries and not web_research.get("errors"):
            return "Web search enrichment was enabled but yielded no additional corroborating sources."

        provider = web_research.get("provider", "web search")
        lines = [f"Supplemental {provider} lookups executed to corroborate investigative pivots."]

        for item in queries[:5]:
            query = item.get("query", "(query)")
            results = item.get("results") or []
            if results:
                top = results[0]
                title = top.get("title", "Result")
                url = top.get("url", "")
                snippet = top.get("snippet")
                lines.append(f"- {query}: {title} — {url}")
                if snippet:
                    lines.append(f"  {snippet}")
            else:
                lines.append(f"- {query}: No authoritative hits returned during sampling.")

        for error in web_research.get("errors", [])[:3]:
            query = error.get("query", "(query)")
            messages = error.get("messages") or []
            if messages:
                joined = "; ".join(messages)
                lines.append(f"- {query}: Lookup failed ({joined})")

        return "\n".join(lines).strip()

    def _compose_section(
        self,
        dataset_label: str,
        records: List[Dict[str, Any]],
        topic: str,
        keywords: Optional[List[Any]] = None,
    ) -> str:
        if not records:
            return f"No {topic.lower()} identified in the ingested SpiderFoot export."

        references = self._collect_evidence_references(records, dataset_label)
        keyword_text = ""
        if keywords:
            cleaned = [str(keyword[0] if isinstance(keyword, (list, tuple)) else keyword) for keyword in keywords]
            cleaned = [word for word in cleaned if word]
            if cleaned:
                keyword_text = "Top recurring markers: " + ", ".join(cleaned[:8]) + "."

        lines = [keyword_text, "Key supporting evidence:"] if keyword_text else ["Key supporting evidence:"]
        lines.extend(f"- {ref}" for ref in references)
        return "\n".join(lines).strip()

    def _collect_evidence_references(
        self,
        records: List[Dict[str, Any]],
        dataset_label: str,
        limit: int = 5,
    ) -> List[str]:
        references: List[str] = []
        for record in records:
            raw = record.get("raw") if isinstance(record, dict) else None
            source = raw if isinstance(raw, dict) else record
            if not isinstance(source, dict):
                continue
            row_number = source.get("__row_number")
            filename = source.get("__source_file", dataset_label)
            if not row_number:
                continue
            snippet = source.get("Data") or source.get("data") or source.get("Source") or "Context not provided"
            value_preview = str(snippet).strip()
            if len(value_preview) > 160:
                value_preview = value_preview[:157] + "..."
            for column in ("Type", "Module", "Data"):
                if column in source:
                    references.append(
                        f"{filename}:{row_number}:{column} → {source.get(column)}"
                    )
            references.append(f"Excerpt: {value_preview}")
            if len(references) >= limit:
                break
        if not references:
            references.append(f"No row-level provenance available for {dataset_label}.")
        return references[:limit]

    def _build_module_section(
        self,
        module_activity: Dict[str, Any],
        dataset_label: str,
        sample_records: List[Dict[str, Any]],
    ) -> str:
        modules = module_activity.get("most_active", [])
        if not modules:
            return "No module activity recorded."

        lines = ["Primary collection modules driving the dataset:"]
        seen = 0
        for module_name, count in modules[:10]:
            lines.append(f"- {module_name}: {count} events")
            seen += 1
        if seen < len(modules):
            lines.append(f"- Additional modules: {len(modules) - seen} more with lower volumes")

        if sample_records:
            references: List[str] = []
            for row in sample_records:
                if row.get("Module") and row.get("__row_number"):
                    references.append(
                        f"{row.get('__source_file', dataset_label)}:{row['__row_number']}:Module → {row['Module']}"
                    )
                if len(references) >= 5:
                    break
            if references:
                lines.append("Representative module provenance:")
                lines.extend(f"- {ref}" for ref in references)

        return "\n".join(lines)

    def _build_timeline_section(self, timeline: Dict[str, Any]) -> str:
        if not timeline.get("has_timeline"):
            return "No timestamp data supplied, timeline omitted."

        by_date = timeline.get("events_by_date", {})
        if not by_date:
            return "Timestamps detected but no per-day aggregation available."

        earliest = next(iter(by_date))
        latest = list(by_date.keys())[-1]
        lines = [
            f"Activity recorded from {earliest} to {latest} covering {len(by_date)} days.",
            "Daily density (top 5 peaks):",
        ]
        for date, count in list(by_date.items())[:5]:
            lines.append(f"- {date}: {count} events")
        return "\n".join(lines)

    def _build_pivots(
        self,
        analysis_data: Dict[str, Any],
        sample_records: List[Dict[str, Any]],
        dataset_label: str,
    ) -> List[PivotLead]:
        pivots_payload = analysis_data.get("pivots_and_leads") or []
        results: List[PivotLead] = []
        for item in pivots_payload[:10]:
            evidence = item.get("supporting_evidence") or []
            if not evidence:
                evidence = self._collect_pivot_evidence(item, sample_records, dataset_label)
            results.append(
                PivotLead(
                    title=item.get("title", "Lead"),
                    summary=item.get("summary", ""),
                    rationale=item.get("rationale", item.get("why", "")),
                    recommended_actions=item.get("recommended_actions", item.get("next_steps", "")),
                    confidence=item.get("confidence", "moderate"),
                    supporting_evidence=evidence,
                )
            )
        return results

    def _collect_pivot_evidence(
        self,
        pivot: Dict[str, Any],
        sample_records: List[Dict[str, Any]],
        dataset_label: str,
        limit: int = 5,
    ) -> List[str]:
        criteria = pivot.get("indicator") or pivot.get("title") or ""
        evidence: List[str] = []
        if not sample_records:
            return evidence
        criteria_lower = str(criteria).lower()
        for row in sample_records:
            haystack = " ".join(str(value) for value in row.values())
            if criteria_lower and criteria_lower not in haystack.lower():
                continue
            row_number = row.get("__row_number")
            if not row_number:
                continue
            evidence.append(
                f"{row.get('__source_file', dataset_label)}:{row_number}:Type → {row.get('Type')}"
            )
            evidence.append(
                f"{row.get('__source_file', dataset_label)}:{row_number}:Data → {row.get('Data')}"
            )
            if len(evidence) >= limit:
                break
        return evidence[:limit]

    def _build_recommendations(self, analysis_data: Dict[str, Any]) -> List[str]:
        recommendations = analysis_data.get("recommendations") or []
        if isinstance(recommendations, list) and recommendations:
            return recommendations

        outputs: List[str] = []
        corruption = analysis_data.get("corruption_patterns", {})
        if corruption.get("total_indicators", 0) > 0:
            outputs.append(
                "Escalate corruption-related entities for enhanced due diligence with provenance attached."
            )
        toc = analysis_data.get("toc_patterns", {})
        if toc.get("total_indicators", 0) > 0:
            outputs.append(
                "Deploy immediate containment for systems linked to threat-of-compromise alerts."
            )
        risk_domains = analysis_data.get("risk_domains", {})
        if risk_domains.get("total_risk_domains", 0) > 0:
            outputs.append(
                "Blacklist domains flagged as high-risk until manual adjudication is complete."
            )
        compromised = analysis_data.get("compromised_assets", {})
        if compromised.get("total_compromised", 0) > 0:
            outputs.append(
                "Notify asset owners and initiate forensic containment for compromised infrastructure."
            )
        if not outputs:
            outputs.append("No actionable threats detected; continue monitoring cadence.")
        return outputs


def resolve_llm_builder(prefer_remote: bool = True) -> BaseReportBuilder:
    """Return an LLM-capable report builder, preferring remote providers when configured."""

    remote_error: Optional[Exception] = None
    if prefer_remote and completion is not None:
        try:
            config = LLMReportConfig.from_environment()
        except LLMReportError as exc:
            remote_error = exc
        else:
            try:
                return LLMReportBuilder(config)
            except LLMReportError as exc:  # litellm missing or misconfigured
                remote_error = exc

    if remote_error:
        print(f"  ! Falling back to embedded narrative engine: {remote_error}")

    return LocalLLMReportBuilder.from_environment()