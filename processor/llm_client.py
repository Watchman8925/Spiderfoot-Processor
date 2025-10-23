#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LLM integration helpers for generating long-form investigative reports."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime
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

        return cls(
            model=model,
            api_key=api_key,
            base_url=base_url or None,
            provider=provider or None,
            organization=organization or None,
            temperature=temperature,
            max_output_tokens=max_output_tokens,
            top_p=top_p,
        )


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


class LLMReportBuilder:
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
        response_text, raw_response = self._invoke_llm(payload)
        structured_payload = self._parse_llm_response(response_text)
        return self._build_result(structured_payload, raw_response)

    def _build_prompt_payload(
        self,
        analysis_data: Dict[str, Any],
        sample_records: Optional[List[Dict[str, Any]]],
        target_sections: int,
    ) -> Dict[str, Any]:
        """Assemble the contextual payload provided to the LLM."""
        sample_records = sample_records or []
        trimmed_records = sample_records[:50]  # Prevent runaway context sizes

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
        return snapshot

    def _invoke_llm(self, payload: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Invoke the configured LLM and return raw response data."""
        messages = [
            {
                "role": "system",
                "content": (
                    "You are an elite intelligence analyst building a comprehensive "
                    "investigative report based on OSINT-derived SpiderFoot findings. "
                    "Produce a JSON object with these keys: executive_summary (string), "
                    "detailed_report (list of sections with title/content), pivots "
                    "(list of leads with title, summary, rationale, recommended_actions, "
                    "confidence, supporting_evidence), strategic_recommendations (list of strings). "
                    "The combined narrative should approximate 30 pages (target 350+ words per section). "
                    "Make pivots actionable and explain why each matters."
                ),
            },
            {
                "role": "user",
                "content": json.dumps(payload, ensure_ascii=False, indent=2),
            },
        ]

        kwargs: Dict[str, Any] = {
            "model": self.config.model,
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