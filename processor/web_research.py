#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Lightweight web research helper for SpiderFoot report enrichment."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from datetime import datetime
from html import unescape
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, unquote, urlparse

import requests

__all__ = [
    "WebResearchError",
    "WebResearchConfig",
    "WebResearchClient",
]


class WebResearchError(RuntimeError):
    """Raised when web research cannot be executed."""


def _env_flag(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on", "enable", "enabled"}


def _default_user_agent() -> str:
    return "SpiderfootProcessor/1.0 (+https://github.com/Watchman8925/Spiderfoot-Processor)"


@dataclass
class WebResearchConfig:
    """Configuration values controlling web research behaviour."""

    enabled: bool = False
    provider: str = "duckduckgo"
    timeout: int = 10
    max_results: int = 3
    max_queries: int = 8
    throttle_seconds: float = 1.0
    user_agent: str = _default_user_agent()

    @classmethod
    def from_environment(cls, enable_override: Optional[bool] = None) -> "WebResearchConfig":
        enabled = enable_override if enable_override is not None else _env_flag("SPIDERFOOT_WEB_SEARCH_ENABLED")
        provider = os.getenv("SPIDERFOOT_WEB_SEARCH_PROVIDER", "duckduckgo").strip().lower() or "duckduckgo"

        def safe_int(env_name: str, default: int) -> int:
            raw = os.getenv(env_name)
            if raw is None:
                return default
            try:
                value = int(raw)
            except ValueError:
                return default
            return value if value > 0 else default

        def safe_float(env_name: str, default: float) -> float:
            raw = os.getenv(env_name)
            if raw is None:
                return default
            try:
                value = float(raw)
            except ValueError:
                return default
            return value if value >= 0 else default

        timeout = safe_int("SPIDERFOOT_WEB_SEARCH_TIMEOUT", 10)
        max_results = safe_int("SPIDERFOOT_WEB_SEARCH_MAX_RESULTS", 3)
        max_queries = safe_int("SPIDERFOOT_WEB_SEARCH_MAX_QUERIES", 8)
        throttle_seconds = safe_float("SPIDERFOOT_WEB_SEARCH_THROTTLE_SECONDS", 1.0)
        user_agent = os.getenv("SPIDERFOOT_WEB_SEARCH_USER_AGENT", _default_user_agent()).strip() or _default_user_agent()
        return cls(
            enabled=enabled,
            provider=provider,
            timeout=timeout,
            max_results=max_results,
            max_queries=max_queries,
            throttle_seconds=throttle_seconds,
            user_agent=user_agent,
        )


class _DuckDuckGoParser(HTMLParser):
    """Minimal parser to extract DuckDuckGo search results."""

    def __init__(self) -> None:
        super().__init__()
        self.results: List[Dict[str, str]] = []
        self._current: Optional[Dict[str, str]] = None
        self._active_field: Optional[str] = None
        self._buffer: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[tuple]) -> None:
        attr_map = {key: value for key, value in attrs}
        class_tokens = (attr_map.get("class") or "").split()

        if tag == "a" and "result__a" in class_tokens:
            if self._current and self._current.get("url") and self._current.get("title"):
                self.results.append(self._current)
            href = attr_map.get("href", "")
            self._current = {"url": href, "title": "", "snippet": ""}
            self._active_field = "title"
            self._buffer = []
        elif tag in {"a", "span", "p"} and "result__snippet" in class_tokens and self._current:
            self._active_field = "snippet"
            self._buffer = []

    def handle_endtag(self, tag: str) -> None:
        if self._active_field and tag in {"a", "span", "p"}:
            text = unescape("".join(self._buffer).strip())
            if self._current:
                if self._active_field == "title" and not self._current.get("title"):
                    self._current["title"] = text
                elif self._active_field == "snippet" and not self._current.get("snippet"):
                    self._current["snippet"] = text
            self._active_field = None
            self._buffer = []

        if tag == "a" and self._current and self._current.get("url") and self._current.get("title"):
            # Snippet may appear later; do not append again here.
            pass

    def handle_data(self, data: str) -> None:
        if self._active_field is not None:
            self._buffer.append(data)

    def close(self) -> None:
        super().close()
        if self._current and self._current.get("url") and self._current.get("title"):
            self.results.append(self._current)
        self._current = None
        self._buffer = []
        self._active_field = None


def _clean_duckduckgo_url(url: str) -> str:
    if not url:
        return url
    if "duckduckgo.com/l/" in url:
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        uddg = query.get("uddg")
        if uddg:
            return unquote(uddg[0])
    return url


class WebResearchClient:
    """Simple HTTP client that performs web searches for enrichment."""

    def __init__(self, config: WebResearchConfig):
        if not config.enabled:
            raise WebResearchError("Web research requested but disabled in configuration.")
        if config.provider not in {"duckduckgo"}:
            raise WebResearchError(f"Unsupported web search provider: {config.provider}")

        self.config = config
        self.provider_name = config.provider
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": config.user_agent})
        self._last_request_ts = 0.0

    def _respect_throttle(self) -> None:
        delay = self.config.throttle_seconds
        if delay <= 0:
            return
        now = time.time()
        elapsed = now - self._last_request_ts
        if elapsed < delay:
            time.sleep(delay - elapsed)
        self._last_request_ts = time.time()

    def search(self, query: str) -> List[Dict[str, str]]:
        query = (query or "").strip()
        if not query:
            return []
        self._respect_throttle()
        try:
            response = self._session.get(
                "https://duckduckgo.com/html/",
                params={"q": query, "ia": "web"},
                timeout=self.config.timeout,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            raise WebResearchError(f"DuckDuckGo request failed: {exc}") from exc

        parser = _DuckDuckGoParser()
        parser.feed(response.text)
        parser.close()

        cleaned: List[Dict[str, str]] = []
        for result in parser.results:
            url = _clean_duckduckgo_url(result.get("url", ""))
            title = result.get("title", "").strip()
            snippet = result.get("snippet", "").strip()
            if not url or not title:
                continue
            cleaned.append(
                {
                    "title": title,
                    "url": url,
                    "snippet": snippet,
                }
            )
            if len(cleaned) >= self.config.max_results:
                break
        return cleaned

    def bulk_search(self, queries: List[str]) -> Dict[str, List[Dict[str, str]]]:
        results: Dict[str, List[Dict[str, str]]] = {}
        for idx, query in enumerate(queries):
            if idx >= self.config.max_queries:
                break
            try:
                hits = self.search(query)
            except WebResearchError as exc:
                results[query] = [{"error": str(exc)}]
                continue
            results[query] = hits
        return results

    def metadata(self) -> Dict[str, Any]:
        return {
            "provider": self.provider_name,
            "timeout": self.config.timeout,
            "max_results": self.config.max_results,
        }


def summarise_web_research(raw_results: Dict[str, List[Dict[str, str]]], provider: str) -> Dict[str, Any]:
    """Convert raw search output into a structured summary."""
    if not raw_results:
        return {}

    summary = {
        "provider": provider,
        "executed_at": datetime.utcnow().isoformat() + "Z",
        "queries": [],
        "errors": [],
    }

    for query, entries in raw_results.items():
        cleaned_entries: List[Dict[str, str]] = []
        error_messages: List[str] = []
        for entry in entries:
            if "error" in entry:
                error_messages.append(entry["error"])
                continue
            cleaned_entries.append(entry)
        if cleaned_entries:
            summary["queries"].append(
                {
                    "query": query,
                    "fetched_at": datetime.utcnow().isoformat() + "Z",
                    "results": cleaned_entries,
                }
            )
        if error_messages:
            summary["errors"].append({"query": query, "messages": error_messages})

    return summary
