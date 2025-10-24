#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for LLM client configuration and helpers."""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from processor.llm_client import LLMReportConfig, LLMReportBuilder  # noqa: E402


class LLMClientTestCase(unittest.TestCase):
    """Test cases targeting the LLM client hardening helpers."""

    def setUp(self):
        self.managed_keys = [
            "SPIDERFOOT_LLM_MODEL",
            "SPIDERFOOT_LLM_API_KEY",
            "SPIDERFOOT_LLM_TIMEOUT",
            "SPIDERFOOT_LLM_MAX_RETRIES",
            "SPIDERFOOT_LLM_REDACT_FIELDS",
            "SPIDERFOOT_LLM_MAX_SAMPLE_RECORDS",
            "SPIDERFOOT_LLM_BASE_URL",
            "SPIDERFOOT_LLM_PROVIDER",
            "SPIDERFOOT_LLM_ORG",
            "SPIDERFOOT_LLM_SYSTEM_PROMPT",
            "SPIDERFOOT_LLM_SYSTEM_PROMPT_FILE",
            "SPIDERFOOT_LLM_USER_INSTRUCTIONS",
            "SPIDERFOOT_LLM_USER_INSTRUCTIONS_FILE",
            "SPIDERFOOT_LLM_FALLBACK_MODEL",
            "SPIDERFOOT_LLM_FALLBACK_SYSTEM_PROMPT",
            "LLM_MODEL",
            "LLM_API_KEY",
            "LLM_TIMEOUT",
            "LLM_MAX_RETRIES",
        ]
        self.original_env = {key: os.environ.get(key) for key in self.managed_keys}
        for key in self.managed_keys:
            os.environ.pop(key, None)

    def tearDown(self):
        for key in self.managed_keys:
            os.environ.pop(key, None)
            original = self.original_env.get(key)
            if original is not None:
                os.environ[key] = original

    def _build_config(self, extra_env=None):
        extra_env = extra_env or {}
        os.environ["SPIDERFOOT_LLM_MODEL"] = "dummy-model"
        os.environ["SPIDERFOOT_LLM_API_KEY"] = "dummy-key"
        for key, value in extra_env.items():
            os.environ[key] = value
        return LLMReportConfig.from_environment()

    def test_from_environment_uses_defaults(self):
        config = self._build_config()
        self.assertEqual(config.request_timeout, 30.0)
        self.assertEqual(config.max_retries, 2)
        self.assertIn("raw", config.redact_fields)
        self.assertIn("__source_path", config.redact_fields)

    def test_from_environment_overrides(self):
        config = self._build_config(
            {
                "SPIDERFOOT_LLM_TIMEOUT": "15",
                "SPIDERFOOT_LLM_MAX_RETRIES": "4",
                "SPIDERFOOT_LLM_REDACT_FIELDS": "Secret,__row_number",
            }
        )
        self.assertEqual(config.request_timeout, 15.0)
        self.assertEqual(config.max_retries, 4)
        self.assertIn("Secret", config.redact_fields)
        self.assertIn("__row_number", config.redact_fields)

    def test_prompt_payload_is_sanitised(self):
        config = self._build_config({"SPIDERFOOT_LLM_REDACT_FIELDS": "Secret"})
        fake_completion = mock.Mock(return_value={
            "choices": [
                {"message": {"content": "{}"}, "finish_reason": "stop"}
            ]
        })

        analysis = {
            "summary": {"total_records": 1, "raw": "should strip"},
            "web_research": {
                "provider": "duckduckgo",
                "queries": [
                    {
                        "query": "example",
                        "fetched_at": "2025-01-01T00:00:00Z",
                        "results": [
                            {
                                "title": "Example",
                                "url": "https://example.com",
                                "raw": "remove",
                            }
                        ],
                    }
                ],
            },
        }
        sample_records = [
            {
                "Type": "CORRUPTION_INDICATOR",
                "Data": "value",
                "raw": {"inner": "hidden"},
                "Secret": "sensitive",
                "__source_path": "/tmp/source.csv",
            }
        ]

        with mock.patch("processor.llm_client.completion", fake_completion):
            builder = LLMReportBuilder(config)
            payload = builder._build_prompt_payload(analysis, sample_records, target_sections=5)

        snapshot = payload["analysis_snapshot"]
        self.assertNotIn("raw", snapshot.get("summary", {}))
        queries = snapshot.get("web_research", {}).get("queries", [])
        self.assertTrue(all("raw" not in (result or {}) for item in queries for result in item.get("results", [])))

        redacted_record = payload["sample_records"][0]
        self.assertNotIn("raw", redacted_record)
        self.assertNotIn("Secret", redacted_record)
        self.assertNotIn("__source_path", redacted_record)

    def test_invoke_llm_retries_and_timeout(self):
        config = self._build_config({"SPIDERFOOT_LLM_TIMEOUT": "12", "SPIDERFOOT_LLM_MAX_RETRIES": "1"})

        failure = Exception("temporary failure")
        success_response = {
            "model": "dummy-model",
            "choices": [
                {"message": {"content": "{\"executive_summary\": \"\"}"}, "finish_reason": "stop"}
            ],
            "usage": {"total_tokens": 10},
        }

        mock_completion = mock.Mock(side_effect=[failure, success_response])

        with mock.patch("processor.llm_client.completion", mock_completion):
            builder = LLMReportBuilder(config)
            with mock.patch("processor.llm_client.time.sleep", return_value=None) as sleep_mock:
                content, raw = builder._invoke_llm({})

        self.assertEqual(mock_completion.call_count, 2)
        first_call_kwargs = mock_completion.call_args_list[0].kwargs
        self.assertEqual(first_call_kwargs.get("timeout"), 12.0)
        self.assertEqual(sleep_mock.call_count, 1)
        self.assertEqual(content, "{\"executive_summary\": \"\"}")
        self.assertEqual(raw.get("model"), "dummy-model")


if __name__ == "__main__":
    unittest.main()
