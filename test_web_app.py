#!/usr/bin/env python3
"""Regression tests for web app bootstrap and required artefacts."""

from pathlib import Path


REQUIRED_FILES = (
    "web_app.py",
    "templates/index.html",
    "static/css/style.css",
    "static/js/app.js",
    "processor/__init__.py",
    "processor/csv_importer.py",
    "processor/analyzer.py",
    "processor/report_generator.py",
)


def test_required_modules_importable():
    """Ensure core modules can be imported without raising ImportError."""

    from flask import Flask  # noqa: F401
    from processor.csv_importer import SpiderFootCSVImporter  # noqa: F401
    from processor.analyzer import SpiderFootAnalyzer  # noqa: F401
    from processor.report_generator import ReportGenerator  # noqa: F401


def test_flask_app_routes_accessible():
    """Validate that the Flask app boots and exposes the key routes."""

    from web_app import app

    with app.test_client() as client:
        health = client.get("/health")
        assert health.status_code == 200
        assert health.is_json
        payload = health.get_json()
        assert payload.get("status") == "healthy"

        index = client.get("/")
        assert index.status_code == 200
        assert b"SpiderFoot" in index.data


def test_required_files_present():
    """Check that essential project files exist so the UI can load."""

    for relative_path in REQUIRED_FILES:
        assert Path(relative_path).exists(), f"Missing required file: {relative_path}"
