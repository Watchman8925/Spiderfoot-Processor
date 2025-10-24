#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SpiderFoot TOC/Corruption Web Application

A modern web interface for processing SpiderFoot CSV exports,
generating visualizations, and creating PDF reports.
"""

import importlib
import json
import os
import sys
from datetime import datetime
from pathlib import Path

from flask import Flask, render_template, request, jsonify, send_file
from werkzeug.utils import secure_filename

# Add processor to path
sys.path.insert(0, os.path.dirname(__file__))

from processor.csv_importer import SpiderFootCSVImporter
from processor.analyzer import SpiderFootAnalyzer
from processor.report_generator import ReportGenerator
from processor.web_research import WebResearchConfig

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size
app.config['UPLOAD_FOLDER'] = Path('uploads')
app.config['REPORTS_FOLDER'] = Path('reports')

# Ensure folders exist
app.config['UPLOAD_FOLDER'].mkdir(exist_ok=True)
app.config['REPORTS_FOLDER'].mkdir(exist_ok=True)

ALLOWED_EXTENSIONS = {'csv'}
TEXT_PREVIEW_EXTENSIONS = {'.json', '.txt', '.md', '.markdown', '.csv', '.log'}
INLINE_IMAGE_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.svg'}
INLINE_PDF_EXTENSIONS = {'.pdf'}
MAX_TEXT_PREVIEW_BYTES = 200_000


def allowed_file(filename):
    """Check if file has allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def _resolve_report_file(report_id: str, filename: str) -> Path:
    """Return a safe filesystem path for a generated report artefact."""

    if Path(report_id).name != report_id or Path(filename).name != filename:
        raise ValueError("Invalid path components supplied.")

    base_reports = app.config['REPORTS_FOLDER'].resolve()
    target_path = (base_reports / report_id / filename).resolve()

    if not target_path.exists():
        raise FileNotFoundError(filename)

    if base_reports not in target_path.parents:
        raise ValueError("Attempted access outside reports directory.")

    return target_path


@app.route('/')
def index():
    """Render the main page."""
    default_web_research = WebResearchConfig.from_environment().enabled
    return render_template('index.html', default_web_research=default_web_research)


@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle CSV file upload."""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']

        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        if not allowed_file(file.filename):
            return jsonify({'error': 'Invalid file type. Only CSV files are allowed.'}), 400

        # Save uploaded file
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        unique_filename = f"{timestamp}_{filename}"
        filepath = app.config['UPLOAD_FOLDER'] / unique_filename

        file.save(str(filepath))

        # Import and validate CSV
        importer = SpiderFootCSVImporter()
        importer.load_csv(str(filepath))

        # Return summary data
        summary = importer.get_summary()

        return jsonify({
            'success': True,
            'filename': unique_filename,
            'summary': summary
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/analyze', methods=['POST'])
def analyze_data():
    """Analyze uploaded CSV file."""
    try:
        data = request.get_json()
        filename = data.get('filename')

        if not filename:
            return jsonify({'error': 'No filename provided'}), 400

        filepath = app.config['UPLOAD_FOLDER'] / filename

        if not filepath.exists():
            return jsonify({'error': 'File not found'}), 404

        # Import CSV
        importer = SpiderFootCSVImporter()
        result = importer.load_csv(str(filepath))

        # Apply filters if provided
        filtered_data = result['data']
        filters = data.get('filters', {})

        if filters.get('event_types'):
            filtered_data = [
                row for row in filtered_data
                if row.get('Type') in filters['event_types']
            ]

        if filters.get('search'):
            search_term = filters['search'].lower()
            filtered_data = [
                row for row in filtered_data
                if any(search_term in str(v).lower() for v in row.values())
            ]

        # Analyze data
        analyzer = SpiderFootAnalyzer(filtered_data)
        analysis = analyzer.generate_full_analysis()
        recommendations = analyzer.get_recommendations()

        analysis['recommendations'] = recommendations

        return jsonify({
            'success': True,
            'analysis': analysis
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/generate_report', methods=['POST'])
def generate_report():
    """Generate PDF report and visualizations."""
    try:
        data = request.get_json()
        filename = data.get('filename')
        options = data.get('options', {})

        if not filename:
            return jsonify({'error': 'No filename provided'}), 400

        filepath = app.config['UPLOAD_FOLDER'] / filename

        if not filepath.exists():
            return jsonify({'error': 'File not found'}), 404

        # Import and analyze
        importer = SpiderFootCSVImporter()
        result = importer.load_csv(str(filepath))

        analyzer = SpiderFootAnalyzer(result['data'])
        analysis = analyzer.generate_full_analysis()

        # Generate reports
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_dir = app.config['REPORTS_FOLDER'] / timestamp
        report_dir.mkdir(exist_ok=True)

        enable_web_research = options.get('enable_web_research') if 'enable_web_research' in options else None

        generator = ReportGenerator(
            analysis,
            str(report_dir),
            source_records=result['data'],
            enable_llm=True,
            enable_web_research=enable_web_research
        )

        generated_files = {}

        # Generate charts if requested
        if options.get('generate_charts', True):
            try:
                charts = generator.generate_all_charts()
                generated_files['charts'] = [str(Path(c).name) for c in charts]
            except ImportError:
                generated_files['charts_error'] = 'matplotlib not installed'

        # Generate PDF if requested
        if options.get('generate_pdf', True):
            try:
                pdf_paths = generator.generate_dual_pdf_reports()
                generated_files['pdf_intelligence'] = str(Path(pdf_paths['pdf_intelligence']).name)
                generated_files['pdf_narrative'] = str(Path(pdf_paths['pdf_narrative']).name)
            except ImportError:
                generated_files['pdf_error'] = 'reportlab not installed'

        # Generate JSON
        web_summary = generator.export_web_research()
        if web_summary:
            generated_files['web_research'] = str(Path(web_summary).name)

        json_path = generator.export_json_report()
        generated_files['json'] = str(Path(json_path).name)

        # AI narrative artefacts (optional)
        ai_payload = None
        llm_markdown = generator.export_llm_markdown()
        if llm_markdown:
            generated_files['llm_markdown'] = str(Path(llm_markdown).name)
            ai_payload = generator.get_llm_report_payload()

        llm_status = generator.get_llm_status()
        if llm_status.get('error'):
            app.logger.warning("LLM report generation issue: %s", llm_status['error'])
        return jsonify({
            'success': True,
            'report_id': timestamp,
            'files': generated_files,
            'ai_report': ai_payload,
            'web_research': generator.get_web_research_results(),
            'llm_status': llm_status,
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/download/<report_id>/<filename>')
def download_file(report_id, filename):
    """Download generated report file."""
    try:
        filepath = _resolve_report_file(report_id, filename)

        return send_file(
            str(filepath),
            as_attachment=True,
            download_name=filename
        )

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/preview/<report_id>/<filename>')
def preview_file(report_id, filename):
    """Provide inline previews for generated artefacts when possible."""

    try:
        filepath = _resolve_report_file(report_id, filename)
    except FileNotFoundError:
        return jsonify({'error': 'File not found'}), 404
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400

    extension = filepath.suffix.lower()

    if extension in TEXT_PREVIEW_EXTENSIONS:
        try:
            file_size = filepath.stat().st_size
            truncated = file_size > MAX_TEXT_PREVIEW_BYTES

            if truncated:
                with filepath.open('r', encoding='utf-8', errors='replace') as handle:
                    content = handle.read(MAX_TEXT_PREVIEW_BYTES)
                content = content.rstrip()
                content += "\n\n[Preview truncated. File size exceeds preview limit.]\n"
            else:
                content = filepath.read_text(encoding='utf-8', errors='replace')

            if extension == '.json' and not truncated:
                try:
                    parsed = json.loads(content)
                    content = json.dumps(parsed, indent=2, ensure_ascii=False)
                except json.JSONDecodeError:
                    pass

            return jsonify({
                'success': True,
                'report_id': report_id,
                'filename': filename,
                'extension': extension.lstrip('.'),
                'content': content,
                'truncated': truncated,
            })
        except OSError as exc:
            return jsonify({'error': f'Failed to read file: {exc}'}), 500

    if extension in INLINE_IMAGE_EXTENSIONS:
        mimetype = None
        if extension == '.svg':
            mimetype = 'image/svg+xml'
        return send_file(str(filepath), as_attachment=False, download_name=filename, mimetype=mimetype)

    if extension in INLINE_PDF_EXTENSIONS:
        return send_file(str(filepath), as_attachment=False, download_name=filename)

    return jsonify({'error': 'Preview not supported for this file type.'}), 415


@app.route('/health')
def health():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'version': '1.0.0'
    })


if __name__ == '__main__':
    # Check for required optional dependencies without importing heavy modules
    missing_deps = []
    for dep in ('matplotlib', 'reportlab'):
        if importlib.util.find_spec(dep) is None:  # type: ignore[attr-defined]
            missing_deps.append(dep)

    if missing_deps:
        print("\n⚠️  Warning: Optional dependencies missing:")
        for dep in missing_deps:
            print(f"   - {dep}")
        print("\nInstall with: pip install " + " ".join(missing_deps))
        print("\nThe app will work but some features may be limited.\n")

    print("=" * 70)
    print("SpiderFoot TOC/Corruption Web Application")
    print("=" * 70)
    print("\nStarting server...")
    print("Access the web interface at: http://localhost:5000")
    print("\nPress Ctrl+C to stop the server")
    print("=" * 70)

    app.run(debug=True, host='0.0.0.0', port=5000)
