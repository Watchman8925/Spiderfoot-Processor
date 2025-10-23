#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SpiderFoot TOC/Corruption Web Application

A modern web interface for processing SpiderFoot CSV exports,
generating visualizations, and creating PDF reports.
"""

import os
import sys
from pathlib import Path
from datetime import datetime
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for

# Add processor to path
sys.path.insert(0, os.path.dirname(__file__))

from processor.csv_importer import SpiderFootCSVImporter
from processor.analyzer import SpiderFootAnalyzer
from processor.report_generator import ReportGenerator

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size
app.config['UPLOAD_FOLDER'] = Path('uploads')
app.config['REPORTS_FOLDER'] = Path('reports')

# Ensure folders exist
app.config['UPLOAD_FOLDER'].mkdir(exist_ok=True)
app.config['REPORTS_FOLDER'].mkdir(exist_ok=True)

ALLOWED_EXTENSIONS = {'csv'}


def allowed_file(filename):
    """Check if file has allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/')
def index():
    """Render the main page."""
    return render_template('index.html')


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
        result = importer.load_csv(str(filepath))

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

        generator = ReportGenerator(analysis, str(report_dir))

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
                pdf_path = generator.generate_pdf_report()
                generated_files['pdf'] = str(Path(pdf_path).name)
            except ImportError:
                generated_files['pdf_error'] = 'reportlab not installed'

        # Generate JSON
        json_path = generator.export_json_report()
        generated_files['json'] = str(Path(json_path).name)

        return jsonify({
            'success': True,
            'report_id': timestamp,
            'files': generated_files
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/download/<report_id>/<filename>')
def download_file(report_id, filename):
    """Download generated report file."""
    try:
        filepath = app.config['REPORTS_FOLDER'] / report_id / filename

        if not filepath.exists():
            return jsonify({'error': 'File not found'}), 404

        return send_file(
            str(filepath),
            as_attachment=True,
            download_name=filename
        )

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/health')
def health():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'version': '1.0.0'
    })


if __name__ == '__main__':
    # Check for required dependencies
    missing_deps = []

    try:
        import matplotlib
    except ImportError:
        missing_deps.append('matplotlib')

    try:
        import reportlab
    except ImportError:
        missing_deps.append('reportlab')

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
    print(f"Access the web interface at: http://localhost:5000")
    print("\nPress Ctrl+C to stop the server")
    print("=" * 70)

    app.run(debug=True, host='0.0.0.0', port=5000)
