#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Example usage of SpiderFoot Data Processor Python API

This script demonstrates how to use the processor components
programmatically in your own Python applications.
"""

from processor.csv_importer import SpiderFootCSVImporter
from processor.analyzer import SpiderFootAnalyzer
from processor.report_generator import ReportGenerator


def example_basic_processing(csv_path):
    """
    Example 1: Basic CSV processing and analysis.

    Args:
        csv_path: Path to SpiderFoot CSV export
    """
    print("Example 1: Basic Processing")
    print("-" * 50)

    # Import CSV
    importer = SpiderFootCSVImporter()
    result = importer.load_csv(csv_path)

    print(f"Loaded {result['stats']['total_records']} records")
    print(f"Event types: {len(result['stats']['event_types'])}")
    print(f"Corruption indicators: {result['stats']['corruption_indicators']}")
    print(f"TOC indicators: {result['stats']['toc_indicators']}")
    print()


def example_filtering_and_export(csv_path):
    """
    Example 2: Filter data and export to new CSV.

    Args:
        csv_path: Path to SpiderFoot CSV export
    """
    print("Example 2: Filtering and Export")
    print("-" * 50)

    # Import and filter
    importer = SpiderFootCSVImporter()
    importer.load_csv(csv_path)

    # Get only corruption indicators
    corruption_data = importer.filter_corruption_indicators()
    print(f"Found {len(corruption_data)} corruption indicators")

    # Export to new CSV
    if corruption_data:
        importer.export_filtered(corruption_data, 'corruption_only.csv')
        print("Exported to corruption_only.csv")

    print()


def example_analysis(csv_path):
    """
    Example 3: Perform detailed analysis.

    Args:
        csv_path: Path to SpiderFoot CSV export
    """
    print("Example 3: Detailed Analysis")
    print("-" * 50)

    # Import data
    importer = SpiderFootCSVImporter()
    result = importer.load_csv(csv_path)

    # Analyze
    analyzer = SpiderFootAnalyzer(result['data'])
    analysis = analyzer.generate_full_analysis()

    # Display results
    print("Analysis Results:")
    print(f"  Total events: {analysis['event_distribution']['total_events']}")
    print(f"  Unique event types: {analysis['event_distribution']['unique_event_types']}")
    print(f"  Corruption indicators: {analysis['corruption_patterns']['total_indicators']}")
    print(f"  TOC indicators: {analysis['toc_patterns']['total_indicators']}")
    print(f"  High-risk domains: {analysis['risk_domains']['total_risk_domains']}")

    # Get recommendations
    recommendations = analyzer.get_recommendations()
    print("\nRecommendations:")
    for i, rec in enumerate(recommendations, 1):
        print(f"  {i}. {rec}")

    print()


def example_report_generation(csv_path):
    """
    Example 4: Generate visualizations and PDF report.

    Args:
        csv_path: Path to SpiderFoot CSV export
    """
    print("Example 4: Report Generation")
    print("-" * 50)

    # Import and analyze
    importer = SpiderFootCSVImporter()
    result = importer.load_csv(csv_path)

    analyzer = SpiderFootAnalyzer(result['data'])
    analysis = analyzer.generate_full_analysis()

    # Generate reports
    generator = ReportGenerator(analysis, output_dir='./example_reports')

    # Generate charts
    try:
        charts = generator.generate_all_charts()
        print(f"Generated {len(charts)} charts:")
        for chart in charts:
            print(f"  - {chart}")
    except ImportError as e:
        print(f"Could not generate charts: {e}")
        print("Install matplotlib: pip install matplotlib")

    # Generate PDF
    try:
        pdf_path = generator.generate_pdf_report()
        print(f"Generated PDF report: {pdf_path}")
    except ImportError as e:
        print(f"Could not generate PDF: {e}")
        print("Install reportlab: pip install reportlab")

    # Generate JSON
    json_path = generator.export_json_report()
    print(f"Generated JSON export: {json_path}")

    print()


def example_search_and_filter(csv_path):
    """
    Example 5: Search and filter data.

    Args:
        csv_path: Path to SpiderFoot CSV export
    """
    print("Example 5: Search and Filter")
    print("-" * 50)

    # Import data
    importer = SpiderFootCSVImporter()
    importer.load_csv(csv_path)

    # Search for keyword
    malware_results = importer.search_data('malware')
    print(f"Found {len(malware_results)} records mentioning 'malware'")

    # Filter by multiple event types
    threat_data = importer.filter_by_type([
        'TOC_INDICATOR',
        'HIGH_RISK_DOMAIN',
        'COMPROMISED_ASSET'
    ])
    print(f"Found {len(threat_data)} threat-related records")

    # Filter by module
    plugin_data = importer.filter_by_module(['sfp_toc_corruption'])
    print(f"Found {len(plugin_data)} records from TOC/Corruption plugin")

    print()


if __name__ == '__main__':
    import sys

    if len(sys.argv) < 2:
        print("Usage: python example_usage.py <csv_file>")
        print("\nThis script demonstrates the SpiderFoot Data Processor API.")
        print("Provide a SpiderFoot CSV export file to see examples in action.")
        sys.exit(1)

    csv_file = sys.argv[1]

    print("=" * 70)
    print("SpiderFoot Data Processor - Example Usage")
    print("=" * 70)
    print()

    try:
        # Run all examples
        example_basic_processing(csv_file)
        example_filtering_and_export(csv_file)
        example_analysis(csv_file)
        example_search_and_filter(csv_file)
        example_report_generation(csv_file)

        print("=" * 70)
        print("All examples completed!")
        print("Check the current directory and ./example_reports for outputs.")
        print("=" * 70)

    except FileNotFoundError:
        print(f"Error: CSV file not found: {csv_file}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
