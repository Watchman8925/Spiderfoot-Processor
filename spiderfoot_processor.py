#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         spiderfoot_processor
# Purpose:      Command-line tool to process SpiderFoot CSV exports
#
# Author:       Watchman8925
#
# Created:      2025
# License:      MIT
# -------------------------------------------------------------------------------

import argparse
import sys
from pathlib import Path

from processor.csv_importer import SpiderFootCSVImporter
from processor.analyzer import SpiderFootAnalyzer
from processor.report_generator import ReportGenerator


def main():
    """Main entry point for the SpiderFoot Processor CLI."""
    parser = argparse.ArgumentParser(
        description='Process SpiderFoot CSV exports with analysis and reporting',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Process a CSV file and generate all reports
  python spiderfoot_processor.py input.csv

  # Process with custom output directory
  python spiderfoot_processor.py input.csv -o ./my_reports

  # Generate only PDF report
  python spiderfoot_processor.py input.csv --pdf-only

  # Generate only charts
  python spiderfoot_processor.py input.csv --charts-only

  # Filter and export specific event types
  python spiderfoot_processor.py input.csv --filter-type CORRUPTION_INDICATOR -e filtered.csv
        """
    )

    parser.add_argument('input_csv', help='Path to SpiderFoot CSV export file')
    parser.add_argument('-o', '--output-dir', default='./reports',
                       help='Output directory for reports (default: ./reports)')
    parser.add_argument('-e', '--export-filtered', metavar='OUTPUT_CSV',
                       help='Export filtered data to CSV file')
    parser.add_argument('--filter-type', nargs='+', metavar='TYPE',
                       help='Filter by event type(s)')
    parser.add_argument('--filter-module', nargs='+', metavar='MODULE',
                       help='Filter by module(s)')
    parser.add_argument('--search', metavar='KEYWORD',
                       help='Search for keyword in data')
    parser.add_argument('--pdf-only', action='store_true',
                       help='Generate only PDF report (skip charts)')
    parser.add_argument('--charts-only', action='store_true',
                       help='Generate only charts (skip PDF)')
    parser.add_argument('--json', action='store_true',
                       help='Export analysis as JSON')
    parser.add_argument('--summary', action='store_true',
                       help='Display summary statistics only')
    parser.add_argument('--no-reports', action='store_true',
                       help='Skip report generation (only import and analyze)')

    args = parser.parse_args()

    # Validate input file
    input_path = Path(args.input_csv)
    if not input_path.exists():
        print(f"Error: Input file not found: {args.input_csv}")
        sys.exit(1)

    print("=" * 70)
    print("SpiderFoot Data Processor")
    print("=" * 70)
    print()

    # Step 1: Import CSV
    print(f"[1/4] Importing CSV file: {args.input_csv}")
    try:
        importer = SpiderFootCSVImporter()
        result = importer.load_csv(str(input_path))
        print(f"✓ Loaded {result['stats']['total_records']} records")
        print()
    except Exception as e:
        print(f"✗ Error importing CSV: {e}")
        sys.exit(1)

    # Apply filters if specified
    data_to_analyze = importer.get_data()

    if args.filter_type:
        print(f"Filtering by event type(s): {', '.join(args.filter_type)}")
        data_to_analyze = importer.filter_by_type(args.filter_type)
        print(f"✓ Filtered to {len(data_to_analyze)} records")
        print()

    if args.filter_module:
        print(f"Filtering by module(s): {', '.join(args.filter_module)}")
        data_to_analyze = importer.filter_by_module(args.filter_module)
        print(f"✓ Filtered to {len(data_to_analyze)} records")
        print()

    if args.search:
        print(f"Searching for keyword: {args.search}")
        data_to_analyze = importer.search_data(args.search)
        print(f"✓ Found {len(data_to_analyze)} matching records")
        print()

    # Export filtered data if requested
    if args.export_filtered:
        if not data_to_analyze:
            print("Warning: No data to export after filtering")
        else:
            try:
                importer.export_filtered(data_to_analyze, args.export_filtered)
                print(f"✓ Exported filtered data to: {args.export_filtered}")
                print()
            except Exception as e:
                print("✗ Error exporting filtered data: {}".format(e))

    # Display summary if requested
    if args.summary:
        summary = importer.get_summary()
        print("\n" + "=" * 70)
        print("SUMMARY STATISTICS")
        print("=" * 70)
        print(f"Total Records: {summary['total_records']}")
        print(f"Event Types: {summary['event_types_count']}")
        print(f"Modules: {summary['modules_count']}")
        print(f"Corruption Indicators: {summary['corruption_indicators']}")
        print(f"TOC Indicators: {summary['toc_indicators']}")
        print()

        print("Top Event Types:")
        for event_type, count in sorted(summary['event_types'].items(),
                                       key=lambda x: x[1], reverse=True)[:10]:
            print(f"  {event_type}: {count}")
        print()

        if args.no_reports:
            sys.exit(0)

    # Step 2: Analyze data
    print("[2/4] Analyzing data...")
    try:
        analyzer = SpiderFootAnalyzer(data_to_analyze)
        analysis = analyzer.generate_full_analysis()
        print("✓ Analysis complete")
        print()
    except Exception as e:
        print("✗ Error analyzing data: {}".format(e))
        sys.exit(1)

    if args.no_reports:
        print("Skipping report generation as requested")
        sys.exit(0)

    # Step 3: Generate reports
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"[3/4] Generating reports in: {args.output_dir}")

    generator = ReportGenerator(analysis, str(output_dir))

    # Generate charts
    if not args.pdf_only:
        print("  → Generating charts...")
        try:
            charts = generator.generate_all_charts()
            if charts:
                print(f"  ✓ Generated {len(charts)} chart(s)")
                for chart in charts:
                    print(f"    - {Path(chart).name}")
            else:
                print("  ! No charts generated (data may be insufficient)")
        except ImportError as e:
            print(f"  ! Could not generate charts: {e}")
            print("  ! Install matplotlib: pip install matplotlib")
        except Exception as e:
            print(f"  ✗ Error generating charts: {e}")

    # Generate PDF
    if not args.charts_only:
        print("  → Generating PDF report...")
        try:
            pdf_path = generator.generate_pdf_report()
            print(f"  ✓ PDF report: {Path(pdf_path).name}")
        except ImportError as e:
            print("  ! Could not generate PDF: {}".format(e))
            print("  ! Install reportlab: pip install reportlab")
        except Exception as e:
            print(f"  ✗ Error generating PDF: {e}")

    # Generate JSON if requested
    if args.json:
        print("  → Generating JSON export...")
        try:
            json_path = generator.export_json_report()
            print(f"  ✓ JSON export: {Path(json_path).name}")
        except Exception as e:
            print(f"  ✗ Error generating JSON: {e}")

    print()

    # Step 4: Display key findings
    print("[4/4] Key Findings:")
    print("-" * 70)

    corruption = analysis.get('corruption_patterns', {})
    toc = analysis.get('toc_patterns', {})
    risk_domains = analysis.get('risk_domains', {})
    compromised = analysis.get('compromised_assets', {})

    print(f"Corruption Indicators: {corruption.get('total_indicators', 0)}")
    print(f"TOC Indicators: {toc.get('total_indicators', 0)}")
    print(f"High-Risk Domains: {risk_domains.get('total_risk_domains', 0)}")
    print(f"Compromised Assets: {compromised.get('total_compromised', 0)}")
    print()

    # Display recommendations
    print("Recommendations:")
    recommendations = analyzer.get_recommendations()
    for i, rec in enumerate(recommendations, 1):
        print(f"{i}. {rec}")

    print()
    print("=" * 70)
    print("Processing complete!")
    print(f"Reports saved to: {args.output_dir}")
    print("=" * 70)


if __name__ == '__main__':
    main()
