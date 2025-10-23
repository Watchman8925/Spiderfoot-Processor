# SpiderFoot Data Processor Guide

This guide explains how to use the SpiderFoot Data Processor to analyze CSV exports, generate visualizations, and create PDF reports.

## Table of Contents
- [Overview](#overview)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Features](#features)
- [Command-Line Options](#command-line-options)
- [Examples](#examples)
- [Output Files](#output-files)
- [Troubleshooting](#troubleshooting)

## Overview

The SpiderFoot Data Processor is a powerful tool that allows you to:
1. **Import** SpiderFoot CSV export files
2. **Analyze** the data for patterns and insights
3. **Visualize** findings with charts and graphs
4. **Generate** professional PDF reports

## Installation

### Basic Installation

```bash
# Clone the repository
git clone https://github.com/Watchman8925/Spiderfoot-Processor.git
cd Spiderfoot-Processor

# Install base requirements
pip install -r requirements.txt
```

### Full Installation (with visualization and PDF support)

```bash
# Install all dependencies
pip install matplotlib reportlab

# Or install from requirements.txt (already includes these)
pip install -r requirements.txt
```

## Quick Start

### Step 1: Export Data from SpiderFoot

1. In SpiderFoot, go to your completed scan
2. Click "Export" and choose "CSV" format
3. Save the file (e.g., `spiderfoot_scan.csv`)

### Step 2: Process the CSV File

```bash
# Basic processing - generates all reports
python spiderfoot_processor.py spiderfoot_scan.csv

# View summary first
python spiderfoot_processor.py spiderfoot_scan.csv --summary
```

### Step 3: Review Generated Reports

Check the `./reports` directory for:
- PNG charts (event distribution, module activity, threat overview)
- PDF report with comprehensive analysis
- Optional JSON export with raw analysis data

## Features

### 1. CSV Import and Validation

The processor can load SpiderFoot CSV exports and validate the data:

```bash
python spiderfoot_processor.py your_export.csv --summary
```

### 2. Data Filtering

Filter data by event types, modules, or keywords:

```bash
# Filter by event type
python spiderfoot_processor.py your_export.csv --filter-type CORRUPTION_INDICATOR

# Filter by multiple types
python spiderfoot_processor.py your_export.csv --filter-type CORRUPTION_INDICATOR TOC_INDICATOR

# Filter by module
python spiderfoot_processor.py your_export.csv --filter-module sfp_toc_corruption

# Search for keywords
python spiderfoot_processor.py your_export.csv --search "malware"
```

### 3. Data Analysis

Automatic analysis includes:
- Event distribution statistics
- Module activity analysis
- Corruption pattern detection
- TOC indicator analysis
- High-risk domain identification
- Compromised asset detection
- Timeline generation (if timestamps available)

### 4. Visualization

Generate charts showing:
- **Event Distribution**: Pie chart of event types
- **Module Activity**: Bar chart of most active modules
- **Threat Overview**: Bar chart of key threat indicators

```bash
# Generate only charts
python spiderfoot_processor.py your_export.csv --charts-only
```

### 5. PDF Report Generation

Create comprehensive PDF reports with:
- Executive summary
- Visual charts
- Detailed findings
- Recommendations

```bash
# Generate only PDF
python spiderfoot_processor.py your_export.csv --pdf-only
```

### 6. Data Export

Export filtered or analyzed data:

```bash
# Export filtered data to new CSV
python spiderfoot_processor.py your_export.csv --filter-type HIGH_RISK_DOMAIN -e high_risk_only.csv

# Export analysis as JSON
python spiderfoot_processor.py your_export.csv --json
```

## Command-Line Options

### Input/Output Options

- `input_csv` - Path to SpiderFoot CSV export (required)
- `-o, --output-dir DIR` - Output directory for reports (default: ./reports)
- `-e, --export-filtered FILE` - Export filtered data to CSV file

### Filtering Options

- `--filter-type TYPE [TYPE ...]` - Filter by event type(s)
- `--filter-module MODULE [MODULE ...]` - Filter by module(s)
- `--search KEYWORD` - Search for keyword in data

### Report Options

- `--pdf-only` - Generate only PDF report (skip charts)
- `--charts-only` - Generate only charts (skip PDF)
- `--json` - Export analysis as JSON
- `--summary` - Display summary statistics only
- `--no-reports` - Skip report generation

## Examples

### Example 1: Basic Analysis

Process a CSV file and generate all reports:

```bash
python spiderfoot_processor.py spiderfoot_scan_20251023.csv
```

**Output:**
- `./reports/event_distribution.png`
- `./reports/module_activity.png`
- `./reports/threat_overview.png`
- `./reports/report_20251023_103000.pdf`

### Example 2: Focus on Corruption Indicators

Filter and analyze only corruption indicators:

```bash
python spiderfoot_processor.py spiderfoot_scan.csv \
  --filter-type CORRUPTION_INDICATOR \
  -o ./corruption_reports \
  -e corruption_indicators.csv
```

### Example 3: Security Threat Analysis

Analyze TOC indicators and high-risk domains:

```bash
python spiderfoot_processor.py spiderfoot_scan.csv \
  --filter-type TOC_INDICATOR HIGH_RISK_DOMAIN HIGH_RISK_IPADDR \
  -o ./security_analysis
```

### Example 4: Search for Specific Threats

Search for malware-related findings:

```bash
python spiderfoot_processor.py spiderfoot_scan.csv \
  --search "malware" \
  -o ./malware_findings \
  -e malware_results.csv
```

### Example 5: Quick Summary

Get a quick overview without generating reports:

```bash
python spiderfoot_processor.py spiderfoot_scan.csv --summary --no-reports
```

### Example 6: Custom Report Directory

Save reports to a specific location:

```bash
python spiderfoot_processor.py spiderfoot_scan.csv \
  -o /path/to/investigation_2025/reports
```

### Example 7: Generate Only Visualizations

Create charts without PDF:

```bash
python spiderfoot_processor.py spiderfoot_scan.csv --charts-only
```

### Example 8: Machine-Readable Output

Export analysis results as JSON for integration with other tools:

```bash
python spiderfoot_processor.py spiderfoot_scan.csv --json -o ./json_exports
```

## Output Files

### Charts (PNG format)

1. **event_distribution.png**
   - Pie chart showing distribution of event types
   - Helps identify what types of findings are most common

2. **module_activity.png**
   - Bar chart of module activity
   - Shows which SpiderFoot modules generated the most events

3. **threat_overview.png**
   - Bar chart of key threat metrics
   - Displays corruption indicators, TOC indicators, high-risk domains, and compromised assets

### PDF Report

The PDF report includes:

1. **Title Page**
   - Report title and generation timestamp
   - Basic metadata

2. **Executive Summary**
   - Key statistics table
   - High-level overview

3. **Visual Analysis**
   - All generated charts
   - Visual representation of findings

4. **Detailed Findings**
   - Corruption patterns analysis
   - TOC patterns analysis
   - Risk domain analysis

5. **Recommendations**
   - Actionable recommendations based on findings
   - Prioritized by severity

### JSON Export (optional)

Machine-readable analysis results including:
- Complete statistics
- Event distributions
- Module activity
- Corruption and TOC patterns
- Risk assessments
- Timeline data (if available)

### Filtered CSV (optional)

When using `--export-filtered`, creates a new CSV file with:
- Only the filtered records
- Same format as input CSV
- Can be re-imported into SpiderFoot or other tools

## Troubleshooting

### Issue: "No module named 'matplotlib'"

**Solution:**
```bash
pip install matplotlib
```

### Issue: "No module named 'reportlab'"

**Solution:**
```bash
pip install reportlab
```

### Issue: Charts not generated

**Possible causes:**
- matplotlib not installed
- Insufficient data for visualization

**Solution:**
- Install matplotlib: `pip install matplotlib`
- Ensure your CSV has enough data (at least a few records)

### Issue: PDF generation fails

**Possible causes:**
- reportlab not installed
- Permission issues in output directory

**Solution:**
- Install reportlab: `pip install reportlab`
- Check output directory permissions
- Try a different output directory with `-o`

### Issue: "No data to export after filtering"

**Cause:** Filters removed all records

**Solution:**
- Check your filter criteria
- Verify the event types in your CSV with `--summary`
- Try broader filters or no filters

### Issue: Large CSV files take a long time

**Solution:**
- Process large files in stages with filters
- Use `--no-reports` first to just validate import
- Consider splitting the CSV file

### Issue: Unicode or encoding errors

**Solution:**
The importer handles encoding issues automatically, but if problems persist:
- Ensure your CSV is UTF-8 encoded
- Check for corrupted data in the CSV

## Advanced Usage

### Using the Python API

You can also use the processor components in your own Python scripts:

```python
from processor.csv_importer import SpiderFootCSVImporter
from processor.analyzer import SpiderFootAnalyzer
from processor.report_generator import ReportGenerator

# Import CSV
importer = SpiderFootCSVImporter()
result = importer.load_csv('spiderfoot_export.csv')

# Analyze data
analyzer = SpiderFootAnalyzer(result['data'])
analysis = analyzer.generate_full_analysis()

# Generate reports
generator = ReportGenerator(analysis, output_dir='./my_reports')
generator.generate_all_charts()
pdf_path = generator.generate_pdf_report()

print(f"Report generated: {pdf_path}")
```

### Batch Processing

Process multiple CSV files:

```bash
#!/bin/bash
for csv_file in scans/*.csv; do
    echo "Processing $csv_file"
    python spiderfoot_processor.py "$csv_file" -o "reports/$(basename $csv_file .csv)"
done
```

### Integration with CI/CD

Use in automated workflows:

```bash
# Process scan results and check for critical findings
python spiderfoot_processor.py scan_results.csv --json -o ./reports

# Parse JSON and fail if critical issues found
# (Add your own logic here based on the JSON output)
```

## Tips and Best Practices

1. **Start with --summary**: Always review summary statistics first to understand your data
2. **Use filters wisely**: Narrow down to specific event types for focused analysis
3. **Save filtered data**: Export filtered results to CSV for sharing or further analysis
4. **Organize outputs**: Use `-o` to create separate directories for different analyses
5. **Keep raw data**: Always keep your original CSV files for reference
6. **Regular reports**: Generate periodic reports to track trends over time
7. **Share PDFs**: PDF reports are great for sharing with stakeholders who don't need raw data

## Support

For issues or questions:
- Open an issue on GitHub: https://github.com/Watchman8925/Spiderfoot-Processor/issues
- Check EXAMPLES.md for more usage scenarios
- See README.md for general documentation

## Next Steps

- Try processing your SpiderFoot exports
- Experiment with different filters and search terms
- Customize the analysis for your specific needs
- Integrate with your investigation workflows

Happy analyzing! 🔍
