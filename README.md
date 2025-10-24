# SpiderFoot TOC/Corruption Plugin Pack

A comprehensive SpiderFoot plugin pack focused on detecting indicators of corruption and threat of compromise (TOC) across various data sources.

**🆕 NEW: CSV Processor with Visualization and PDF Reports!**
Now includes a powerful data processor that can import SpiderFoot CSV exports, analyze patterns, generate charts, and create professional PDF reports.

## Overview

This plugin pack extends SpiderFoot's OSINT capabilities to identify potential corruption indicators and threats of compromise in your investigations. It analyzes various data types including email addresses, domains, IP addresses, and content from leak sites and breach data.

## Features

### SpiderFoot Plugin
- **Corruption Detection**: Identifies keywords and patterns associated with corruption, fraud, bribery, and other financial crimes
- **Threat of Compromise Detection**: Detects indicators of system compromise, data breaches, and malicious activity
- **Multi-Source Analysis**: Processes data from emails, domains, IP addresses, and dark web mentions
- **Configurable Sensitivity**: Adjustable detection thresholds to balance false positives and detection accuracy
- **Risk Scoring**: Categorizes findings based on risk level and confidence

### Data Processor (NEW!)
- **CSV Import**: Upload and process SpiderFoot CSV export files
- **Advanced Analysis**: Analyze patterns, trends, and correlations in your data
- **Visualization**: Generate charts and graphs for better insights
- **PDF Reports**: Create professional intelligence and narrative exposé PDFs with findings, provenance, and recommendations
- **Filtering & Search**: Filter by event types, modules, or search for specific keywords

## Quick Start

### Web Application (NEW! 🎉)

The easiest way to use the processor - a modern web interface:

```bash
# Clone and install
git clone https://github.com/Watchman8925/Spiderfoot-Processor.git
cd Spiderfoot-Processor
pip install -r requirements.txt

# Start the web app
python web_app.py

# Open browser to http://localhost:5000
```

Features:
- 🌐 **Modern dark-themed web interface**
- 📤 **Drag-and-drop CSV upload**
- 📊 **Interactive visualizations**
- 📄 **One-click PDF report generation**
- 🔍 **Real-time analysis**

### Command-Line Tool

For CSV processing without a web browser:

```bash
# Clone and install
git clone https://github.com/Watchman8925/Spiderfoot-Processor.git
cd Spiderfoot-Processor
pip install -r requirements.txt

# Process your SpiderFoot CSV export
python spiderfoot_processor.py your_spiderfoot_export.csv

# Results will be in ./reports directory
```

## Installation

### SpiderFoot Plugin

1. Ensure you have SpiderFoot 4.0 or later installed
2. Clone this repository:
   ```bash
   git clone https://github.com/Watchman8925/Spiderfoot-Processor.git
   cd Spiderfoot-Processor
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Copy the plugin files to your SpiderFoot modules directory:
   ```bash
   cp plugins/sfp_toc_corruption.py /path/to/spiderfoot/modules/
   ```

## Configuration

The plugin can be configured through SpiderFoot's web interface or by modifying the default options:

### Available Options

- **corruption_keywords**: Keywords indicating potential corruption (default includes fraud, bribery, corruption, etc.)
- **toc_keywords**: Keywords indicating threat of compromise (default includes breach, compromise, leaked, etc.)
- **check_emails**: Enable email address analysis (default: True)
- **check_domains**: Enable domain analysis (default: True)
- **check_ips**: Enable IP address analysis (default: True)
- **sensitivity**: Detection sensitivity level - low, medium, or high (default: medium)

## Usage

### Using the SpiderFoot Plugin

1. Start SpiderFoot and navigate to the web interface
2. Create a new scan
3. Select "TOC/Corruption Detector" from the available modules
4. Configure the module options as needed
5. Start the scan

### Using the Web Application (NEW!)

The modern web interface provides the easiest way to process and analyze your data:

```bash
# Start the web server
python web_app.py

# Open http://localhost:5000 in your browser
```

**Features:**
1. **Upload**: Drag-and-drop or browse for your CSV file
2. **Analyze**: View instant statistics and insights
3. **Visualize**: Generate interactive charts automatically
4. **Report**: Download professional PDF reports
5. **Export**: Get JSON data for further processing

### Using the Data Processor (Command-Line)

Process your SpiderFoot CSV exports with advanced analysis and reporting:

```bash
# Basic usage - process CSV and generate all reports
python spiderfoot_processor.py your_spiderfoot_export.csv

# Specify output directory
python spiderfoot_processor.py your_export.csv -o ./my_reports

# View summary statistics
python spiderfoot_processor.py your_export.csv --summary

# Filter by event type
python spiderfoot_processor.py your_export.csv --filter-type CORRUPTION_INDICATOR TOC_INDICATOR

# Search for specific keywords
python spiderfoot_processor.py your_export.csv --search "malware"

# Generate only PDF report
python spiderfoot_processor.py your_export.csv --pdf-only

# Export filtered data to new CSV
python spiderfoot_processor.py your_export.csv --filter-type HIGH_RISK_DOMAIN -e high_risk_domains.csv
```

The processor will generate:

- **Charts**: Visual representations of event distribution, module activity, and threat overview
- **PDF Report**: Comprehensive report with executive summary, visualizations, detailed findings, and recommendations
- **JSON Export**: Machine-readable analysis results (optional with `--json` flag)

## AI-Assisted Reporting

Set these environment variables before launching the web app or CLI if you want the AI-generated narrative:

- `SPIDERFOOT_LLM_MODEL` and `SPIDERFOOT_LLM_API_KEY` (required)
- `SPIDERFOOT_LLM_BASE_URL`, `SPIDERFOOT_LLM_PROVIDER`, `SPIDERFOOT_LLM_ORG` (optional, provider specific)
- `SPIDERFOOT_LLM_SYSTEM_PROMPT` or `SPIDERFOOT_LLM_SYSTEM_PROMPT_FILE` to supply a custom system prompt
- `SPIDERFOOT_LLM_USER_INSTRUCTIONS` (or `_FILE`) to prepend extra guidance before the JSON payload
- `SPIDERFOOT_LLM_FALLBACK_MODEL` (with optional `_FALLBACK_SYSTEM_PROMPT`) to specify a backup model if the primary fails
- `SPIDERFOOT_LLM_MAX_SAMPLE_RECORDS` to control how many raw records are shared with the model (default 50)

The processor automatically passes a trimmed snapshot of the uploaded CSV along with key analysis results to the model you configure. A forensic intelligence prompt is preloaded by default; you can override it via the variables above. When no API credentials are provided (or the remote call fails), the system falls back to an embedded narrative engine that still produces provenance-backed reports—so AI output is available even in fully offline environments.

### Optional Web Research Enrichment

Some investigations benefit from quick open-source context on high-priority findings. The processor now includes an optional enrichment pass that performs throttled DuckDuckGo lookups for the most salient domains, IP addresses, and entity strings found in your dataset. Results are stored in `web_research_*.json`, fed into the AI narrative, and surfaced in the web UI downloads panel.

- Enable at runtime via the CLI flag `--enable-web-research`, the web UI checkbox “Enrich with Web Research,” or by exporting `SPIDERFOOT_WEB_SEARCH_ENABLED=true`.
- Fine-tune behaviour with:
   - `SPIDERFOOT_WEB_SEARCH_PROVIDER` (currently `duckduckgo`)
   - `SPIDERFOOT_WEB_SEARCH_TIMEOUT` (seconds, default 10)
   - `SPIDERFOOT_WEB_SEARCH_MAX_RESULTS` (per query, default 3)
   - `SPIDERFOOT_WEB_SEARCH_MAX_QUERIES` (overall cap, default 8)
   - `SPIDERFOOT_WEB_SEARCH_THROTTLE_SECONDS` (delay between queries, default 1.0)
   - `SPIDERFOOT_WEB_SEARCH_USER_AGENT` (custom user-agent string)

⚠️ This feature is off by default to preserve offline operation. When enabled it requires outbound HTTPS access and adheres to the configured throttling limits to avoid hammering remote services.

### Event Types Processed

The plugin watches for these SpiderFoot event types:

- `EMAILADDR` - Email addresses
- `DOMAIN_NAME` - Domain names
- `IP_ADDRESS` - IP addresses
- `AFFILIATE_EMAILADDR` - Affiliated email addresses
- `AFFILIATE_DOMAIN_NAME` - Affiliated domains
- `AFFILIATE_IPADDR` - Affiliated IP addresses
- `LEAK_SITE` - Data from leak sites
- `BREACH_DATA` - Breach data
- `DARKNET_MENTION` - Dark web mentions

### Event Types Produced

The plugin generates these event types:

- `CORRUPTION_INDICATOR` - Detected corruption indicators
- `TOC_INDICATOR` - Threat of compromise indicators
- `MALICIOUS_AFFILIATE` - Potentially malicious affiliates
- `COMPROMISED_ASSET` - Assets showing signs of compromise
- `HIGH_RISK_DOMAIN` - High-risk domains
- `HIGH_RISK_IPADDR` - High-risk IP addresses

## Examples

### Example 1: Investigating a Domain

When analyzing a domain, the plugin will:

- Check for suspicious TLDs (e.g., .xyz, .tk)
- Identify potential phishing terms (e.g., "secure", "login", "verify")
- Analyze associated content for corruption/TOC keywords

### Example 2: Processing Breach Data

When processing breach data, the plugin will:

- Scan content for corruption-related keywords
- Identify threat of compromise indicators
- Generate appropriate events for downstream processing

## Development

### Running Tests

```bash
python -m pytest tests/
```

### Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

Watchman8925

## Disclaimer

This tool is for legitimate security research and OSINT investigations only. Users are responsible for ensuring their use complies with applicable laws and regulations.

## Support

For issues, questions, or contributions, please visit:
<https://github.com/Watchman8925/Spiderfoot-Processor>
