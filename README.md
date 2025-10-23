# SpiderFoot TOC/Corruption Plugin Pack

A comprehensive SpiderFoot plugin pack focused on detecting indicators of corruption and threat of compromise (TOC) across various data sources.

## Overview

This plugin pack extends SpiderFoot's OSINT capabilities to identify potential corruption indicators and threats of compromise in your investigations. It analyzes various data types including email addresses, domains, IP addresses, and content from leak sites and breach data.

## Features

- **Corruption Detection**: Identifies keywords and patterns associated with corruption, fraud, bribery, and other financial crimes
- **Threat of Compromise Detection**: Detects indicators of system compromise, data breaches, and malicious activity
- **Multi-Source Analysis**: Processes data from emails, domains, IP addresses, and dark web mentions
- **Configurable Sensitivity**: Adjustable detection thresholds to balance false positives and detection accuracy
- **Risk Scoring**: Categorizes findings based on risk level and confidence

## Installation

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

1. Start SpiderFoot and navigate to the web interface
2. Create a new scan
3. Select "TOC/Corruption Detector" from the available modules
4. Configure the module options as needed
5. Start the scan

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
https://github.com/Watchman8925/Spiderfoot-Processor