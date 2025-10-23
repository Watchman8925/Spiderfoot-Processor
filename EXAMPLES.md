# Usage Examples

This document provides practical examples of using the SpiderFoot TOC/Corruption Plugin Pack.

## Example 1: Basic Domain Investigation

### Scenario
You want to investigate a suspicious domain for signs of corruption or compromise.

### Steps
1. Start SpiderFoot and create a new scan
2. Enter the domain name: `suspicious-site.xyz`
3. Select the "TOC/Corruption Detector" module
4. Use default settings
5. Start the scan

### Expected Output
The plugin will analyze:
- The domain's TLD (`.xyz` is flagged as suspicious)
- Associated email addresses
- Any breach data or dark web mentions
- Content for corruption/TOC keywords

## Example 2: Email Address Analysis

### Scenario
You have an email address from a data breach and want to check for compromise indicators.

### Configuration
```python
# In SpiderFoot UI, configure:
check_emails: True
sensitivity: high
```

### Input
`temp.test.throwaway@example.com`

### Expected Findings
- Suspicious pattern: "temp"
- Suspicious pattern: "test"
- Suspicious pattern: "throwaway"
- Event type: `TOC_INDICATOR`

## Example 3: Breach Data Investigation

### Scenario
You're analyzing content from a data breach to identify corruption indicators.

### Sample Content
```
The company was involved in fraud and bribery schemes.
Internal documents reveal embezzlement of funds.
```

### Expected Findings
- Corruption keyword: "fraud"
- Corruption keyword: "bribery"
- Corruption keyword: "embezzlement"
- Event type: `CORRUPTION_INDICATOR`

## Example 4: Custom Configuration

### Scenario
You want to add custom keywords specific to your investigation.

### Configuration
```yaml
# In config.yaml or SpiderFoot UI:
corruption_keywords:
  - fraud
  - bribery
  - corruption
  - embezzlement
  - kickback
  - money laundering
  - extortion
  - graft
  - custom_term_1  # Your custom keyword
  - custom_term_2  # Your custom keyword

toc_keywords:
  - breach
  - compromise
  - leaked
  - exposed
  - hacked
  - stolen
  - malware
  - ransomware
  - backdoor
  - vulnerability
  - custom_threat_1  # Your custom keyword
  - custom_threat_2  # Your custom keyword
```

## Example 5: Sensitivity Levels

### Low Sensitivity
Only reports high-confidence findings. Use when you want to minimize false positives.

```python
sensitivity: low
min_keyword_matches: 2
```

### Medium Sensitivity (Recommended)
Balanced approach for most investigations.

```python
sensitivity: medium
min_keyword_matches: 1
```

### High Sensitivity
Reports all potential indicators. Use for thorough investigations.

```python
sensitivity: high
min_keyword_matches: 1
```

## Example 6: Integration with Other Modules

The TOC/Corruption Detector works well with other SpiderFoot modules:

1. **DNS Resolution** → TOC/Corruption Detector
   - Resolves domains first
   - Then checks for corruption indicators

2. **Email Harvester** → TOC/Corruption Detector
   - Finds email addresses
   - Analyzes them for compromise patterns

3. **Breach Data Module** → TOC/Corruption Detector
   - Retrieves breach data
   - Scans for corruption/TOC keywords

## Example 7: Automated Workflow

### Python Script Example
```python
# This is a conceptual example - adapt to your SpiderFoot setup

from spiderfoot import SpiderFoot, SpiderFootEvent

# Initialize SpiderFoot
sf = SpiderFoot({})

# Configure the TOC/Corruption module
module_opts = {
    'corruption_keywords': ['fraud', 'bribery', 'corruption'],
    'toc_keywords': ['breach', 'compromise', 'leaked'],
    'check_emails': True,
    'check_domains': True,
    'sensitivity': 'medium'
}

# Create and run scan
target = "suspicious-domain.com"
scan_id = sf.scanCreate(target, ['sfp_toc_corruption'], module_opts)
sf.scanStart(scan_id)

# Process results
results = sf.scanResults(scan_id)
for result in results:
    if result['type'] in ['CORRUPTION_INDICATOR', 'TOC_INDICATOR']:
        print(f"Found: {result['data']}")
```

## Example 8: Investigating Multiple Targets

### Scenario
You have a list of domains to investigate.

### Batch Processing
```bash
# domains.txt contains one domain per line
while read domain; do
    echo "Investigating: $domain"
    # Use SpiderFoot CLI or API to scan each domain
done < domains.txt
```

## Example 9: Reviewing Results

### Understanding Event Types

**CORRUPTION_INDICATOR**
- Indicates potential corruption-related activities
- Check the associated data for context
- Consider severity and source reliability

**TOC_INDICATOR**
- Indicates potential compromise or threat
- May require immediate action
- Correlate with other security events

**HIGH_RISK_DOMAIN**
- Domain exhibits suspicious characteristics
- May be used for phishing or malware
- Consider blocking or monitoring

**HIGH_RISK_IPADDR**
- IP address shows signs of malicious activity
- May be part of botnet or attack infrastructure
- Consider blocking or enhanced monitoring

## Example 10: False Positive Handling

### Common False Positives
- Legitimate security blogs discussing threats
- Academic papers on corruption
- News articles about breaches

### Mitigation
1. Review context before acting
2. Use medium or low sensitivity for fewer false positives
3. Whitelist known good sources
4. Correlate with other intelligence sources

## Tips for Effective Use

1. **Start with default settings** - Adjust based on your needs
2. **Review all findings** - Context is important
3. **Combine with other modules** - Better results with comprehensive scanning
4. **Update keywords regularly** - Keep up with emerging threats
5. **Document your findings** - Build institutional knowledge

## Troubleshooting

### No Results Found
- Check that the module is enabled
- Verify target is valid
- Try increasing sensitivity
- Check other SpiderFoot modules are providing input

### Too Many False Positives
- Decrease sensitivity
- Increase minimum keyword matches
- Refine your keyword lists
- Use context analysis (if enabled)

### Performance Issues
- Disable caching if memory is limited
- Process smaller batches
- Reduce number of concurrent scans

## Support

For more examples or help with specific use cases, please:
- Open an issue on GitHub
- Consult the main README
- Check SpiderFoot documentation
