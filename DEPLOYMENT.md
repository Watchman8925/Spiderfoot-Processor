# Deployment Guide: SpiderFoot TOC/Corruption Plugin Pack

## Quick Start

### Prerequisites
- SpiderFoot 4.0 or later installed
- Python 3.7+
- pip package manager

### Installation Steps

#### Method 1: Manual Installation (Recommended)

1. **Clone the repository**
   ```bash
   git clone https://github.com/Watchman8925/Spiderfoot-Processor.git
   cd Spiderfoot-Processor
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Copy plugin to SpiderFoot**
   ```bash
   # Replace /path/to/spiderfoot with your SpiderFoot installation directory
   cp plugins/sfp_toc_corruption.py /path/to/spiderfoot/modules/
   ```

4. **Restart SpiderFoot**
   ```bash
   cd /path/to/spiderfoot
   python sf.py
   ```

5. **Verify installation**
   - Open SpiderFoot web interface (default: http://127.0.0.1:5001)
   - Create a new scan
   - Look for "TOC/Corruption Detector" in the module list
   - If found, installation is successful!

#### Method 2: Python Package Installation

```bash
# From the repository directory
pip install .

# Or for development
pip install -e .
```

### Configuration

#### Option 1: Web Interface
1. In SpiderFoot, create a new scan
2. Select "TOC/Corruption Detector" module
3. Click on module settings
4. Adjust options as needed:
   - Corruption keywords
   - TOC keywords
   - Check emails/domains/IPs
   - Sensitivity level

#### Option 2: Configuration File
1. Copy the sample configuration:
   ```bash
   cp config.yaml /path/to/spiderfoot/modules/sfp_toc_corruption.yaml
   ```

2. Edit the configuration file to match your needs

3. Restart SpiderFoot

### Usage

#### Basic Scan
1. Open SpiderFoot web interface
2. Click "New Scan"
3. Enter target (domain, email, or IP)
4. Select "TOC/Corruption Detector"
5. Click "Run Scan"

#### Advanced Configuration
```yaml
# Example advanced configuration
sfp_toc_corruption:
  corruption_keywords:
    - fraud
    - bribery
    - corruption
    - embezzlement
    - your_custom_keyword
  
  toc_keywords:
    - breach
    - compromise
    - leaked
    - your_custom_threat
  
  sensitivity: high
  check_emails: true
  check_domains: true
  check_ips: true
```

## Verification

### Test the Installation

Run the test suite to verify everything works:

```bash
cd Spiderfoot-Processor
python -m pytest tests/ -v
```

Expected output:
```
20 passed in 0.08s
```

### Test Basic Functionality

Create a simple test script:

```python
import sys
sys.path.insert(0, '/path/to/spiderfoot/modules')

from sfp_toc_corruption import sfp_toc_corruption

plugin = sfp_toc_corruption()
print(f"Plugin loaded: {plugin.meta['name']}")
print(f"Watched events: {len(plugin.watchedEvents())}")
print(f"Produced events: {len(plugin.producedEvents())}")
```

## Troubleshooting

### Plugin Not Showing in SpiderFoot

**Problem**: Module doesn't appear in the module list

**Solutions**:
1. Verify file is in correct location: `/path/to/spiderfoot/modules/sfp_toc_corruption.py`
2. Check file permissions: `chmod 644 sfp_toc_corruption.py`
3. Verify SpiderFoot is restarted
4. Check SpiderFoot logs for errors

### Import Errors

**Problem**: `ModuleNotFoundError: No module named 'spiderfoot'`

**Solution**: This is normal if testing outside SpiderFoot. The plugin is designed to work within SpiderFoot's environment.

### No Results Generated

**Problem**: Plugin runs but produces no results

**Solutions**:
1. Check that other modules are feeding events to this plugin
2. Verify sensitivity is not set too low
3. Ensure keyword lists match your data
4. Check target is valid and has data to analyze

### Performance Issues

**Problem**: Scans are slow or timing out

**Solutions**:
1. Reduce sensitivity level
2. Disable checks you don't need (emails/domains/IPs)
3. Reduce number of concurrent scans
4. Optimize keyword lists

## Integration Examples

### With Other Modules

The TOC/Corruption plugin works best with:

1. **sfp_dnsresolve** - Resolves domains before analysis
2. **sfp_email** - Harvests emails for analysis
3. **sfp_leakix** - Provides breach data
4. **sfp_tor** - Provides dark web mentions

### Recommended Module Combinations

**For Comprehensive OSINT**:
- DNS Resolution
- Email Harvester
- Breach Data Module
- TOC/Corruption Detector
- Threat Intelligence Modules

**For Quick Checks**:
- DNS Resolution
- TOC/Corruption Detector

## Monitoring and Maintenance

### Log Files

SpiderFoot logs are typically located at:
- `/path/to/spiderfoot/logs/`

Check for plugin-specific messages:
```bash
grep "sfp_toc_corruption" /path/to/spiderfoot/logs/*.log
```

### Updates

To update the plugin:

```bash
cd Spiderfoot-Processor
git pull origin main
cp plugins/sfp_toc_corruption.py /path/to/spiderfoot/modules/
# Restart SpiderFoot
```

### Customization

#### Adding Custom Keywords

Edit the plugin file or configuration:

```python
'corruption_keywords': [
    'fraud', 'bribery', 'corruption',
    'your_industry_specific_term_1',
    'your_industry_specific_term_2'
]
```

#### Adding Custom Detection Logic

The plugin is designed to be extensible. See `CONTRIBUTING.md` for guidelines.

## Production Deployment

### Best Practices

1. **Test First**: Always test in a development environment
2. **Backup**: Keep backups of your SpiderFoot configuration
3. **Monitor**: Watch logs for any errors
4. **Document**: Keep notes on custom configurations
5. **Update Regularly**: Check for updates and security patches

### Performance Tuning

For large-scale deployments:

```yaml
# High-performance configuration
sfp_toc_corruption:
  sensitivity: medium  # Balance accuracy and speed
  check_emails: true
  check_domains: true
  check_ips: false  # Disable if not needed
  advanced:
    enable_caching: true
    max_cache_size: 10000
```

### Security Considerations

1. Keep keyword lists confidential (may reveal investigation focus)
2. Secure access to SpiderFoot instance
3. Monitor for sensitive data in results
4. Follow data retention policies
5. Comply with applicable laws and regulations

## Support

### Getting Help

- **Issues**: https://github.com/Watchman8925/Spiderfoot-Processor/issues
- **Documentation**: See README.md and EXAMPLES.md
- **SpiderFoot**: https://www.spiderfoot.net/

### Reporting Bugs

When reporting bugs, include:
1. SpiderFoot version
2. Python version
3. Plugin version
4. Error messages (if any)
5. Steps to reproduce

### Contributing

See CONTRIBUTING.md for guidelines on:
- Submitting bug fixes
- Adding features
- Improving documentation
- Testing

## License

This plugin is licensed under the MIT License. See LICENSE file for details.

## Acknowledgments

- SpiderFoot team for the excellent OSINT framework
- Contributors to this plugin pack
- Security research community

---

**Last Updated**: October 23, 2025
**Version**: 1.0.0
**Maintainer**: Watchman8925
