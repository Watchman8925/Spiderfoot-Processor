# Web Application Guide

## Overview

The SpiderFoot TOC/Corruption Web Application provides a modern, user-friendly interface for processing SpiderFoot CSV exports, analyzing data, and generating professional reports.

## Features

### 🎨 Modern Dark Theme
- Sleek, professional dark interface
- Responsive design for all screen sizes
- Smooth animations and transitions

### 📤 Easy Upload
- Drag-and-drop file upload
- Browse and select files
- Real-time upload progress
- File validation

### 📊 Interactive Analysis
- Instant data summaries
- Threat overview cards
- Tabbed detailed analysis
- Visual data presentation

### 📈 Automatic Visualizations
- Event distribution charts
- Module activity graphs
- Threat overview metrics

### 📄 Professional Reports
- One-click PDF generation
- Embedded charts and graphs
- Executive summaries
- Actionable recommendations

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/Watchman8925/Spiderfoot-Processor.git
cd Spiderfoot-Processor

# Install dependencies
pip install -r requirements.txt
```

### Starting the Server

```bash
# Start the web application
python web_app.py
```

The server will start on `http://localhost:5000`

### Accessing the Interface

Open your web browser and navigate to:
```
http://localhost:5000
```

## Using the Web Application

### Step 1: Upload Your CSV File

1. **Drag & Drop**: Drag your SpiderFoot CSV export directly onto the upload zone
   - OR -
2. **Browse Files**: Click the "Browse Files" button and select your CSV file

The application will:
- Validate the file format
- Show upload progress
- Parse and analyze the CSV
- Display initial statistics

### Step 2: Review the Summary

After upload, you'll see:
- **Total Records**: Number of events in your CSV
- **Event Types**: Count of unique event types
- **Modules**: Number of SpiderFoot modules used
- **Corruption Indicators**: Count of corruption-related findings
- **TOC Indicators**: Count of threat of compromise findings

### Step 3: Analyze the Data

Click the **"Analyze Data"** button to perform deep analysis.

The analysis includes:
- Event distribution patterns
- Module activity metrics
- Corruption keyword analysis
- TOC pattern detection
- Risk domain identification
- Compromised asset detection

### Step 4: Explore the Results

Navigate through the tabbed interface:

#### Events Tab
- View all event types detected
- See distribution percentages
- Identify most common events

#### Modules Tab
- See which modules generated the most events
- Understand module contributions
- Analyze module effectiveness

#### Corruption Tab
- Review corruption indicators
- See most common corruption keywords
- Identify suspicious patterns

#### Threats Tab
- Analyze TOC indicators
- Review threat keywords
- Assess compromise indicators

#### Recommendations Tab
- Read security recommendations
- Get actionable insights
- Prioritize response actions

### Step 5: Generate Reports

1. Choose report options:
   - ☑️ Generate Charts (PNG)
   - ☑️ Generate PDF Report

2. Click **"Generate & Download Reports"**

3. Download generated files:
   - PDF report with full analysis
   - Individual chart images
   - JSON data export

## Configuration

### Changing the Port

Edit `web_app.py` and modify the last line:

```python
app.run(debug=True, host='0.0.0.0', port=5000)  # Change 5000 to your port
```

### Maximum File Size

Default: 50MB

To change, edit `web_app.py`:

```python
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB
```

### Upload and Report Directories

By default:
- Uploads: `./uploads`
- Reports: `./reports`

To change, edit `web_app.py`:

```python
app.config['UPLOAD_FOLDER'] = Path('your_upload_dir')
app.config['REPORTS_FOLDER'] = Path('your_reports_dir')
```

## Keyboard Shortcuts

- **Ctrl+U**: Focus on upload area (when visible)
- **Escape**: Close modals or reset view
- **Tab**: Navigate between sections

## Browser Compatibility

Tested and working on:
- ✅ Chrome 90+
- ✅ Firefox 88+
- ✅ Safari 14+
- ✅ Edge 90+

## Security Considerations

### Production Deployment

For production use:

1. **Change the Secret Key**:
   ```python
   app.config['SECRET_KEY'] = 'your-secure-random-key'
   # Or use environment variable:
   # export SECRET_KEY='your-secure-random-key'
   ```

2. **Disable Debug Mode**:
   ```python
   app.run(debug=False, host='0.0.0.0', port=5000)
   ```

3. **Use HTTPS**: Deploy behind a reverse proxy (nginx, Apache) with SSL

4. **Limit Access**: Use firewall rules or authentication middleware

5. **Set File Size Limits**: Prevent abuse by limiting upload sizes

### File Handling

- Uploaded files are stored temporarily
- Files are validated before processing
- Filenames are sanitized using `secure_filename()`
- Files are processed and then can be deleted

## Troubleshooting

### Port Already in Use

If port 5000 is already in use:

```bash
# Find the process using the port
lsof -i :5000  # macOS/Linux
netstat -ano | findstr :5000  # Windows

# Kill the process or use a different port
```

### Upload Fails

**Possible causes:**
- File too large (exceeds 50MB)
- Not a valid CSV file
- Corrupted CSV data

**Solutions:**
- Check file size
- Verify CSV format
- Try exporting data again from SpiderFoot

### Charts Not Generated

**Possible causes:**
- matplotlib not installed

**Solution:**
```bash
pip install matplotlib
```

### PDF Generation Fails

**Possible causes:**
- reportlab not installed

**Solution:**
```bash
pip install reportlab
```

### Page Not Loading

**Possible causes:**
- Server not started
- Wrong URL
- Firewall blocking connection

**Solutions:**
- Verify server is running
- Check console for errors
- Try `http://127.0.0.1:5000` instead of `localhost`

## Advanced Features

### API Endpoints

The web app exposes these endpoints:

#### Upload CSV
```
POST /upload
Content-Type: multipart/form-data
Body: file (CSV)
```

#### Analyze Data
```
POST /analyze
Content-Type: application/json
Body: {
  "filename": "uploaded_file.csv",
  "filters": {...}
}
```

#### Generate Report
```
POST /generate_report
Content-Type: application/json
Body: {
  "filename": "uploaded_file.csv",
  "options": {
    "generate_charts": true,
    "generate_pdf": true
  }
}
```

#### Download File
```
GET /download/<report_id>/<filename>
```

#### Health Check
```
GET /health
```

### Automation

You can automate the web app using curl or Python requests:

```bash
# Upload file
curl -X POST -F "file=@scan.csv" http://localhost:5000/upload

# Analyze
curl -X POST -H "Content-Type: application/json" \
  -d '{"filename":"scan.csv"}' \
  http://localhost:5000/analyze

# Generate report
curl -X POST -H "Content-Type: application/json" \
  -d '{"filename":"scan.csv","options":{"generate_pdf":true}}' \
  http://localhost:5000/generate_report
```

## Performance

### Optimization Tips

1. **Use Chrome/Edge**: Best performance with Chromium-based browsers
2. **Close Unused Tabs**: Free up memory for analysis
3. **Smaller Files**: Process large CSVs in batches if possible
4. **Local Deployment**: Run on the same machine as your data

### Expected Processing Times

File Size | Upload | Analysis | Report Generation
----------|--------|----------|------------------
< 1MB     | < 1s   | 1-2s     | 5-10s
1-10MB    | 1-5s   | 2-5s     | 10-20s
10-50MB   | 5-15s  | 5-15s    | 20-60s

*Times vary based on hardware and data complexity*

## Support

### Getting Help

1. Check this guide
2. Review error messages in browser console (F12)
3. Check server logs in terminal
4. Open an issue on GitHub: https://github.com/Watchman8925/Spiderfoot-Processor/issues

### Reporting Bugs

Include:
- Browser version
- Python version
- Error messages (browser console and server logs)
- Steps to reproduce
- CSV file size and structure (if relevant)

## Contributing

Want to improve the web app?

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

See `CONTRIBUTING.md` for details.

## License

MIT License - See `LICENSE` file for details.

## Credits

Built with:
- Flask - Web framework
- Font Awesome - Icons
- Modern CSS3 - Styling
- Vanilla JavaScript - Interactivity

---

**Enjoy the web application!** 🎉

For more information, visit: https://github.com/Watchman8925/Spiderfoot-Processor
