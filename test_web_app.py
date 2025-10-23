#!/usr/bin/env python3
"""
Test script for the web application
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(__file__))

def test_imports():
    """Test that all required modules can be imported."""
    print("Testing imports...")
    
    try:
        from flask import Flask
        print("✓ Flask imported")
    except ImportError as e:
        print(f"✗ Flask import failed: {e}")
        return False
    
    try:
        from processor.csv_importer import SpiderFootCSVImporter
        print("✓ CSV Importer imported")
    except ImportError as e:
        print(f"✗ CSV Importer import failed: {e}")
        return False
    
    try:
        from processor.analyzer import SpiderFootAnalyzer
        print("✓ Analyzer imported")
    except ImportError as e:
        print(f"✗ Analyzer import failed: {e}")
        return False
    
    try:
        from processor.report_generator import ReportGenerator
        print("✓ Report Generator imported")
    except ImportError as e:
        print(f"✗ Report Generator import failed: {e}")
        return False
    
    return True

def test_flask_app():
    """Test that the Flask app can be created."""
    print("\nTesting Flask app creation...")
    
    try:
        from web_app import app
        print("✓ Flask app created successfully")
        
        # Test routes exist
        with app.test_client() as client:
            response = client.get('/health')
            if response.status_code == 200:
                print("✓ Health endpoint working")
            else:
                print(f"✗ Health endpoint returned {response.status_code}")
                return False
            
            response = client.get('/')
            if response.status_code == 200:
                print("✓ Index page accessible")
            else:
                print(f"✗ Index page returned {response.status_code}")
                return False
        
        return True
    except Exception as e:
        print(f"✗ Flask app test failed: {e}")
        return False

def test_file_structure():
    """Test that all required files exist."""
    print("\nTesting file structure...")
    
    required_files = [
        'web_app.py',
        'templates/index.html',
        'static/css/style.css',
        'static/js/app.js',
        'processor/__init__.py',
        'processor/csv_importer.py',
        'processor/analyzer.py',
        'processor/report_generator.py'
    ]
    
    all_exist = True
    for filepath in required_files:
        if os.path.exists(filepath):
            print(f"✓ {filepath} exists")
        else:
            print(f"✗ {filepath} missing")
            all_exist = False
    
    return all_exist

if __name__ == '__main__':
    print("=" * 70)
    print("SpiderFoot Web App - Test Suite")
    print("=" * 70)
    print()
    
    tests = [
        ("File Structure", test_file_structure),
        ("Module Imports", test_imports),
        ("Flask Application", test_flask_app)
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"\n✗ Test '{test_name}' crashed: {e}")
            results.append((test_name, False))
    
    print("\n" + "=" * 70)
    print("TEST RESULTS")
    print("=" * 70)
    
    for test_name, result in results:
        status = "✓ PASSED" if result else "✗ FAILED"
        print(f"{test_name}: {status}")
    
    all_passed = all(result for _, result in results)
    
    print("=" * 70)
    if all_passed:
        print("✓ All tests passed! Web app is ready to use.")
        print("\nTo start the web app, run:")
        print("  python web_app.py")
        print("\nThen open http://localhost:5000 in your browser")
    else:
        print("✗ Some tests failed. Please review the errors above.")
        sys.exit(1)
