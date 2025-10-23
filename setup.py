#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
import os

# Read the README file
with open('README.md', 'r', encoding='utf-8') as f:
    long_description = f.read()

# Read requirements
with open('requirements.txt', 'r', encoding='utf-8') as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name='spiderfoot-toc-corruption',
    version='1.0.0',
    author='Watchman8925',
    description='SpiderFoot plugin pack for detecting indicators of corruption and threat of compromise',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/Watchman8925/Spiderfoot-Processor',
    packages=find_packages(),
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'Topic :: Security',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
    ],
    python_requires='>=3.7',
    install_requires=requirements,
    extras_require={
        'dev': [
            'pytest>=7.0.0',
            'pytest-cov>=4.0.0',
            'flake8>=6.0.0',
            'black>=23.0.0',
        ],
    },
    entry_points={
        'spiderfoot.plugins': [
            'sfp_toc_corruption = plugins.sfp_toc_corruption:sfp_toc_corruption',
        ],
    },
    include_package_data=True,
    package_data={
        'plugins': ['*.py'],
    },
    keywords='spiderfoot osint security corruption threat-intelligence',
)
