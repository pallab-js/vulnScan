#!/usr/bin/env python3
"""
Setup script for WebScanner
"""

from setuptools import setup, find_packages
import os

# Read README
with open('README.md', 'r', encoding='utf-8') as f:
    long_description = f.read()

# Read requirements
with open('requirements.txt', 'r', encoding='utf-8') as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name='webscanner',
    version='1.0.0',
    description='CLI web security scanner',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='WebScanner',
    author_email='',
    url='https://github.com/yourusername/webscanner',
    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    include_package_data=True,
    install_requires=requirements,
    entry_points={
        'console_scripts': [
            'webscanner=webscanner.cli.main:main',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Topic :: Security',
    ],
    python_requires='>=3.8',
    keywords='security scanner web vulnerability cli',
    project_urls={
        'Bug Reports': 'https://github.com/yourusername/webscanner/issues',
        'Source': 'https://github.com/yourusername/webscanner',
        'Documentation': 'https://github.com/yourusername/webscanner#readme',
    },
)