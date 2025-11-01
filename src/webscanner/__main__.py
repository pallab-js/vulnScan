#!/usr/bin/env python3
"""
Main entry point for WebScanner CLI
"""

import sys
import os

# Add the parent directory to the path to import webscanner
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from webscanner.cli.main import main

if __name__ == "__main__":
    main()