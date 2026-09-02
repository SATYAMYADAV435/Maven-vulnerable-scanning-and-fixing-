#!/usr/bin/env python3
"""Convenience root entrypoint for Maven Security Scanner CLI."""
import sys
from app.cli import main

if __name__ == "__main__":
    sys.exit(main())
