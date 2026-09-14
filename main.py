#!/usr/bin/env python3
"""Точка входа. Эквивалентно `python -m trust_prediction.cli`.

Примеры:
    python main.py demo
    python main.py raci
    python main.py status --project data/project.json --version <id>
"""
from trust_prediction.cli import main

if __name__ == "__main__":
    main()
