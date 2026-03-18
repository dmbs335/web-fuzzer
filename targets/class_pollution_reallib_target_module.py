#!/usr/bin/env python3
"""Persistent-mode module for class_pollution_reallib_target.

Must export process(input_str) -> {"output": str, "exit_code": int}.
"""
from __future__ import annotations

import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from targets.class_pollution_reallib_target import process_input


def process(input_str: str) -> dict:
    """Process one input and return persistent wrapper compatible result."""
    try:
        raw = input_str.encode("utf-8") if isinstance(input_str, str) else input_str
        result = process_input(raw)
        return {"output": json.dumps(result, default=str), "exit_code": 0}
    except Exception as e:
        return {"output": json.dumps({"error": str(e), "merged": False}), "exit_code": 1}
