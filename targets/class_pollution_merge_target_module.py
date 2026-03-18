#!/usr/bin/env python3
"""Persistent-mode module for class_pollution_merge_target.

Used by persistent_wrapper.py for high-throughput fuzzing.
Must export process(input_str) -> {"output": str, "exit_code": int}.
"""
from __future__ import annotations

import json
import sys
import os

# Add project root to path so targets/ imports work
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from targets.class_pollution_merge_target import process_input


def process(input_str: str) -> dict:
    """Process one input and return persistent wrapper compatible result."""
    data = input_str.encode("utf-8") if isinstance(input_str, str) else input_str
    result = process_input(data)
    return {"output": json.dumps(result, default=str), "exit_code": 0}
