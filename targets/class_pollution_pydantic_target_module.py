#!/usr/bin/env python3
"""Persistent-mode module for class_pollution_pydantic_target."""
from __future__ import annotations

import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from class_pollution_pydantic_target import process_input


def process(input_str: str) -> dict:
    data = input_str.encode("utf-8") if isinstance(input_str, str) else input_str
    result = process_input(data)
    return {"output": json.dumps(result, default=str), "exit_code": 0}
