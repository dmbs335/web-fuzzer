"""Persistent module for Apache Confusion fuzzing target.

Exports process(input_str) for use with persistent_wrapper.py.
Expects APACHE_CONFUSION_PORT environment variable to be set.

Usage:
    APACHE_CONFUSION_PORT=9101 python persistent_wrapper.py \
        targets/apache_confusion_target_module.py
"""

from __future__ import annotations

import json
import os
import sys

# Ensure targets/ directory is on sys.path for sibling imports
_this_dir = os.path.dirname(os.path.abspath(__file__))
if _this_dir not in sys.path:
    sys.path.insert(0, _this_dir)

# Lazy-initialised session
_session = None
_port = int(os.environ.get("APACHE_CONFUSION_PORT", "9100"))


def _get_session():
    global _session
    if _session is None:
        from apache_confusion_target import _make_session
        _session = _make_session(_port)
    return _session


def process(input_str: str) -> dict:
    """Process a single URL input and return fuzztrace result."""
    from apache_confusion_target import query_apache

    session = _get_session()
    url_path = input_str.strip()
    if not url_path:
        return {"output": "", "exit_code": 1}

    try:
        result = query_apache(session, url_path)
        return {
            "output": json.dumps(result, ensure_ascii=False),
            "exit_code": 0,
        }
    except Exception as e:
        return {
            "output": json.dumps({"error": str(e)}),
            "exit_code": 1,
        }
