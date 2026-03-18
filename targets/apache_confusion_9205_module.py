"""Thin wrapper setting APACHE_CONFUSION_PORT before importing the real module."""
import os, sys
os.environ["APACHE_CONFUSION_PORT"] = "9205"
_this_dir = os.path.dirname(os.path.abspath(__file__))
if _this_dir not in sys.path:
    sys.path.insert(0, _this_dir)
from apache_confusion_target_module import process  # noqa: F401, E402
