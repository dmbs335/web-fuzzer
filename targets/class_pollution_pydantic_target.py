#!/usr/bin/env python3
"""Class pollution target for Pydantic-style model_validate patterns.

Tests whether Pydantic-like model construction allows class pollution via:
1. model_validate(user_data) — validates but may pass through nested dicts
2. __init__(**kwargs) — direct attribute assignment
3. model_config mutation — class-level config object pollution

This is NOT a known CVE — it tests whether Pydantic's validation prevents
class pollution that raw setattr/merge would allow.

Input format:
    {"model": "user", "payload": {"admin": true, "__class__": {"secret": "pwned"}}}
"""
from __future__ import annotations

import json
import sys
from typing import Any


# ── Emulated Pydantic-like models ────────────────────────────

class ModelConfig:
    """Emulated Pydantic model_config."""
    strict = False
    validate_assignment = False
    extra = "ignore"  # "allow", "ignore", "forbid"
    frozen = False
    populate_by_name = True


class BaseModel:
    """Emulated Pydantic BaseModel with varying strictness levels."""

    model_config = ModelConfig()
    _model_fields: dict[str, dict] = {}

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        # Auto-discover fields from annotations
        fields = {}
        for name, annotation in getattr(cls, "__annotations__", {}).items():
            default = getattr(cls, name, None)
            fields[name] = {"type": annotation, "default": default}
        cls._model_fields = fields

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            if key in self._model_fields:
                setattr(self, key, value)
            elif self.model_config.extra == "allow":
                setattr(self, key, value)
            # "ignore" = silently drop, "forbid" = raise

    @classmethod
    def model_validate(cls, data: dict) -> "BaseModel":
        """Validate and create model from dict — the safe path."""
        if not isinstance(data, dict):
            raise ValueError("Expected dict")

        validated = {}
        for key, value in data.items():
            if key in cls._model_fields:
                validated[key] = value
            elif cls.model_config.extra == "allow":
                validated[key] = value
            elif cls.model_config.extra == "forbid":
                raise ValueError(f"Extra field not allowed: {key}")

        return cls(**validated)

    @classmethod
    def model_validate_unsafe(cls, data: dict) -> "BaseModel":
        """VULNERABLE: No field validation — direct merge into instance."""
        instance = cls.__new__(cls)
        for key, value in data.items():
            if isinstance(value, dict):
                existing = getattr(instance, key, None)
                if existing is not None and hasattr(existing, "__dict__"):
                    _recursive_merge(value, existing)
                else:
                    setattr(instance, key, value)
            else:
                setattr(instance, key, value)
        return instance


def _recursive_merge(src: dict, dst: Any, depth: int = 0) -> None:
    """Vulnerable recursive merge — no dunder filter."""
    if depth > 8:
        return
    for key, value in src.items():
        if isinstance(value, dict):
            existing = getattr(dst, key, None)
            if existing is not None and hasattr(existing, "__dict__"):
                _recursive_merge(value, existing, depth + 1)
            else:
                try:
                    setattr(dst, key, value)
                except (AttributeError, TypeError):
                    pass
        else:
            try:
                setattr(dst, key, value)
            except (AttributeError, TypeError):
                pass


# ── Concrete models ──────────────────────────────────────────

class UserModel(BaseModel):
    username: str = ""
    email: str = ""
    is_active: bool = True
    is_admin: bool = False
    role: str = "user"
    permissions: list = []


class ConfigModel(BaseModel):
    debug: bool = False
    secret_key: str = "default-secret"
    allowed_hosts: list = ["localhost"]
    database_url: str = "sqlite:///db.sqlite3"


class UserModelExtraAllow(UserModel):
    """Same as UserModel but with extra='allow'."""
    model_config = ModelConfig()


# Override to allow extra fields
UserModelExtraAllow.model_config.extra = "allow"


MODELS = {
    "user": UserModel,
    "config": ConfigModel,
    "user_extra": UserModelExtraAllow,
}

VALIDATE_METHODS = {
    "validate": "model_validate",
    "unsafe": "model_validate_unsafe",
    "init": "__init__",
}


# ── Snapshot ─────────────────────────────────────────────────

_WATCHED_ATTRS = [
    "username", "email", "is_active", "is_admin", "role", "permissions",
    "debug", "secret_key", "allowed_hosts", "database_url",
]


def _snapshot(obj: object) -> dict:
    result = {}
    for attr in _WATCHED_ATTRS:
        val = getattr(obj, attr, None)
        if val is not None:
            result[attr] = val if isinstance(val, (str, int, float, bool, type(None))) else str(val)[:200]
    return result


def _snapshot_class(cls: type) -> dict:
    result = {}
    for attr in _WATCHED_ATTRS:
        val = getattr(cls, attr, None)
        if val is not None:
            result[attr] = val if isinstance(val, (str, int, float, bool, type(None))) else str(val)[:200]
    return result


# ── Helpers for oracle compatibility ─────────────────────────

def _estimate_depth(payload: dict, depth: int = 0) -> int:
    max_d = depth
    for key, value in payload.items():
        if isinstance(key, str) and key.startswith("__") and key.endswith("__"):
            if isinstance(value, dict):
                max_d = max(max_d, _estimate_depth(value, depth + 1))
            else:
                max_d = max(max_d, depth + 1)
    return max_d


def _extract_dunders(payload: dict) -> list[str]:
    dunders = []
    for key, value in payload.items():
        if isinstance(key, str) and key.startswith("__") and key.endswith("__"):
            if key not in dunders:
                dunders.append(key)
            if isinstance(value, dict):
                for d in _extract_dunders(value):
                    if d not in dunders:
                        dunders.append(d)
    return dunders


# ── Main processing ─────────────────────────────────────────

def process_input(raw: bytes) -> dict:
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {"merged": False, "error": "invalid_json", "model": "unknown"}

    model_name = data.get("model", "user")
    method_name = data.get("method", "validate")
    payload = data.get("payload", {})

    if not isinstance(payload, dict):
        return {"merged": False, "error": "payload_not_dict", "model": model_name}

    model_cls = MODELS.get(model_name)
    if model_cls is None:
        return {"merged": False, "error": f"unknown_model:{model_name}", "model": model_name}

    method_attr = VALIDATE_METHODS.get(method_name)
    if method_attr is None:
        return {"merged": False, "error": f"unknown_method:{method_name}", "model": model_name}

    # Snapshot before
    cls_before = _snapshot_class(model_cls)

    exc_class = None
    exc_msg = None
    merged = False
    instance = None

    try:
        if method_name == "init":
            instance = model_cls(**payload)
        else:
            method = getattr(model_cls, method_attr)
            instance = method(payload)
        merged = True
    except Exception as e:
        exc_class = type(e).__name__
        exc_msg = str(e)[:200]

    # Snapshot after
    cls_after = _snapshot_class(model_cls)
    inst_snapshot = _snapshot(instance) if instance else {}

    # Check class-level pollution
    class_attrs_changed = {}
    for k in cls_before:
        if cls_before[k] != cls_after.get(k):
            class_attrs_changed[k] = {"before": cls_before[k], "after": cls_after.get(k)}

    # Check config pollution
    config_changed = {}
    config_attrs = ["strict", "validate_assignment", "extra", "frozen", "populate_by_name"]
    for attr in config_attrs:
        before_val = getattr(ModelConfig, attr, None)
        after_val = getattr(model_cls.model_config, attr, None)
        if str(before_val) != str(after_val):
            config_changed[attr] = {"before": str(before_val), "after": str(after_val)}

    # Check if validation was bypassed
    extra_fields_accepted = []
    if instance:
        for key in payload:
            if key not in model_cls._model_fields and hasattr(instance, key):
                extra_fields_accepted.append(key)

    # Oracle-compatible fields
    chain_depth = _estimate_depth(payload)
    dunder_traversed = _extract_dunders(payload)

    result = {
        "merged": merged,
        "error": exc_msg,
        "merge_impl": f"{model_name}_{method_name}",
        "model": model_name,
        "method": method_name,
        # Oracle-compatible fields
        "globals_polluted": [],
        "globals_polluted_count": 0,
        "class_attrs_changed": class_attrs_changed,
        "class_attrs_changed_count": len(class_attrs_changed),
        "attrs_changed": {},
        "attrs_changed_count": 0,
        "chain_depth": chain_depth,
        "dunder_traversed": dunder_traversed,
        "dunder_traversed_count": len(dunder_traversed),
        "exception_class": exc_class,
        # Pydantic-specific fields
        "instance_attrs": inst_snapshot,
        "config_changed": config_changed,
        "config_changed_count": len(config_changed),
        "extra_fields_accepted": extra_fields_accepted,
        "extra_fields_count": len(extra_fields_accepted),
        "validation_bypassed": bool(extra_fields_accepted and method_name == "validate"),
    }

    # Restore class state
    for k, v in cls_before.items():
        try:
            setattr(model_cls, k, v)
        except (AttributeError, TypeError):
            pass

    return result


def main():
    raw = sys.stdin.buffer.read()
    if not raw:
        print(json.dumps({"merged": False, "error": "empty_input", "model": "unknown"}))
        return
    result = process_input(raw)
    print(json.dumps(result, default=str))


if __name__ == "__main__":
    main()
