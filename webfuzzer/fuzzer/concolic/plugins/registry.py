"""Domain plugin registry with auto-detection from oracle/grammar name."""

from __future__ import annotations

from ..domain_plugin import DomainPlugin

# Lazy imports to avoid loading all plugins at startup
_PLUGIN_MAP: dict[str, str] = {
    # oracle/grammar name → module.ClassName
    "saml": "saml_plugin.SamlPlugin",
    "saml_sigtrue": "saml_plugin.SamlPlugin",
    "saml_validator": "saml_plugin.SamlPlugin",
    "jwt": "jwt_plugin.JwtPlugin",
    "cookie": "cookie_plugin.CookiePlugin",
}

# Grammar names that map to domains
_GRAMMAR_MAP: dict[str, str] = {
    "saml": "saml",
    "jwt": "jwt",
    "cookie": "cookie",
}


def get_plugin(oracle: str | None = None, grammar: str | None = None) -> DomainPlugin | None:
    """Auto-detect and instantiate the appropriate domain plugin.

    Tries oracle name first, then grammar name.
    Returns None if no matching plugin found (graceful fallback).
    """
    # Try oracle name
    domain = None
    if oracle:
        for key in _PLUGIN_MAP:
            if key in oracle.lower():
                domain = key
                break

    # Try grammar name
    if domain is None and grammar:
        domain = _GRAMMAR_MAP.get(grammar.lower())

    if domain is None:
        return None

    module_class = _PLUGIN_MAP.get(domain)
    if module_class is None:
        return None

    # Lazy import
    module_name, class_name = module_class.rsplit(".", 1)
    import importlib
    mod = importlib.import_module(f".{module_name}", package=__package__)
    cls = getattr(mod, class_name)
    return cls()


def available_plugins() -> list[str]:
    """List available domain names."""
    return sorted(set(_PLUGIN_MAP.values()))
