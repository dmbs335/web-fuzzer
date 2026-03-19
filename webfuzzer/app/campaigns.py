"""Campaign presets and CLI helpers."""

from __future__ import annotations

from pathlib import Path


CAMPAIGN_PRESETS = {
    "cve_detect": {
        "oracle": "cve_scanner",
        "mutators": "apache_confusion,grammar,havoc",
        "seeds_dir": "targets/apache_confusion_seeds_cve",
        "grammar": "apache_confusion",
        "campaign_mode": "cve_detect",
    },
    "patch_bypass": {
        "oracle": "cve_scanner",
        "mutators": "apache_confusion,havoc",
        "seeds_dir": "targets/apache_confusion_seeds_cve/patch_bypass",
        "grammar": "apache_confusion",
        "campaign_mode": "patch_bypass",
    },
    "novel": {
        "oracle": "apache_confusion",
        "mutators": "apache_confusion,grammar,havoc",
        "seeds_dir": "targets/apache_confusion_seeds",
        "grammar": "apache_confusion",
        "campaign_mode": "novel",
    },
}


def apply_campaign_preset(args) -> str:
    """Apply a campaign preset to CLI args and return the campaign mode."""
    campaign = getattr(args, "campaign", None)
    campaign_mode = "novel"
    if not campaign or campaign not in CAMPAIGN_PRESETS:
        return campaign_mode

    preset = CAMPAIGN_PRESETS[campaign]
    campaign_mode = preset.get("campaign_mode", campaign_mode)

    # Only apply preset values if the user did not override the CLI default.
    if args.oracle == "crash,sanitizer":
        args.oracle = preset["oracle"]
    if args.mutators == "grammar,havoc":
        args.mutators = preset["mutators"]
    if args.seeds_dir is None:
        args.seeds_dir = Path(preset["seeds_dir"])
    if args.grammar == "html":
        args.grammar = preset.get("grammar", args.grammar)

    return campaign_mode
