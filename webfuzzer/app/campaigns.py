"""Campaign presets and CLI helpers."""

from __future__ import annotations

from pathlib import Path

CAMPAIGN_PRESETS = {
    "hrs_deep": {
        "campaign_mode": "hrs_deep",
        "oracle": "request_smuggling",
        "mutators": "request_smuggling,grammar,havoc",
        "seeds_dir": "seeds/request_smuggling",
        "grammar": "request_smuggling_stream",
        "adaptive_coverage": True,
        "adaptive_level": 2,
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
