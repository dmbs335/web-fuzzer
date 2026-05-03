from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

from webfuzzer.fuzzer.campaign_manifest import (
    CampaignManifestInput,
    build_campaign_manifest,
    corpus_hash_for_manifest,
    infer_condition,
    infer_method,
    write_campaign_manifest,
)


def test_campaign_manifest_has_formal_research_required_shape(tmp_path):
    seeds = tmp_path / "seeds"
    seeds.mkdir()
    (seeds / "a.txt").write_text("seed-a", encoding="utf-8")

    manifest = build_campaign_manifest(
        CampaignManifestInput(
            grammar="saml",
            target_cmd="python target.py {input}",
            diff_cmds=("python ref.py {input}",),
            output_dir=tmp_path / "out",
            seed=3,
            count=100,
            timeout=60,
            cli="webfuzzer fuzz --grammar saml",
            seeds_dir=seeds,
            artifacts={"diff_trace": "diff_trace.jsonl"},
            options={"lattice_atoms": "atoms.json", "initial_seed_count": 10},
        )
    )

    assert manifest["schema_version"] == "1.0.0"
    assert manifest["producer"] == "web-fuzzer"
    assert manifest["domain"] == "saml"
    assert manifest["condition"] == "candidate"
    assert manifest["method"] == "lattice-atoms"
    assert manifest["seed"] == 3
    assert manifest["budget_seconds"] == 60.0
    assert manifest["budget_iterations"] == 100
    assert set(manifest["target_hashes"]) == {"primary", "ref0"}
    assert manifest["source_target_hash"].startswith("sha256:")
    assert manifest["source_corpus_hash"].startswith("sha256:")
    assert manifest["artifacts"]["diff_trace"] == "diff_trace.jsonl"
    assert manifest["artifacts"]["report"].endswith("report.json")


def test_campaign_manifest_method_and_condition_inference():
    assert infer_method({"scheduler": "entropic", "mutator_scheduler": "random"}) == "baseline"
    assert infer_method({"mcts": True, "guidance": "jwt"}) == "guidance:jwt+mcts"
    assert infer_method({"method": "danger-boost"}) == "danger-boost"
    assert infer_condition({"condition": "negative-control"}, "lattice-atoms") == "negative-control"
    assert infer_condition({}, "baseline") == "baseline"
    assert infer_condition({}, "lattice-atoms") == "candidate"


def test_campaign_manifest_corpus_hash_changes_with_seed_contents(tmp_path):
    seeds = tmp_path / "seeds"
    seeds.mkdir()
    seed_file = seeds / "seed.txt"
    seed_file.write_text("one", encoding="utf-8")
    first = corpus_hash_for_manifest(
        seeds_dir=seeds,
        grammar="json",
        seed=1,
        initial_seed_count=1,
    )

    seed_file.write_text("two", encoding="utf-8")
    second = corpus_hash_for_manifest(
        seeds_dir=seeds,
        grammar="json",
        seed=1,
        initial_seed_count=1,
    )

    assert first != second


def test_write_campaign_manifest_round_trips_json(tmp_path):
    manifest = build_campaign_manifest(
        CampaignManifestInput(
            grammar="json",
            target_cmd="python target.py {input}",
            output_dir=tmp_path,
            cli="webfuzzer fuzz --grammar json",
            options={"method": "baseline", "condition": "baseline"},
        )
    )
    path = tmp_path / "campaign_manifest.json"

    write_campaign_manifest(path, manifest)

    loaded = json.loads(path.read_text(encoding="utf-8"))
    assert loaded["run_id"] == manifest["run_id"]


def test_campaign_manifest_validates_against_formal_research_contract_when_available(tmp_path):
    research_root = Path(os.environ.get(
        "FUZZING_FORMAL_RESEARCH_DIR",
        r"C:\Users\dmbs3\fuzzing-formal-research",
    ))
    contract_path = (
        research_root
        / "experiments"
        / "fuzzing_formal_research"
        / "common"
        / "artifact_contracts.py"
    )
    if not contract_path.exists():
        return

    spec = importlib.util.spec_from_file_location("artifact_contracts_for_test", contract_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    manifest = build_campaign_manifest(
        CampaignManifestInput(
            grammar="jwt",
            target_cmd="python target.py {input}",
            output_dir=tmp_path,
            seed=1,
            timeout=30,
            cli="webfuzzer fuzz --grammar jwt",
            options={"method": "baseline", "condition": "baseline"},
        )
    )

    assert module.validate_artifact_record(manifest, "campaign_manifest") == []
