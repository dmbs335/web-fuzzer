"""CLI generation tests for pgwire grammar."""

from argparse import Namespace

from webfuzzer.cli import cmd_generate


def test_generate_pgwire_transcript(tmp_path):
    output = tmp_path / "session.pgwire"
    args = Namespace(
        grammar="pgsql_wire_session",
        rule=None,
        count=1,
        seed=42,
        max_depth=None,
        grammar_dir=None,
        no_builtins=False,
        output=output,
        separator="\n---\n",
    )

    rc = cmd_generate(args)

    data = output.read_bytes()
    assert rc == 0
    assert data.startswith(b"WFPG1\nM ")
    assert b'"transport_mode":"pgsql_v3"' in data
