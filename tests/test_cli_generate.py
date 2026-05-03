"""CLI generation tests."""

from argparse import Namespace

from webfuzzer.cli import cmd_generate


def test_generate_preserves_raw_crlf_in_output_file(tmp_path):
    output = tmp_path / "hrs.wire"
    args = Namespace(
        grammar="request_smuggling_stream",
        rule="trailer_merge_stream",
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
    assert b"\r\r\n" not in data
    assert b"\r\n\r\n" in data
    assert b"X-WF-Family: trailer_merge" in data
