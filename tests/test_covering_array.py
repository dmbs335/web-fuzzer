"""Tests for the IPOG covering array generator."""

import itertools

import pytest

from webfuzzer.combinatorial.covering_array import generate_covering_array


class TestCoveringArray:
    """Core covering-array correctness tests."""

    def test_pairwise_coverage_3x3(self):
        """All pairs are covered for 3 params × 3 values each."""
        params = [["a", "b", "c"]] * 3
        ca = generate_covering_array(params, strength=2, seed=42)

        # Check all pairs of parameters are covered
        for p1, p2 in itertools.combinations(range(3), 2):
            seen_pairs = set()
            for row in ca:
                seen_pairs.add((row[p1], row[p2]))
            expected = {(v1, v2) for v1 in params[p1] for v2 in params[p2]}
            assert seen_pairs == expected, f"Missing pairs for params ({p1}, {p2})"

    def test_pairwise_coverage_mixed_sizes(self):
        """Pairwise coverage for parameters with different numbers of values."""
        params = [
            ["x", "y"],          # 2 values
            ["a", "b", "c"],     # 3 values
            ["1", "2", "3", "4"],  # 4 values
        ]
        ca = generate_covering_array(params, strength=2, seed=42)

        for p1, p2 in itertools.combinations(range(3), 2):
            seen = set()
            for row in ca:
                seen.add((row[p1], row[p2]))
            expected = {(v1, v2) for v1 in params[p1] for v2 in params[p2]}
            assert seen == expected

    def test_determinism_with_seed(self):
        """Same seed produces identical output."""
        params = [["a", "b", "c"]] * 4
        ca1 = generate_covering_array(params, strength=2, seed=123)
        ca2 = generate_covering_array(params, strength=2, seed=123)
        assert ca1 == ca2

    def test_different_seeds_may_differ(self):
        """Different seeds can produce different arrays."""
        params = [["a", "b", "c"]] * 5
        ca1 = generate_covering_array(params, strength=2, seed=1)
        ca2 = generate_covering_array(params, strength=2, seed=999)
        # They should both cover all pairs, but order/extra rows may differ
        assert len(ca1) > 0
        assert len(ca2) > 0

    def test_size_within_bounds(self):
        """Array size is within reasonable bounds for pairwise."""
        # 5 params × 3 values each — theoretical min is ~9 rows for pairwise
        params = [["a", "b", "c"]] * 5
        ca = generate_covering_array(params, strength=2, seed=42)
        # Should be reasonable: at most 2× the max(v_i × v_j) = 9
        assert len(ca) <= 30, f"Array too large: {len(ca)} rows"
        assert len(ca) >= 9, f"Array too small: {len(ca)} rows (minimum 9)"

    def test_single_parameter(self):
        """Single parameter returns one row per value."""
        params = [["x", "y", "z"]]
        ca = generate_covering_array(params, strength=1, seed=42)
        values = [row[0] for row in ca]
        assert set(values) == {"x", "y", "z"}

    def test_empty_parameters(self):
        """Empty parameter list returns empty array."""
        assert generate_covering_array([], strength=2) == []

    def test_strength_exceeds_param_count(self):
        """Strength clamped to number of parameters."""
        params = [["a", "b"], ["x", "y"]]
        ca = generate_covering_array(params, strength=5, seed=42)
        # Clamped to strength=2, which is exhaustive for 2 params
        assert len(ca) == 4  # 2 × 2

    def test_strength_1_covers_all_values(self):
        """1-way coverage means every value of every parameter appears."""
        params = [["a", "b", "c"], ["x", "y"], ["1", "2", "3", "4"]]
        ca = generate_covering_array(params, strength=1, seed=42)
        for pi, values in enumerate(params):
            seen = {row[pi] for row in ca}
            assert seen == set(values)

    def test_3way_coverage(self):
        """3-way coverage for small problem."""
        params = [["a", "b"], ["x", "y"], ["1", "2"]]
        ca = generate_covering_array(params, strength=3, seed=42)
        # 3-way with 3 params is exhaustive: 2×2×2 = 8
        assert len(ca) == 8
        all_triples = set()
        for row in ca:
            all_triples.add(tuple(row))
        assert len(all_triples) == 8

    def test_invalid_strength(self):
        """Strength < 1 raises ValueError."""
        with pytest.raises(ValueError):
            generate_covering_array([["a"]], strength=0)

    def test_all_rows_have_correct_width(self):
        """Every row has one value per parameter."""
        params = [["a", "b"], ["x", "y", "z"], ["1", "2"]]
        ca = generate_covering_array(params, strength=2, seed=42)
        for row in ca:
            assert len(row) == 3
            assert row[0] in params[0]
            assert row[1] in params[1]
            assert row[2] in params[2]

    def test_7_parameters_url_like(self):
        """Covering array for a URL-like parameter space (7 dimensions)."""
        params = [
            ["http", "https", "ftp"],       # scheme
            ["none", "user@"],               # userinfo
            ["example.com", "127.0.0.1"],    # host
            ["none", "80", "8080"],           # port
            ["/", "/path", "/../"],           # path
            ["none", "?q=1"],                # query
            ["none", "#frag"],               # fragment
        ]
        ca = generate_covering_array(params, strength=2, seed=42)

        # Check pairwise coverage
        for p1, p2 in itertools.combinations(range(7), 2):
            seen = {(row[p1], row[p2]) for row in ca}
            expected = {(v1, v2) for v1 in params[p1] for v2 in params[p2]}
            assert seen == expected, f"Missing pairs for params ({p1}, {p2})"
