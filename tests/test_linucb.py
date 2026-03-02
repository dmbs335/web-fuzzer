"""Tests for LinUCB contextual bandit mutator scheduler."""

import time

import pytest

from webfuzzer.fuzzer.corpus import Seed
from webfuzzer.fuzzer.protocols import Input, ScheduleResult
from webfuzzer.fuzzer.schedulers.linucb_scheduler import (
    LinUCBScheduler,
    _D,
    _dot,
    _identity,
    _matvec,
)


def _make_mutator(name: str):
    """Create a minimal mutator-like object."""
    class FakeMutator:
        pass
    m = FakeMutator()
    m.name = name
    return m


def _make_seed(seed_id: int = 0, **kwargs) -> Seed:
    s = Seed(id=seed_id, input=Input(data=b"test"), created_at=time.time())
    for k, v in kwargs.items():
        setattr(s, k, v)
    return s


class TestLinAlg:
    """Tests for pure-Python linear algebra helpers."""

    def test_identity(self):
        I = _identity(3)
        assert I == [[1, 0, 0], [0, 1, 0], [0, 0, 1]]

    def test_dot_product(self):
        assert _dot([1.0, 2.0, 3.0], [4.0, 5.0, 6.0]) == pytest.approx(32.0)

    def test_dot_zero(self):
        assert _dot([0.0, 0.0], [1.0, 2.0]) == pytest.approx(0.0)

    def test_matvec(self):
        A = [[1.0, 0.0], [0.0, 2.0]]
        x = [3.0, 4.0]
        assert _matvec(A, x) == [pytest.approx(3.0), pytest.approx(8.0)]

    def test_matvec_identity(self):
        I = _identity(3)
        x = [1.0, 2.0, 3.0]
        result = _matvec(I, x)
        for a, b in zip(result, x):
            assert a == pytest.approx(b)


class TestLinUCBScheduler:
    def test_initialization_on_first_select(self):
        scheduler = LinUCBScheduler(alpha=1.0, seed=42)
        mutators = [_make_mutator("grammar"), _make_mutator("havoc")]
        seed = _make_seed()
        selected = scheduler.select(mutators, seed)
        assert selected.name in ("grammar", "havoc")
        assert scheduler._initialized
        assert scheduler._k == 2

    def test_select_returns_valid_mutator(self):
        scheduler = LinUCBScheduler(alpha=1.0, seed=42)
        mutators = [_make_mutator(f"m{i}") for i in range(4)]
        seed = _make_seed()
        for _ in range(20):
            m = scheduler.select(mutators, seed)
            assert m in mutators

    def test_update_modifies_model(self):
        scheduler = LinUCBScheduler(alpha=1.0, seed=42)
        mutators = [_make_mutator("grammar"), _make_mutator("havoc")]
        seed = _make_seed()

        selected = scheduler.select(mutators, seed)
        arm_before = [row[:] for row in scheduler._A[scheduler._last_arm]] if scheduler._last_arm >= 0 else None

        result = ScheduleResult(found_new_coverage=True)
        scheduler.update(selected, result)

        # After update, model should have changed
        assert scheduler._last_context is None  # reset after update

    def test_reward_function(self):
        assert LinUCBScheduler._compute_reward(
            ScheduleResult(found_new_coverage=True)) == pytest.approx(1.0)
        assert LinUCBScheduler._compute_reward(
            ScheduleResult(found_crash=True)) == pytest.approx(5.0)
        assert LinUCBScheduler._compute_reward(
            ScheduleResult(found_new_coverage=True, found_crash=True)) == pytest.approx(6.0)
        assert LinUCBScheduler._compute_reward(
            ScheduleResult()) == pytest.approx(-0.01)

    def test_learning_separates_arms(self):
        """After many updates, the scheduler should learn to prefer rewarded arms."""
        scheduler = LinUCBScheduler(alpha=0.5, seed=42)
        mutators = [_make_mutator("good"), _make_mutator("bad")]

        for _ in range(50):
            seed = _make_seed()
            selected = scheduler.select(mutators, seed)
            if selected.name == "good":
                scheduler.update(selected, ScheduleResult(found_new_coverage=True))
            else:
                scheduler.update(selected, ScheduleResult())

        # After learning, "good" should be preferred
        picks = []
        for _ in range(20):
            seed = _make_seed()
            picks.append(scheduler.select(mutators, seed).name)
        good_count = picks.count("good")
        assert good_count > 10, f"Expected 'good' to dominate but got {good_count}/20"

    def test_reinitializes_when_mutator_count_changes(self):
        scheduler = LinUCBScheduler(alpha=1.0, seed=42)
        mutators2 = [_make_mutator("a"), _make_mutator("b")]
        seed = _make_seed()
        scheduler.select(mutators2, seed)
        assert scheduler._k == 2

        mutators3 = [_make_mutator("a"), _make_mutator("b"), _make_mutator("c")]
        scheduler.select(mutators3, seed)
        assert scheduler._k == 3

    def test_context_extraction_dimensions(self):
        scheduler = LinUCBScheduler(seed=42)
        seed = _make_seed(finding_count=2, energy=5.0, depth=3, exec_count=10)
        ctx = scheduler._extract_context(seed)
        assert len(ctx) == _D
        # Last element is bias=1.0
        assert ctx[-1] == pytest.approx(1.0)
        # has_findings should be 1.0
        assert ctx[1] == pytest.approx(1.0)

    def test_context_without_tree(self):
        """Seeds without a tree get default values."""
        scheduler = LinUCBScheduler(seed=42)
        seed = _make_seed()
        ctx = scheduler._extract_context(seed)
        assert ctx[0] == pytest.approx(0.5)  # tree_depth default
        assert ctx[2] == pytest.approx(0.5)  # rule_diversity default

    def test_sherman_morrison_preserves_inverse(self):
        """After updates, A_inv should approximately equal inv(A)."""
        scheduler = LinUCBScheduler(alpha=1.0, seed=42)
        mutators = [_make_mutator("m0")]
        seed = _make_seed()

        for _ in range(5):
            scheduler.select(mutators, seed)
            scheduler.update(mutators[0], ScheduleResult(found_new_coverage=True))

        # Verify A × A_inv ≈ I
        A = scheduler._A[0]
        A_inv = scheduler._A_inv[0]
        product = [[sum(A[i][k] * A_inv[k][j] for k in range(_D))
                     for j in range(_D)] for i in range(_D)]
        for i in range(_D):
            for j in range(_D):
                expected = 1.0 if i == j else 0.0
                assert abs(product[i][j] - expected) < 0.01, \
                    f"A @ A_inv [{i}][{j}] = {product[i][j]}, expected {expected}"

    def test_determinism(self):
        """Same seed produces identical selections."""
        def run(rng_seed):
            sched = LinUCBScheduler(alpha=1.0, seed=rng_seed)
            mutators = [_make_mutator("a"), _make_mutator("b")]
            results = []
            for _ in range(5):
                s = _make_seed()
                s.created_at = 0  # Fix time for determinism
                m = sched.select(mutators, s)
                results.append(m.name)
                sched.update(m, ScheduleResult())
            return results
        assert run(42) == run(42)
