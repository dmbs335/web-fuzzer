"""Online correlation tracking between input properties and output divergences.

Uses discretized mutual information (MI) to discover which structural
properties of an XML input predict behavioral divergence across library
pairs.  No hardcoded domain knowledge — correlations are learned from
runtime observations.

Memory budget: ~3MB total (observation ring buffer + contingency tables).
CPU budget: O(num_properties) per observation, MI recompute every 500 obs.
"""

from __future__ import annotations

import math
from collections import deque
from typing import Any

from .property_vector import NUM_PROPERTIES, DivergenceVector, Observation
from .property_extractor import PROPERTY_NAMES
from .coverage_extractor import COV_FEATURE_NAMES, NUM_COV_FEATURES

_NUM_BINS = 4  # discretize each property into 4 quantile-based bins
_WINDOW_SIZE = 5000  # sliding window of observations
_MI_RECOMPUTE_INTERVAL = 500  # recompute MI every N observations
_BIN_RECOMPUTE_INTERVAL = 2000  # recompute quantile bin edges every N obs
_MIN_STRATEGY_TRIALS = 10  # min trials before trusting strategy effectiveness
_MAX_TRACKED_FIELDS = 30  # cap on divergence fields to track


class CorrelationTracker:
    """Online MI-based correlation between input properties and output divergences.

    Data structure: for each (property_i, divergence_field_j) pair,
    maintain a 4×2 contingency table:
      rows = property value binned into 4 quantile bins
      cols = divergence present (1) / absent (0)

    MI is recomputed every ``_MI_RECOMPUTE_INTERVAL`` observations.
    """

    def __init__(
        self,
        num_properties: int = NUM_PROPERTIES,
        window_size: int = _WINDOW_SIZE,
    ) -> None:
        self._num_props = num_properties
        self._window_size = window_size
        self._observations: deque[Observation] = deque(maxlen=window_size)

        # Divergence field registry (discovered at runtime)
        self._field_names: list[str] = []
        self._field_index: dict[str, int] = {}

        # Contingency tables: [prop_idx][field_idx] -> [bin][div_present]
        # Lazily sized as fields are discovered
        self._contingency: list[list[list[list[int]]]] = [
            [] for _ in range(num_properties)
        ]

        # Cached MI scores: [prop_idx][field_idx]
        self._mi_scores: list[list[float]] = [[] for _ in range(num_properties)]

        # Adaptive bin edges: [prop_idx] -> list of 3 boundary values
        # (splits into 4 bins). Initialized with equal-width bins.
        self._bin_edges: list[list[float]] = [
            [0.25, 0.5, 0.75] for _ in range(num_properties)
        ]

        # Property value buffer for quantile estimation
        self._prop_buffer: list[list[float]] = [[] for _ in range(num_properties)]
        self._prop_buffer_max = 500

        # Strategy effectiveness: strategy_name -> (divergence_hits, trials)
        self._strategy_outcomes: dict[str, list[int]] = {}  # [hits, trials]

        # ── Coverage feature tracking ────────────────────────
        self._num_cov_feats = NUM_COV_FEATURES
        self._cov_contingency: list[list[list[list[int]]]] = [
            [] for _ in range(NUM_COV_FEATURES)
        ]
        self._cov_mi_scores: list[list[float]] = [[] for _ in range(NUM_COV_FEATURES)]
        self._cov_bin_edges: list[list[float]] = [
            [0.25, 0.5, 0.75] for _ in range(NUM_COV_FEATURES)
        ]
        self._cov_buffer: list[list[float]] = [[] for _ in range(NUM_COV_FEATURES)]

        # Recompute counters
        self._obs_since_mi_recompute = 0
        self._obs_since_bin_recompute = 0

    def record(self, obs: Observation) -> None:
        """Record a new observation.  O(num_properties) per call."""
        # Evict oldest if window full
        if len(self._observations) == self._window_size:
            self._remove_from_contingency(self._observations[0])

        self._observations.append(obs)

        # Discover new divergence fields
        for d in obs.divergences:
            for field in d.field_diffs:
                self._ensure_field(field)

        # Add to contingency tables
        self._add_to_contingency(obs)

        # Track strategy outcomes
        divergent = obs.has_divergence
        for strat in obs.strategy_names:
            entry = self._strategy_outcomes.setdefault(strat, [0, 0])
            if divergent:
                entry[0] += 1
            entry[1] += 1

        # Buffer property values for quantile estimation
        for i, val in enumerate(obs.properties.values):
            buf = self._prop_buffer[i]
            if len(buf) < self._prop_buffer_max:
                buf.append(val)

        # ── Coverage feature contingency ─────────────────────
        if obs.coverage_features:
            self._add_cov_to_contingency(obs)
            for i, val in enumerate(obs.coverage_features):
                if i < self._num_cov_feats:
                    buf = self._cov_buffer[i]
                    if len(buf) < self._prop_buffer_max:
                        buf.append(val)

        # Periodic recomputation
        self._obs_since_mi_recompute += 1
        self._obs_since_bin_recompute += 1

        if self._obs_since_mi_recompute >= _MI_RECOMPUTE_INTERVAL:
            self._recompute_mi()
            self._obs_since_mi_recompute = 0

        if self._obs_since_bin_recompute >= _BIN_RECOMPUTE_INTERVAL:
            self._recompute_bin_edges()
            self._obs_since_bin_recompute = 0

    def top_correlations(self, k: int = 10) -> list[tuple[str, str, float]]:
        """Return top-k (property_name, divergence_field, MI_score) triples.

        Includes both structural property and coverage feature correlations.
        """
        if not self._field_names:
            return []

        entries: list[tuple[str, str, float]] = []

        # Structural property correlations
        for p in range(self._num_props):
            for f_idx, f_name in enumerate(self._field_names):
                if f_idx < len(self._mi_scores[p]):
                    mi = self._mi_scores[p][f_idx]
                    if mi > 0.001:
                        entries.append((PROPERTY_NAMES[p], f_name, mi))

        # Coverage feature correlations
        for c in range(self._num_cov_feats):
            for f_idx, f_name in enumerate(self._field_names):
                if f_idx < len(self._cov_mi_scores[c]):
                    mi = self._cov_mi_scores[c][f_idx]
                    if mi > 0.001:
                        entries.append((COV_FEATURE_NAMES[c], f_name, mi))

        entries.sort(key=lambda x: x[2], reverse=True)
        return entries[:k]

    def property_importance(self) -> list[tuple[int, float]]:
        """Return (property_idx, max_MI_over_all_fields) sorted descending.

        Used to focus mutation on the most predictive properties.
        """
        result: list[tuple[int, float]] = []
        for p in range(self._num_props):
            if self._mi_scores[p]:
                max_mi = max(self._mi_scores[p])
            else:
                max_mi = 0.0
            result.append((p, max_mi))
        result.sort(key=lambda x: x[1], reverse=True)
        return result

    def strategy_effectiveness(self) -> dict[str, float]:
        """Return strategy_name -> divergence_rate (empirical, not hardcoded).

        Only returns strategies with >= ``_MIN_STRATEGY_TRIALS`` trials.
        """
        result: dict[str, float] = {}
        for name, (hits, trials) in self._strategy_outcomes.items():
            if trials >= _MIN_STRATEGY_TRIALS:
                result[name] = hits / trials
        return result

    def get_stats(self) -> dict[str, Any]:
        """Return stats for reporting."""
        top = self.top_correlations(5)
        return {
            "observations": len(self._observations),
            "tracked_fields": len(self._field_names),
            "tracked_strategies": len(self._strategy_outcomes),
            "top_correlations": [
                {"prop": p, "field": f, "mi": round(mi, 4)}
                for p, f, mi in top
            ],
        }

    # ── Internal: field management ──────────────────────────────

    def _ensure_field(self, field_name: str) -> int:
        """Register a divergence field if not already known.  Returns index."""
        if field_name in self._field_index:
            return self._field_index[field_name]

        if len(self._field_names) >= _MAX_TRACKED_FIELDS:
            return -1  # cap reached, ignore

        idx = len(self._field_names)
        self._field_names.append(field_name)
        self._field_index[field_name] = idx

        # Extend contingency tables and MI scores for all properties
        for p in range(self._num_props):
            self._contingency[p].append([[0, 0] for _ in range(_NUM_BINS)])
            self._mi_scores[p].append(0.0)

        # Extend coverage contingency tables too
        for c in range(self._num_cov_feats):
            self._cov_contingency[c].append([[0, 0] for _ in range(_NUM_BINS)])
            self._cov_mi_scores[c].append(0.0)

        return idx

    # ── Internal: contingency table operations ──────────────────

    def _bin_value(self, prop_idx: int, value: float) -> int:
        """Assign a property value to a bin using current bin edges."""
        edges = self._bin_edges[prop_idx]
        for b, edge in enumerate(edges):
            if value <= edge:
                return b
        return _NUM_BINS - 1

    def _add_to_contingency(self, obs: Observation) -> None:
        """Add one observation to all contingency tables."""
        divergent_fields = obs.divergent_fields

        for p in range(self._num_props):
            if p >= len(obs.properties.values):
                break
            b = self._bin_value(p, obs.properties.values[p])

            for f_idx in range(len(self._field_names)):
                if f_idx >= len(self._contingency[p]):
                    break
                div_present = 1 if self._field_names[f_idx] in divergent_fields else 0
                self._contingency[p][f_idx][b][div_present] += 1

    def _remove_from_contingency(self, obs: Observation) -> None:
        """Remove one observation from all contingency tables."""
        divergent_fields = obs.divergent_fields

        for p in range(self._num_props):
            if p >= len(obs.properties.values):
                break
            b = self._bin_value(p, obs.properties.values[p])

            for f_idx in range(len(self._field_names)):
                if f_idx >= len(self._contingency[p]):
                    break
                div_present = 1 if self._field_names[f_idx] in divergent_fields else 0
                cell = self._contingency[p][f_idx][b]
                cell[div_present] = max(0, cell[div_present] - 1)

        # Also remove from coverage contingency
        self._remove_cov_from_contingency(obs)

    # ── Internal: coverage contingency operations ──────────────

    def _cov_bin_value(self, feat_idx: int, value: float) -> int:
        edges = self._cov_bin_edges[feat_idx]
        for b, edge in enumerate(edges):
            if value <= edge:
                return b
        return _NUM_BINS - 1

    def _add_cov_to_contingency(self, obs: Observation) -> None:
        if not obs.coverage_features:
            return
        divergent_fields = obs.divergent_fields
        for c in range(min(len(obs.coverage_features), self._num_cov_feats)):
            b = self._cov_bin_value(c, obs.coverage_features[c])
            for f_idx in range(len(self._field_names)):
                if f_idx >= len(self._cov_contingency[c]):
                    break
                div_present = 1 if self._field_names[f_idx] in divergent_fields else 0
                self._cov_contingency[c][f_idx][b][div_present] += 1

    def _remove_cov_from_contingency(self, obs: Observation) -> None:
        if not obs.coverage_features:
            return
        divergent_fields = obs.divergent_fields
        for c in range(min(len(obs.coverage_features), self._num_cov_feats)):
            b = self._cov_bin_value(c, obs.coverage_features[c])
            for f_idx in range(len(self._field_names)):
                if f_idx >= len(self._cov_contingency[c]):
                    break
                div_present = 1 if self._field_names[f_idx] in divergent_fields else 0
                cell = self._cov_contingency[c][f_idx][b]
                cell[div_present] = max(0, cell[div_present] - 1)

    # ── Internal: MI computation ────────────────────────────────

    def _recompute_mi(self) -> None:
        """Recompute MI from contingency tables (property + coverage)."""
        for p in range(self._num_props):
            for f_idx in range(len(self._field_names)):
                if f_idx >= len(self._contingency[p]):
                    break
                table = self._contingency[p][f_idx]
                self._mi_scores[p][f_idx] = self._compute_mi_from_table(table)

        # Coverage MI
        for c in range(self._num_cov_feats):
            for f_idx in range(len(self._field_names)):
                if f_idx >= len(self._cov_contingency[c]):
                    break
                table = self._cov_contingency[c][f_idx]
                self._cov_mi_scores[c][f_idx] = self._compute_mi_from_table(table)

    @staticmethod
    def _compute_mi_from_table(table: list[list[int]]) -> float:
        """Compute MI from a bins×2 contingency table."""
        total = 0
        for row in table:
            total += row[0] + row[1]
        if total < 20:  # not enough data
            return 0.0

        mi = 0.0
        # Row marginals (per bin)
        row_totals = [row[0] + row[1] for row in table]
        # Column marginals (divergent / not divergent)
        col_totals = [
            sum(row[0] for row in table),
            sum(row[1] for row in table),
        ]

        for b in range(_NUM_BINS):
            for d in range(2):
                joint = table[b][d]
                if joint == 0:
                    continue
                p_xy = joint / total
                p_x = row_totals[b] / total
                p_y = col_totals[d] / total
                if p_x > 0 and p_y > 0:
                    mi += p_xy * math.log2(p_xy / (p_x * p_y))

        return max(mi, 0.0)  # clamp numerical noise

    # ── Internal: adaptive binning ──────────────────────────────

    def _recompute_bin_edges(self) -> None:
        """Recompute quantile-based bin boundaries from buffered values.

        Uses approximate quantiles at 25%, 50%, 75%.
        """
        for p in range(self._num_props):
            buf = self._prop_buffer[p]
            if len(buf) < 20:
                continue  # not enough data, keep defaults

            sorted_buf = sorted(buf)
            n = len(sorted_buf)
            self._bin_edges[p] = [
                sorted_buf[n // 4],
                sorted_buf[n // 2],
                sorted_buf[3 * n // 4],
            ]

            # Ensure strictly increasing (add small epsilon if needed)
            for i in range(1, len(self._bin_edges[p])):
                if self._bin_edges[p][i] <= self._bin_edges[p][i - 1]:
                    self._bin_edges[p][i] = self._bin_edges[p][i - 1] + 1e-6

        # Clear buffers to avoid unbounded growth
        for buf in self._prop_buffer:
            buf.clear()

        # Coverage feature bin edges
        for c in range(self._num_cov_feats):
            buf = self._cov_buffer[c]
            if len(buf) < 20:
                continue
            sorted_buf = sorted(buf)
            n = len(sorted_buf)
            self._cov_bin_edges[c] = [
                sorted_buf[n // 4],
                sorted_buf[n // 2],
                sorted_buf[3 * n // 4],
            ]
            for i in range(1, len(self._cov_bin_edges[c])):
                if self._cov_bin_edges[c][i] <= self._cov_bin_edges[c][i - 1]:
                    self._cov_bin_edges[c][i] = self._cov_bin_edges[c][i - 1] + 1e-6

        for buf in self._cov_buffer:
            buf.clear()
