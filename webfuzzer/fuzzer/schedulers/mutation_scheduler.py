"""MOPT/DARWIN mutation operator scheduling.

MOPT (USENIX Security'19): Uses Particle Swarm Optimization to find
optimal mutation operator selection probabilities.

DARWIN (NDSS'23): Uses an Evolution Strategy to optimize mutation
operator distributions. No hyperparameters required.

This module implements both as MutatorScheduler Protocol implementations.
"""

from __future__ import annotations

import math
import random
from typing import TYPE_CHECKING

from ..protocols import Mutator, ScheduleResult

if TYPE_CHECKING:
    from ..corpus import Seed


class MOPTScheduler:
    """MOPT: PSO-based mutation operator scheduling.

    Maintains a probability distribution over mutators and optimizes
    it using Particle Swarm Optimization.

    velocity_i = w*v_i + c1*r1*(pbest_i - p_i) + c2*r2*(gbest_i - p_i)
    p_i = p_i + velocity_i
    """

    def __init__(
        self,
        seed: int | None = None,
        w: float = 0.7,        # inertia weight
        c1: float = 1.5,       # cognitive coefficient
        c2: float = 1.5,       # social coefficient
        epoch_size: int = 500,  # iterations per PSO epoch
    ) -> None:
        self.rng = random.Random(seed)
        self.w = w
        self.c1 = c1
        self.c2 = c2
        self.epoch_size = epoch_size

        self._initialized = False
        self._k = 0                           # number of mutators
        self._probs: list[float] = []         # current probabilities
        self._velocities: list[float] = []    # PSO velocities
        self._pbest: list[float] = []         # personal best
        self._gbest: list[float] = []         # global best
        self._pbest_fitness: float = 0.0
        self._gbest_fitness: float = 0.0

        # Epoch tracking
        self._epoch_iter = 0
        self._epoch_new_cov = 0
        self._epoch_crashes = 0

    def _init_particles(self, k: int) -> None:
        self._k = k
        uniform = 1.0 / k
        self._probs = [uniform] * k
        self._velocities = [0.0] * k
        self._pbest = [uniform] * k
        self._gbest = [uniform] * k
        self._initialized = True

    def select(self, mutators: list[Mutator], seed: Seed) -> Mutator:
        if not self._initialized or self._k != len(mutators):
            self._init_particles(len(mutators))

        chosen = self.rng.choices(mutators, weights=self._probs, k=1)[0]
        return chosen

    def update(self, mutator: Mutator, result: ScheduleResult) -> None:
        self._epoch_iter += 1
        if result.found_new_coverage:
            self._epoch_new_cov += 1
        if result.found_crash:
            self._epoch_crashes += 1

        if self._epoch_iter >= self.epoch_size:
            self._pso_step()
            self._epoch_iter = 0
            self._epoch_new_cov = 0
            self._epoch_crashes = 0

    def _pso_step(self) -> None:
        """One PSO epoch: update velocities and positions."""
        fitness = self._epoch_new_cov + self._epoch_crashes * 5

        # Update personal best
        if fitness > self._pbest_fitness:
            self._pbest = list(self._probs)
            self._pbest_fitness = fitness

        # Update global best
        if fitness > self._gbest_fitness:
            self._gbest = list(self._probs)
            self._gbest_fitness = fitness

        # Update velocities and positions
        for i in range(self._k):
            r1 = self.rng.random()
            r2 = self.rng.random()
            self._velocities[i] = (
                self.w * self._velocities[i]
                + self.c1 * r1 * (self._pbest[i] - self._probs[i])
                + self.c2 * r2 * (self._gbest[i] - self._probs[i])
            )
            self._probs[i] = max(self._probs[i] + self._velocities[i], 0.01)

        # Normalize to sum to 1
        total = sum(self._probs)
        if total > 0:
            self._probs = [p / total for p in self._probs]


class DARWINScheduler:
    """DARWIN: Evolution Strategy for mutation operator scheduling.

    Maintains a population of probability distributions over mutators.
    Each epoch: evaluate fitness → selection → mutation.
    No hyperparameters needed.
    """

    def __init__(
        self,
        seed: int | None = None,
        population_size: int = 10,
        epoch_size: int = 500,
    ) -> None:
        self.rng = random.Random(seed)
        self.pop_size = population_size
        self.epoch_size = epoch_size

        self._initialized = False
        self._k = 0
        self._population: list[list[float]] = []
        self._fitness: list[float] = []
        self._current_idx = 0

        self._epoch_iter = 0
        self._epoch_new_cov = 0
        self._epoch_crashes = 0

    def _init_population(self, k: int) -> None:
        self._k = k
        self._population = []
        for _ in range(self.pop_size):
            individual = [self.rng.random() for _ in range(k)]
            total = sum(individual)
            individual = [p / total for p in individual]
            self._population.append(individual)
        self._fitness = [0.0] * self.pop_size
        self._current_idx = 0
        self._initialized = True

    def select(self, mutators: list[Mutator], seed: Seed) -> Mutator:
        if not self._initialized or self._k != len(mutators):
            self._init_population(len(mutators))

        probs = self._population[self._current_idx]
        chosen = self.rng.choices(mutators, weights=probs, k=1)[0]
        return chosen

    def update(self, mutator: Mutator, result: ScheduleResult) -> None:
        self._epoch_iter += 1
        if result.found_new_coverage:
            self._epoch_new_cov += 1
        if result.found_crash:
            self._epoch_crashes += 1

        if self._epoch_iter >= self.epoch_size:
            fitness = self._epoch_new_cov + self._epoch_crashes * 5
            self._fitness[self._current_idx] = fitness

            self._current_idx += 1
            if self._current_idx >= self.pop_size:
                self._evolve()
                self._current_idx = 0

            self._epoch_iter = 0
            self._epoch_new_cov = 0
            self._epoch_crashes = 0

    def _evolve(self) -> None:
        """Selection + mutation on the population."""
        # Sort by fitness (descending)
        ranked = sorted(
            range(self.pop_size),
            key=lambda i: self._fitness[i],
            reverse=True,
        )

        # Keep top half as parents
        parents = [self._population[i] for i in ranked[:self.pop_size // 2]]

        # Generate new population via mutation
        new_pop: list[list[float]] = []
        for parent in parents:
            new_pop.append(list(parent))  # keep parent
            # Mutate to create child
            child = list(parent)
            for i in range(self._k):
                child[i] += self.rng.gauss(0, 0.05)
                child[i] = max(child[i], 0.01)
            total = sum(child)
            child = [p / total for p in child]
            new_pop.append(child)

        self._population = new_pop[:self.pop_size]
        self._fitness = [0.0] * self.pop_size
