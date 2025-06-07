"""Smart attack orchestrator — chains attack phases in optimal order."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

from hashcrack.cracker import crack_parallel, crack_sequential
from hashcrack.models import (
    AttackPhase,
    CrackResult,
    HashTarget,
    LLMConfig,
    TargetProfile,
)
from hashcrack.adaptive_profiler import AdaptiveProfiler
from hashcrack.profiler import AIProfiler, LocalProfiler
from hashcrack.rules import QUICK_RULES, THOROUGH_RULES, Rule, rule_candidates
from hashcrack.wordlist import file_candidates


@dataclass(frozen=True)
class AttackPlan:
    """Immutable descriptor for one attack phase."""

    name: str
    phase: AttackPhase
    candidates_fn: Callable[[], Iterator[str]]


# ---------------------------------------------------------------------------
# Profiler selection
# ---------------------------------------------------------------------------


def _select_profiler(
    profile: TargetProfile,
    llm_config: LLMConfig | None,
) -> LocalProfiler | AIProfiler:
    """Return AIProfiler when llm_config has an api_key, otherwise LocalProfiler."""
    if llm_config is not None and llm_config.api_key:
        return AIProfiler(llm_config)
    return LocalProfiler()


def _rules_for_preset(preset: str) -> tuple[Rule, ...]:
    """Return the rule tuple matching *preset*. Defaults to QUICK_RULES."""
    if preset == "thorough":
        return THOROUGH_RULES
    return QUICK_RULES


# ---------------------------------------------------------------------------
# Plan builder
# ---------------------------------------------------------------------------


def plan_attacks(
    wordlist_path: Path,
    rules_preset: str = "quick",
    profile: TargetProfile | None = None,
    llm_config: LLMConfig | None = None,
) -> list[AttackPlan]:
    """Build an ordered list of AttackPlan objects for the given configuration.

    Phase ordering:
    1. DICTIONARY  — plain wordlist
    2. RULES       — wordlist + rule mutations (skipped when rules_preset=="none")
    3. PROFILE     — profile-derived candidates (skipped when profile is None)
    4. HYBRID      — profile candidates + rule mutations (only when both profile
                     and rules are active)

    Args:
        wordlist_path:  Path to the base wordlist file.
        rules_preset:   One of "none", "quick", or "thorough".
        profile:        Optional target profile for personalised candidates.
        llm_config:     Optional LLM config; enables AIProfiler when api_key set.

    Returns:
        Ordered list of :class:`AttackPlan` objects.
    """
    plans: list[AttackPlan] = []
    rules_active = rules_preset != "none"

    # Phase 1 — dictionary
    plans.append(
        AttackPlan(
            name="Dictionary",
            phase=AttackPhase.DICTIONARY,
            candidates_fn=lambda: file_candidates(wordlist_path),
        )
    )

    # Phase 2 — rules
    if rules_active:
        rules = _rules_for_preset(rules_preset)
        plans.append(
            AttackPlan(
                name=f"Dictionary + {rules_preset.capitalize()} Rules",
                phase=AttackPhase.RULES,
                candidates_fn=lambda r=rules: rule_candidates(
                    file_candidates(wordlist_path), r
                ),
            )
        )

    # Phase 3 — profile
    if profile is not None:
        profiler = _select_profiler(profile, llm_config)
        plans.append(
            AttackPlan(
                name="Profile",
                phase=AttackPhase.PROFILE,
                candidates_fn=lambda p=profiler, pr=profile: p.generate(pr),
            )
        )

        # Phase 4 — hybrid
        if rules_active:
            rules = _rules_for_preset(rules_preset)
            plans.append(
                AttackPlan(
                    name=f"Profile + {rules_preset.capitalize()} Rules",
                    phase=AttackPhase.HYBRID,
                    candidates_fn=lambda p=profiler, pr=profile, r=rules: rule_candidates(
                        p.generate(pr), r
                    ),
                )
            )

    # Phase 5 — adaptive AI (multi-round)
    if profile is not None and llm_config is not None and llm_config.api_key:
        adaptive = AdaptiveProfiler(llm_config, max_rounds=3)
        def _adaptive_candidates(a=adaptive, pr=profile):
            for round_result in a.generate_all_rounds(pr):
                yield from round_result.candidates
        plans.append(
            AttackPlan(
                name="Adaptive AI",
                phase=AttackPhase.ADAPTIVE,
                candidates_fn=_adaptive_candidates,
            )
        )

    return plans


# ---------------------------------------------------------------------------
# Orchestrated runner
# ---------------------------------------------------------------------------


def _merge_results(
    base: CrackResult,
    phase_result: CrackResult,
    phase: AttackPhase,
) -> CrackResult:
    """Return a new CrackResult with accumulated attempts/duration and found state."""
    total_attempts = base.attempts + phase_result.attempts
    total_duration = base.duration_seconds + phase_result.duration_seconds

    if phase_result.found:
        return CrackResult(
            found=True,
            plaintext=phase_result.plaintext,
            hash_type=phase_result.hash_type,
            attack_phase=phase,
            attempts=total_attempts,
            duration_seconds=total_duration,
        )

    return CrackResult(
        found=False,
        attempts=total_attempts,
        duration_seconds=total_duration,
    )


def run_orchestrated(
    target: HashTarget,
    plans: list[AttackPlan],
    max_workers: int | None = None,
    batch_size: int = 10_000,
    on_progress: Callable[[int], None] | None = None,
    on_phase_change: Callable[[str, int, int], None] | None = None,
) -> CrackResult:
    """Execute attack plans in order, stopping on first successful crack.

    Args:
        target:          The hash to crack.
        plans:           Ordered list of :class:`AttackPlan` objects from
                         :func:`plan_attacks`.
        max_workers:     Worker count for parallel cracking. ``1`` forces
                         sequential mode; ``None`` uses :func:`os.cpu_count`.
        batch_size:      Candidates per work chunk (parallel mode only).
        on_progress:     Called with the number of candidates in each completed
                         chunk/candidate.
        on_phase_change: Called when a new phase begins with
                         ``(phase_name, phase_index, total_phases)``.

    Returns:
        A :class:`~hashcrack.models.CrackResult` from the winning phase,
        or a not-found result accumulating all attempts if every phase fails.
    """
    total_phases = len(plans)
    accumulated = CrackResult(found=False)

    for idx, plan in enumerate(plans):
        if on_phase_change is not None:
            on_phase_change(plan.name, idx, total_phases)

        candidates = plan.candidates_fn()

        if max_workers == 1:
            phase_result = crack_sequential(
                target,
                candidates,
                on_progress=on_progress,
            )
        else:
            phase_result = crack_parallel(
                target,
                candidates,
                max_workers=max_workers,
                batch_size=batch_size,
                on_progress=on_progress,
            )

        accumulated = _merge_results(accumulated, phase_result, plan.phase)

        if accumulated.found:
            return accumulated

    return accumulated
