"""Smart attack orchestrator — chains attack phases in optimal order."""

from __future__ import annotations

import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

from smartcrack.cracker import crack_parallel, crack_sequential
from smartcrack.models import (
    AttackPhase,
    CrackResult,
    CrackSession,
    HashTarget,
    LLMConfig,
    TargetProfile,
)
from smartcrack.mask import generate_ai_masks, mask_candidates
from smartcrack.profiler import LocalProfiler
from smartcrack.rules import QUICK_RULES, THOROUGH_RULES, Rule, rule_candidates
from smartcrack.wordlist import file_candidates, file_candidates_from_offset


@dataclass(frozen=True)
class AttackPlan:
    """Immutable descriptor for one attack phase."""

    name: str
    phase: AttackPhase
    candidates_fn: Callable[[], Iterator[str]]


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
    wordlist_offset: int = 0,
    mask_pattern: str | None = None,
    ai_masks: bool = False,
    rainbow_table_path: Path | None = None,
    combo_wordlist_path: Path | None = None,
    expand_knowledge: bool = False,
) -> list[AttackPlan]:
    """Build an ordered list of AttackPlan objects for the given configuration.

    Phase ordering:
    0. RAINBOW     — rainbow table instant lookup (when rainbow_table_path provided)
    1. DICTIONARY  — plain wordlist
    2. RULES       — wordlist + rule mutations (skipped when rules_preset=="none")
    2.5 COMBO      — combo attack (when combo_wordlist_path provided)
    3. MASK        — mask attack (when mask_pattern or ai_masks is set)
    4. PROFILE     — profile-derived candidates (skipped when profile is None
                     or expand_knowledge is True)
    5. HYBRID      — profile candidates + rule mutations (only when both profile
                     and rules are active; skipped when expand_knowledge is True)

    Args:
        wordlist_path:  Path to the base wordlist file.
        rules_preset:   One of "none", "quick", or "thorough".
        profile:        Optional target profile for personalised candidates.
        llm_config:     Optional LLM config; enables AIProfiler when api_key set.
        wordlist_offset: Number of lines to skip in the wordlist for DICTIONARY
                         phase (used for session resume).
        mask_pattern:   Optional manual mask string (e.g. "?u?l?l?l?d?d?d").
        ai_masks:       When True, generate masks via LLM from profile data.
        rainbow_table_path: Optional path to a binary rainbow table file.
        combo_wordlist_path: Optional path to a second wordlist for combo attack.
        expand_knowledge: When True and LLM available, run knowledge expansion
                          to extract cultural keywords before profile phase.

    Returns:
        Ordered list of :class:`AttackPlan` objects.
    """
    plans: list[AttackPlan] = []
    rules_active = rules_preset != "none"

    # Phase 0 — rainbow table (instant lookup)
    if rainbow_table_path is not None:
        import struct as _struct

        def _rainbow_candidates(table_path: Path = rainbow_table_path) -> Iterator[str]:
            with open(table_path, "rb") as f:
                raw = f.read(32)
                if len(raw) < 32:
                    return
                _magic, _ver, _ht, count, hex_len, pt_len = _struct.unpack(
                    ">4sBBIHH18x", raw
                )
                record_size = hex_len + pt_len
                for _ in range(count):
                    record = f.read(record_size)
                    if len(record) < record_size:
                        return
                    plaintext = record[hex_len:].rstrip(b"\x00").decode("utf-8")
                    if plaintext:
                        yield plaintext

        plans.append(
            AttackPlan(
                name="Rainbow Table",
                phase=AttackPhase.RAINBOW,
                candidates_fn=_rainbow_candidates,
            )
        )

    # Phase 1 — dictionary
    plans.append(
        AttackPlan(
            name="Dictionary",
            phase=AttackPhase.DICTIONARY,
            candidates_fn=lambda o=wordlist_offset: file_candidates_from_offset(
                wordlist_path, o
            ),
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

    # Phase 2.5 — combo
    if combo_wordlist_path is not None:
        from smartcrack.combo import combo_candidates as _combo_gen

        plans.append(
            AttackPlan(
                name="Combo Attack",
                phase=AttackPhase.COMBO,
                candidates_fn=lambda cp=combo_wordlist_path: _combo_gen(
                    wordlist_path, cp
                ),
            )
        )

    # Phase 3 — mask (manual or AI-generated)
    if mask_pattern is not None:
        plans.append(
            AttackPlan(
                name=f"Mask ({mask_pattern})",
                phase=AttackPhase.MASK,
                candidates_fn=lambda m=mask_pattern: mask_candidates(m),
            )
        )

    if ai_masks and profile is not None and llm_config is not None and llm_config.api_key:
        def _ai_mask_candidates(
            pr: TargetProfile = profile,
            cfg: LLMConfig = llm_config,
        ) -> Iterator[str]:
            masks = generate_ai_masks(pr, cfg)
            for m in masks:
                yield from mask_candidates(m)

        plans.append(
            AttackPlan(
                name="AI-Generated Masks",
                phase=AttackPhase.MASK,
                candidates_fn=_ai_mask_candidates,
            )
        )

    # Phase 3.5 — knowledge-expanded profile (single LLM call for cultural keywords)
    if expand_knowledge and profile is not None and llm_config is not None and llm_config.api_key:
        from smartcrack.expanded_combo import generate_from_expanded
        from smartcrack.knowledge_expander import expand_profile

        expanded = expand_profile(profile, llm_config)
        plans.append(
            AttackPlan(
                name="Knowledge-Expanded Profile",
                phase=AttackPhase.EXPANDED_PROFILE,
                candidates_fn=lambda e=expanded: generate_from_expanded(e),
            )
        )

    # Phase 4 — profile (skipped when expand_knowledge replaces it)
    if profile is not None and not expand_knowledge:
        profiler = LocalProfiler()
        plans.append(
            AttackPlan(
                name="Profile",
                phase=AttackPhase.PROFILE,
                candidates_fn=lambda p=profiler, pr=profile: p.generate(pr),
            )
        )

        # Phase 5 — hybrid
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
    session: CrackSession | None = None,
    timeout_seconds: int = 0,
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
        session:         Optional mutable session for save/resume. When provided,
                         phases listed in ``session.phases_completed`` are skipped
                         and session fields are updated in-place as execution
                         progresses.
        timeout_seconds: Wall-clock timeout in seconds. ``0`` means no timeout.
                         When exceeded, no new phase will start and the
                         accumulated not-found result is returned.

    Returns:
        A :class:`~smartcrack.models.CrackResult` from the winning phase,
        or a not-found result accumulating all attempts if every phase fails.
    """
    if timeout_seconds < 0:
        raise ValueError(f"timeout_seconds must be >= 0, got {timeout_seconds}")

    total_phases = len(plans)
    accumulated = CrackResult(found=False)
    deadline = (time.monotonic() + timeout_seconds) if timeout_seconds > 0 else 0.0

    for idx, plan in enumerate(plans):
        # Check wall-clock timeout before starting a new phase
        if deadline and time.monotonic() >= deadline:
            break

        # Skip phases already completed in a previous session run
        if session is not None and plan.phase.value in session.phases_completed:
            session.current_phase = plan.phase
            continue

        if session is not None:
            session.current_phase = plan.phase

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

        # Update session state after each phase
        if session is not None:
            session.candidates_tried += phase_result.attempts
            session.phases_completed = (
                *session.phases_completed,
                plan.phase.value,
            )
            # In a plain dictionary phase, attempts == lines read (one attempt per candidate).
            if plan.phase == AttackPhase.DICTIONARY:
                session.wordlist_offset += phase_result.attempts

        if accumulated.found:
            if session is not None:
                session.completed = True
                session.result = accumulated
            return accumulated

    if session is not None:
        session.completed = True
        session.result = accumulated

    return accumulated
