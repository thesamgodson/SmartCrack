"""CLI entry point using Typer."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn

from hashcrack import __version__
from hashcrack.hash_id import identify_hash
from hashcrack.hashers import verify_any
from hashcrack.models import AttackPhase, HashTarget, HashType, LLMConfig, TargetProfile
from hashcrack.orchestrator import AttackPlan, plan_attacks, run_orchestrated
from hashcrack.wordlist import file_candidates, resolve_wordlist

app = typer.Typer(
    name="hashcrack",
    help="Intelligent hash cracking platform with AI-powered profiling.",
    no_args_is_help=True,
)
console = Console()

BANNER = r"""
 _               _                         _
| |__   __ _ ___| |__   ___ _ __ __ _  ___| | __
| '_ \ / _` / __| '_ \ / __| '__/ _` |/ __| |/ /
| | | | (_| \__ | | | | (__| | | (_| | (__|   <
|_| |_|\__,_|___|_| |_|\___|_|  \__,_|\___|_|\_\
"""


def _print_banner() -> None:
    console.print(BANNER, style="bold cyan")
    console.print(f"  v{__version__} — Intelligent Hash Cracking Platform\n", style="dim")


@app.command()
def crack(
    hash_value: str = typer.Option(..., "--hash", "-H", help="Hash to crack"),
    wordlist: Path = typer.Option(Path("100K.txt"), "--wordlist", "-w", help="Wordlist file path"),
    salt: str = typer.Option("", "--salt", "-s", help="Salt to append to candidates"),
    hash_type: str = typer.Option("auto", "--type", "-t", help="Hash type (auto, md5, sha1, etc.)"),
) -> None:
    """Crack a hash using dictionary attack."""
    _print_banner()

    resolved_path = resolve_wordlist(wordlist)
    console.print(f"[bold]Target:[/] {hash_value}")
    console.print(f"[bold]Wordlist:[/] {resolved_path}")

    type_map: dict[str, HashType] = {
        "md5": HashType.MD5,
        "sha1": HashType.SHA1,
        "sha224": HashType.SHA224,
        "sha256": HashType.SHA256,
        "sha384": HashType.SHA384,
        "sha512": HashType.SHA512,
    }

    resolved_type: HashType
    if hash_type.lower() == "auto":
        candidates = identify_hash(hash_value)
        resolved_type = candidates[0][0] if candidates else HashType.UNKNOWN
        console.print(f"[bold]Detected type:[/] {resolved_type.name}")
    else:
        resolved_type = type_map.get(hash_type.lower(), HashType.UNKNOWN)

    target = HashTarget(
        hash_value=hash_value,
        salt=salt,
        hash_type=resolved_type,
    )

    console.print("\n[yellow][*] Cracking...[/]")
    start = time.perf_counter()
    attempts = 0

    for candidate in file_candidates(resolved_path):
        attempts += 1
        matched_type = verify_any(candidate, target)
        if matched_type is not None:
            elapsed = time.perf_counter() - start
            console.print(f"\n[green][+] Cracked:[/] [bold]{candidate}[/]")
            console.print(f"[green][+] Algorithm:[/] {matched_type.name}")
            console.print(f"[green][+] Attempts:[/] {attempts:,}")
            console.print(f"[green][+] Time:[/] {elapsed:.2f}s")
            return

    elapsed = time.perf_counter() - start
    console.print(f"\n[red][-] Not found after {attempts:,} attempts ({elapsed:.2f}s)[/]")
    console.print("[dim]Try a larger wordlist or enable rules: --rules quick[/]")


@app.command()
def identify(
    hash_value: str = typer.Option(..., "--hash", "-H", help="Hash to identify"),
) -> None:
    """Identify the type(s) of a hash."""
    _print_banner()
    console.print(f"[bold]Hash:[/] {hash_value}\n")

    results = identify_hash(hash_value)
    for hash_type, confidence in results:
        pct = f"{confidence * 100:.0f}%"
        console.print(f"  [cyan]{hash_type.name:<12}[/]  confidence: [bold]{pct}[/]")


@app.command()
def smart(
    hash_value: str = typer.Option(..., "--hash", "-H", help="Hash to crack"),
    wordlist: Path = typer.Option(Path("100K.txt"), "--wordlist", "-w", help="Wordlist file path"),
    salt: str = typer.Option("", "--salt", "-s", help="Salt to append to candidates"),
    hash_type: str = typer.Option("auto", "--type", "-t", help="Hash type (auto, md5, sha1, …)"),
    rules: str = typer.Option("quick", "--rules", "-r", help="Rules preset: none | quick | thorough"),
    workers: Optional[int] = typer.Option(None, "--workers", help="Worker count (default: cpu count)"),
    profile_name: str = typer.Option("", "--profile-name", help="Target first name"),
    profile_lastname: str = typer.Option("", "--profile-lastname", help="Target last name"),
    profile_birthdate: str = typer.Option("", "--profile-birthdate", help="Target birthdate (YYYY-MM-DD)"),
    profile_nickname: str = typer.Option("", "--profile-nickname", help="Target nickname"),
    profile_partner: str = typer.Option("", "--profile-partner", help="Partner name"),
    profile_partner_birthdate: str = typer.Option("", "--profile-partner-birthdate", help="Partner birthdate (YYYY-MM-DD)"),
    profile_pet: str = typer.Option("", "--profile-pet", help="Pet name"),
    profile_child: str = typer.Option("", "--profile-child", help="Child name"),
    profile_keywords: str = typer.Option("", "--profile-keywords", help="Comma-separated keywords"),
    profile_numbers: str = typer.Option("", "--profile-numbers", help="Comma-separated special numbers"),
    llm_base_url: str = typer.Option("", "--llm-base-url", envvar="HASHCRACK_LLM_BASE_URL", help="LLM API base URL"),
    llm_api_key: str = typer.Option("", envvar="HASHCRACK_LLM_API_KEY", help="LLM API key (use env var HASHCRACK_LLM_API_KEY)", hidden=True),
    llm_model: str = typer.Option("", "--llm-model", envvar="HASHCRACK_LLM_MODEL", help="LLM model name"),
    tui: bool = typer.Option(False, "--tui", help="Launch interactive TUI dashboard"),
    rule_file: Optional[Path] = typer.Option(None, "--rule-file", help="Hashcat .rule file path"),
    osint_target: str = typer.Option("", "--osint-target", help="Username for OSINT-based profiling"),
) -> None:
    """Crack a hash using smart chained attack phases."""
    _print_banner()

    resolved_path = resolve_wordlist(wordlist)
    console.print(f"[bold]Target:[/] {hash_value}")
    console.print(f"[bold]Wordlist:[/] {resolved_path}")
    console.print(f"[bold]Rules preset:[/] {rules}")

    type_map: dict[str, HashType] = {
        "md5": HashType.MD5,
        "sha1": HashType.SHA1,
        "sha224": HashType.SHA224,
        "sha256": HashType.SHA256,
        "sha384": HashType.SHA384,
        "sha512": HashType.SHA512,
    }

    resolved_type: HashType
    if hash_type.lower() == "auto":
        candidates_id = identify_hash(hash_value)
        resolved_type = candidates_id[0][0] if candidates_id else HashType.UNKNOWN
        console.print(f"[bold]Detected type:[/] {resolved_type.name}")
    else:
        resolved_type = type_map.get(hash_type.lower(), HashType.UNKNOWN)

    target = HashTarget(
        hash_value=hash_value,
        salt=salt,
        hash_type=resolved_type,
    )

    # Build optional profile
    profile: TargetProfile | None = None
    has_profile_data = any([
        profile_name, profile_lastname, profile_birthdate, profile_nickname,
        profile_partner, profile_partner_birthdate, profile_pet,
        profile_child, profile_keywords, profile_numbers,
    ])
    if has_profile_data:
        keywords_tuple = tuple(
            k.strip() for k in profile_keywords.split(",") if k.strip()
        )
        numbers_tuple = tuple(
            n.strip() for n in profile_numbers.split(",") if n.strip()
        )
        profile = TargetProfile(
            first_name=profile_name,
            last_name=profile_lastname,
            nickname=profile_nickname,
            birthdate=profile_birthdate,
            partner_name=profile_partner,
            partner_birthdate=profile_partner_birthdate,
            pet_name=profile_pet,
            child_name=profile_child,
            keywords=keywords_tuple,
            special_numbers=numbers_tuple,
        )
        console.print("[bold]Profile:[/] enabled")

    if osint_target:
        from hashcrack.osint.username_enum import enumerate_username
        from hashcrack.osint.profile_builder import build_profile_from_findings

        console.print(f"[bold]OSINT target:[/] {osint_target}")
        findings: dict[str, object] = {"username": osint_target, "platforms": [], "bio_keywords": []}
        for result in enumerate_username(osint_target):
            if result.found:
                findings["platforms"].append(result.platform)  # type: ignore[union-attr]
                console.print(f"  [green]Found on {result.platform}[/]")

        osint_profile = build_profile_from_findings(findings)
        if profile is not None:
            profile = TargetProfile(
                first_name=profile.first_name or osint_profile.first_name,
                last_name=profile.last_name or osint_profile.last_name,
                nickname=profile.nickname or osint_profile.nickname,
                birthdate=profile.birthdate,
                partner_name=profile.partner_name,
                partner_birthdate=profile.partner_birthdate,
                pet_name=profile.pet_name,
                child_name=profile.child_name,
                keywords=profile.keywords + osint_profile.keywords,
                special_numbers=profile.special_numbers,
            )
        else:
            profile = osint_profile
        has_profile_data = True
        console.print(f"[bold]Profile built from OSINT:[/] {profile.first_name} {profile.last_name}")

    # Build optional LLM config
    llm_config: LLMConfig | None = None
    if llm_api_key and llm_base_url:
        llm_config = LLMConfig(
            base_url=llm_base_url,
            api_key=llm_api_key,
            model=llm_model,
        )
    elif llm_api_key and not llm_base_url:
        console.print("[yellow][!] LLM API key set but no base URL — AI profiling disabled.[/]")
        console.print("[dim]Set HASHCRACK_LLM_BASE_URL or --llm-base-url[/]")

    plans = plan_attacks(
        wordlist_path=resolved_path,
        rules_preset=rules,
        profile=profile,
        llm_config=llm_config,
    )

    if rule_file is not None:
        from hashcrack.plugins.rule_parser import rule_file_candidates

        new_plans: list[AttackPlan] = []
        for plan in plans:
            if plan.phase == AttackPhase.RULES:
                new_plans.append(AttackPlan(
                    name=f"Dictionary + Custom Rules ({rule_file.name})",
                    phase=AttackPhase.RULES,
                    candidates_fn=lambda rf=rule_file: rule_file_candidates(
                        file_candidates(resolved_path), rf
                    ),
                ))
            elif plan.phase == AttackPhase.HYBRID and profile is not None:
                from hashcrack.orchestrator import _select_profiler  # type: ignore[attr-defined]
                from hashcrack.profiler import LocalProfiler
                profiler = _select_profiler(profile, llm_config) if llm_config else LocalProfiler()
                new_plans.append(AttackPlan(
                    name=f"Profile + Custom Rules ({rule_file.name})",
                    phase=AttackPhase.HYBRID,
                    candidates_fn=lambda rf=rule_file, p=profiler, pr=profile: rule_file_candidates(
                        p.generate(pr), rf
                    ),
                ))
            else:
                new_plans.append(plan)
        plans = new_plans

    if tui:
        from hashcrack.tui.app import HashCrackApp

        tui_app = HashCrackApp(
            target=target,
            plans=plans,
            max_workers=workers,
        )
        tui_app.run()
        return

    console.print(f"[bold]Phases planned:[/] {len(plans)}")
    for i, plan in enumerate(plans, 1):
        console.print(f"  [dim]{i}. {plan.name}[/]")
    console.print()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Starting…", total=None)
        attempts_counter: list[int] = [0]

        def _on_progress(n: int) -> None:
            attempts_counter[0] += n
            progress.update(task, advance=n, description=f"Tried {attempts_counter[0]:,}")

        def _on_phase_change(phase_name: str, phase_idx: int, total: int) -> None:
            progress.update(
                task,
                description=f"[{phase_idx + 1}/{total}] {phase_name}",
            )
            console.log(f"[yellow]→ Phase {phase_idx + 1}/{total}:[/] {phase_name}")

        result = run_orchestrated(
            target=target,
            plans=plans,
            max_workers=workers,
            on_progress=_on_progress,
            on_phase_change=_on_phase_change,
        )

    if result.found:
        console.print(f"\n[green][+] Cracked:[/] [bold]{result.plaintext}[/]")
        if result.hash_type:
            console.print(f"[green][+] Algorithm:[/] {result.hash_type.name}")
        if result.attack_phase:
            console.print(f"[green][+] Phase:[/] {result.attack_phase.value}")
        console.print(f"[green][+] Attempts:[/] {result.attempts:,}")
        console.print(f"[green][+] Time:[/] {result.duration_seconds:.2f}s")
    else:
        console.print(
            f"\n[red][-] Not found after {result.attempts:,} attempts "
            f"({result.duration_seconds:.2f}s)[/]"
        )
        console.print("[dim]Try a larger wordlist, different rules, or add a target profile.[/]")


@app.command()
def version() -> None:
    """Show version."""
    console.print(f"hashcrack v{__version__}")


@app.command()
def plugins() -> None:
    """List installed plugins."""
    from hashcrack.plugins.discovery import list_plugins

    found = list_plugins()
    for group, names in found.items():
        if names:
            console.print(f"[bold]{group}:[/bold] {', '.join(names)}")
        else:
            console.print(f"[bold]{group}:[/bold] [dim]none[/dim]")


@app.command()
def batch(
    hash_file: Path = typer.Option(..., "--file", "-f", help="File containing hashes (one per line)"),
    wordlist: Path = typer.Option(Path("100K.txt"), "--wordlist", "-w", help="Wordlist file path"),
    salt: str = typer.Option("", "--salt", "-s", help="Salt to append"),
    rules: str = typer.Option("quick", "--rules", "-r", help="Rules preset: none | quick | thorough"),
    workers: Optional[int] = typer.Option(None, "--workers", help="Worker count"),
    audit: bool = typer.Option(False, "--audit", help="Generate security audit report after cracking"),
    tui: bool = typer.Option(False, "--tui", help="Launch interactive TUI dashboard"),
) -> None:
    """Crack multiple hashes from a file."""
    _print_banner()

    from hashcrack.batch import BatchResult, auto_type_jobs, deduplicate_hashes, parse_hash_file

    resolved_path = resolve_wordlist(wordlist)
    jobs = parse_hash_file(hash_file)
    jobs = deduplicate_hashes(jobs)
    jobs = auto_type_jobs(jobs)

    console.print(f"[bold]Loaded:[/] {len(jobs)} unique hashes")
    console.print(f"[bold]Wordlist:[/] {resolved_path}")
    console.print()

    cracked = 0
    results: dict[str, object] = {}

    for i, job in enumerate(jobs, 1):
        hash_type = job.hash_type or HashType.UNKNOWN
        target = HashTarget(
            hash_value=job.hash_value,
            salt=job.salt or salt,
            hash_type=hash_type,
        )
        console.print(f"[dim][{i}/{len(jobs)}][/] {job.hash_value[:16]}... ({hash_type.name})", end=" ")

        plans = plan_attacks(
            wordlist_path=resolved_path,
            rules_preset=rules,
        )

        result = run_orchestrated(
            target=target,
            plans=plans,
            max_workers=workers,
        )

        if result.found:
            console.print(f"[green]CRACKED: {result.plaintext}[/]")
            cracked += 1
            results[job.hash_value] = result
        else:
            console.print("[red]not found[/]")

    if jobs:
        console.print(f"\n[bold]Results:[/] {cracked}/{len(jobs)} cracked ({cracked / len(jobs) * 100:.0f}%)")

    if audit and cracked > 0:
        from hashcrack.analysis import generate_audit_summary

        passwords = [r.plaintext for r in results.values() if hasattr(r, "plaintext") and r.plaintext]  # type: ignore[union-attr]
        summary = generate_audit_summary(passwords)
        console.print("\n[bold]Security Audit Summary[/]")
        console.print(f"  Average entropy: {summary.avg_entropy:.1f} bits")
        console.print(f"  Policy failures: {summary.policy_failures}/{summary.total}")
        if summary.strength_distribution:
            console.print(f"  Strength: {dict(summary.strength_distribution)}")
        if summary.recommendations:
            console.print("\n[bold]Recommendations:[/]")
            for rec in summary.recommendations:
                console.print(f"  [yellow]![/] {rec}")


@app.command()
def osint(
    username: str = typer.Argument(..., help="Username to investigate"),
) -> None:
    """Run OSINT username enumeration."""
    _print_banner()
    from hashcrack.osint.username_enum import enumerate_username

    console.print(f"[bold]Enumerating username:[/] {username}\n")
    found_count = 0
    for result in enumerate_username(username):
        status = "[green]FOUND[/green]" if result.found else "[dim]not found[/dim]"
        console.print(f"  {result.platform:15s} {status}  {result.url}")
        if result.found:
            found_count += 1
    console.print(f"\n[bold]Found on {found_count} platforms[/]")


if __name__ == "__main__":
    app()
