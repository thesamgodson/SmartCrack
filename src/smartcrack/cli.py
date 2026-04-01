"""CLI entry point using Typer."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from smartcrack import __version__
from smartcrack.hash_id import identify_hash
from smartcrack.hashers import verify_any
from smartcrack.models import AttackPhase, CrackResult, CrackSession, HashTarget, HashType, LLMConfig, TargetProfile
from smartcrack.orchestrator import AttackPlan, plan_attacks, run_orchestrated
from smartcrack.session import generate_session_id, load_session, save_session
from smartcrack.result_card import render_batch_summary_table, render_result_card
from smartcrack.telemetry import CrackTelemetry
from smartcrack.wordlist import file_candidates, resolve_wordlist

app = typer.Typer(
    name="smartcrack",
    help="Intelligent hash cracking platform with AI-powered profiling.",
    no_args_is_help=True,
)
console = Console()

rainbow_app = typer.Typer(
    name="rainbow",
    help="Rainbow table management commands.",
    no_args_is_help=True,
)
app.add_typer(rainbow_app, name="rainbow")

BANNER = r"""
 ____                       _    ____                _
/ ___| _ __ ___   __ _ _ __| |_ / ___|_ __ __ _  ___| | __
\___ \| '_ ` _ \ / _` | '__| __| |   | '__/ _` |/ __| |/ /
 ___) | | | | | | (_| | |  | |_| |___| | | (_| | (__|   <
|____/|_| |_| |_|\__,_|_|   \__|\____|_|  \__,_|\___|_|\_\
"""


def _print_banner() -> None:
    console.print(BANNER, style="bold cyan")
    console.print(f"  v{__version__} — AI-Powered Hash Cracking Platform\n", style="dim")


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
        "ntlm": HashType.NTLM,
        "md5crypt": HashType.MD5CRYPT,
        "sha256crypt": HashType.SHA256CRYPT,
        "sha512crypt": HashType.SHA512CRYPT,
        "phpass": HashType.PHPASS,
        "wordpress": HashType.PHPASS,
        "drupal7": HashType.DRUPAL7,
        "mysql": HashType.MYSQL41,
        "mssql": HashType.MSSQL2012,
        "django": HashType.DJANGO_PBKDF2,
        "bcrypt": HashType.BCRYPT,
        "argon2": HashType.ARGON2,
        "scrypt": HashType.SCRYPT,
        "yescrypt": HashType.YESCRYPT,
        "netntlmv2": HashType.NETNTLMV2,
        "kerberos": HashType.KERBEROS_TGS,
        "dcc2": HashType.DCC2,
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
    provider: str = typer.Option("", "--provider", envvar="SMARTCRACK_PROVIDER", help="LLM provider: gemini, openai, groq, together, openrouter"),
    api_key: str = typer.Option("", "--api-key", envvar="SMARTCRACK_API_KEY", help="LLM API key (or use env var SMARTCRACK_API_KEY)"),
    llm_base_url: str = typer.Option("", "--llm-base-url", envvar="SMARTCRACK_LLM_BASE_URL", help="Custom LLM base URL (overrides --provider)"),
    llm_api_key: str = typer.Option("", envvar="SMARTCRACK_LLM_API_KEY", help="LLM API key (legacy, prefer --api-key)", hidden=True),
    llm_model: str = typer.Option("", "--llm-model", envvar="SMARTCRACK_LLM_MODEL", help="LLM model name (auto-selected if using --provider)"),
    tui: bool = typer.Option(False, "--tui", help="Launch interactive TUI dashboard"),
    rule_file: Optional[Path] = typer.Option(None, "--rule-file", help="Hashcat .rule file path"),
    osint_target: str = typer.Option("", "--osint-target", help="Username for OSINT-based profiling"),
    timeout: int = typer.Option(0, "--timeout", help="Wall-clock timeout in seconds (0 = no timeout)", min=0),
    session_file: Optional[Path] = typer.Option(None, "--session-file", help="Session file for save/resume (creates if new, resumes if exists)"),
    mask: str = typer.Option("", "--mask", "-M", help="Mask pattern for mask attack (e.g. ?u?l?l?l?d?d)"),
    ai_masks: bool = typer.Option(False, "--ai-masks", help="Auto-generate masks from target profile via LLM"),
    hashcat_mode: Optional[int] = typer.Option(None, "--hashcat-mode", "-m", help="Hashcat mode number (e.g. 0=MD5, 100=SHA1, 1400=SHA256)"),
    hibp_check: bool = typer.Option(False, "--hibp", help="Check cracked password against HIBP breach database"),
    rainbow_table: Optional[Path] = typer.Option(None, "--rainbow-table", help="Path to prebuilt rainbow table file"),
    combo_wordlist: Optional[Path] = typer.Option(None, "--combo-wordlist", help="Second wordlist for combo attack"),
    expand: bool = typer.Option(False, "--expand", help="Expand profile via LLM for cultural keyword generation"),
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
        "ntlm": HashType.NTLM,
        "md5crypt": HashType.MD5CRYPT,
        "sha256crypt": HashType.SHA256CRYPT,
        "sha512crypt": HashType.SHA512CRYPT,
        "phpass": HashType.PHPASS,
        "wordpress": HashType.PHPASS,
        "drupal7": HashType.DRUPAL7,
        "mysql": HashType.MYSQL41,
        "mssql": HashType.MSSQL2012,
        "django": HashType.DJANGO_PBKDF2,
        "bcrypt": HashType.BCRYPT,
        "argon2": HashType.ARGON2,
        "scrypt": HashType.SCRYPT,
        "yescrypt": HashType.YESCRYPT,
        "netntlmv2": HashType.NETNTLMV2,
        "kerberos": HashType.KERBEROS_TGS,
        "dcc2": HashType.DCC2,
    }

    resolved_type: HashType
    if hashcat_mode is not None:
        from smartcrack.hashcat_compat import resolve_hashcat_mode

        try:
            resolved_type = resolve_hashcat_mode(hashcat_mode)
            console.print(f"[bold]Hashcat mode {hashcat_mode}:[/] {resolved_type.name}")
        except KeyError:
            console.print(f"[red]Unknown hashcat mode: {hashcat_mode}[/]")
            raise typer.Exit(code=1) from None
    elif hash_type.lower() == "auto":
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

    if mask:
        console.print(f"[bold]Mask:[/] {mask}")
    if ai_masks:
        console.print("[bold]AI Masks:[/] enabled")

    if osint_target:
        from smartcrack.osint.username_enum import enumerate_username
        from smartcrack.osint.profile_builder import build_profile_from_findings

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
    from smartcrack.providers import resolve_provider

    effective_key = api_key or llm_api_key
    resolved_url, resolved_key, resolved_model = resolve_provider(
        provider=provider or None,
        api_key=effective_key,
        base_url=llm_base_url,
        model=llm_model,
    )

    llm_config: LLMConfig | None = None
    if resolved_key and resolved_url:
        llm_config = LLMConfig(
            base_url=resolved_url,
            api_key=resolved_key,
            model=resolved_model,
        )
        if provider:
            from smartcrack.providers import PROVIDERS
            pname = PROVIDERS.get(provider.lower())
            if pname:
                console.print(f"[bold]LLM:[/] {pname.name} ({resolved_model})")
        elif resolved_url != llm_base_url:
            console.print(f"[bold]LLM:[/] auto-detected ({resolved_model})")
    elif effective_key and not resolved_url:
        console.print("[yellow][!] LLM API key set but provider unknown — use --provider or --llm-base-url[/]")

    # Session load/create
    session: CrackSession | None = None
    wordlist_offset = 0
    if session_file is not None:
        if session_file.exists():
            try:
                session = load_session(session_file)
            except ValueError as exc:
                console.print(f"[red][!] {exc}[/]")
                raise typer.Exit(code=1) from None
            console.print(
                f"[bold]Resuming session:[/] {session.session_id} "
                f"({len(session.phases_completed)} phases completed)"
            )
            wordlist_offset = session.wordlist_offset
        else:
            session = CrackSession(
                session_id=generate_session_id(),
                target=target,
                profile=profile,
            )

    plans = plan_attacks(
        wordlist_path=resolved_path,
        rules_preset=rules,
        profile=profile,
        llm_config=llm_config,
        wordlist_offset=wordlist_offset,
        mask_pattern=mask if mask else None,
        ai_masks=ai_masks,
        rainbow_table_path=rainbow_table,
        combo_wordlist_path=combo_wordlist,
        expand_knowledge=expand,
    )

    if rule_file is not None:
        from smartcrack.plugins.rule_parser import rule_file_candidates

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
                from smartcrack.profiler import LocalProfiler
                profiler = LocalProfiler()
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
        from smartcrack.tui.app import SmartCrackApp

        tui_app = SmartCrackApp(
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

    telemetry = CrackTelemetry()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Starting…", total=None)

        def _on_progress(n: int) -> None:
            telemetry.update(n)
            speed = telemetry.hashes_per_second
            total = telemetry.total_attempts
            eta = telemetry.eta_seconds(total_candidates=None)
            eta_str = f" | ETA: {eta:.0f}s" if eta is not None else ""
            if speed >= 1_000_000:
                speed_str = f"{speed / 1_000_000:.1f}M H/s"
            elif speed >= 1_000:
                speed_str = f"{speed / 1_000:.1f}K H/s"
            else:
                speed_str = f"{speed:.0f} H/s"
            progress.update(
                task,
                advance=n,
                description=f"Tried {total:,} | {speed_str}{eta_str}",
            )

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
            session=session,
            timeout_seconds=timeout,
        )

    if session is not None and session_file is not None:
        save_session(session, session_file)
        console.print(f"[dim]Session saved to {session_file}[/]")

    console.print()
    card = render_result_card(result)
    console.print(card)
    if not result.found:
        console.print("[dim]Try a larger wordlist, different rules, or add a target profile.[/]")

    if result.found and hibp_check and result.plaintext:
        from smartcrack.hibp import check_hibp_password

        console.print("[dim]Checking HIBP breach database...[/]")
        breach_count = check_hibp_password(result.plaintext)
        if breach_count is not None:
            console.print(
                f"[yellow][!] Seen {breach_count:,} times in data breaches (HIBP)[/]"
            )
        else:
            console.print("[dim]Not found in HIBP breach database (or API unavailable)[/]")


@app.command()
def version() -> None:
    """Show version."""
    console.print(f"smartcrack v{__version__}")


@app.command()
def plugins() -> None:
    """List installed plugins."""
    from smartcrack.plugins.discovery import list_plugins

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
    report: str = typer.Option("", "--report", help="Generate report after batch: csv, html, markdown"),
    report_output: Optional[Path] = typer.Option(None, "--report-output", help="Report output path"),
) -> None:
    """Crack multiple hashes from a file."""
    _print_banner()

    from smartcrack.batch import auto_type_jobs, deduplicate_hashes, parse_hash_file

    resolved_path = resolve_wordlist(wordlist)
    jobs = parse_hash_file(hash_file)
    jobs = deduplicate_hashes(jobs)
    jobs = auto_type_jobs(jobs)

    console.print(f"[bold]Loaded:[/] {len(jobs)} unique hashes")
    console.print(f"[bold]Wordlist:[/] {resolved_path}")
    console.print()

    cracked = 0
    results: dict[str, CrackResult] = {}

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

        all_hashes = [job.hash_value for job in jobs]
        all_results = [results.get(job.hash_value, CrackResult(found=False, attempts=0)) for job in jobs]
        summary_table = render_batch_summary_table(all_hashes, all_results)
        console.print()
        console.print(summary_table)

        for hash_val, result_obj in results.items():
            if result_obj.found:
                console.print()
                console.print(render_result_card(result_obj))

    if audit and cracked > 0:
        from smartcrack.analysis import generate_audit_summary

        passwords = [r.plaintext for r in results.values() if r.plaintext]
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

    if report and cracked > 0:
        from smartcrack.analysis import generate_audit_summary as _gen_audit
        from smartcrack.report import (
            generate_csv_report,
            generate_html_dashboard,
            generate_audit_report,
            save_report,
        )

        batch_results: list[tuple[str, CrackResult]] = [
            (h, r) for h, r in results.items() if isinstance(r, CrackResult)
        ]
        passwords_for_report = [
            r.plaintext for r in results.values()
            if hasattr(r, "plaintext") and r.plaintext
        ]
        audit_summary = _gen_audit(passwords_for_report)

        if report == "csv":
            report_content = generate_csv_report(batch_results)
        elif report == "html":
            report_content = generate_html_dashboard(batch_results, audit_summary)
        elif report == "markdown":
            report_content = generate_audit_report(audit_summary, format="markdown")
        else:
            console.print(f"[red]Unknown report format: {report}[/]")
            raise typer.Exit(code=1)

        out_path = report_output or Path(f"batch_report.{report if report != 'markdown' else 'md'}")
        save_report(report_content, out_path)
        console.print(f"[green]Report saved to {out_path}[/]")


@app.command()
def osint(
    username: str = typer.Argument(..., help="Username to investigate"),
) -> None:
    """Run OSINT username enumeration."""
    _print_banner()
    from smartcrack.osint.username_enum import enumerate_username

    console.print(f"[bold]Enumerating username:[/] {username}\n")
    found_count = 0
    for result in enumerate_username(username):
        status = "[green]FOUND[/green]" if result.found else "[dim]not found[/dim]"
        console.print(f"  {result.platform:15s} {status}  {result.url}")
        if result.found:
            found_count += 1
    console.print(f"\n[bold]Found on {found_count} platforms[/]")


@app.command()
def estimate(
    hash_value: str = typer.Option(..., "--hash", "-H", help="Hash to estimate"),
    wordlist: Path = typer.Option(Path("100K.txt"), "--wordlist", "-w", help="Wordlist file path"),
    hash_type: str = typer.Option("auto", "--type", "-t", help="Hash type (auto, md5, sha1, etc.)"),
    rules: str = typer.Option("quick", "--rules", "-r", help="Rules preset: none | quick | thorough"),
) -> None:
    """Estimate probability and time to crack a hash before running."""
    _print_banner()

    from smartcrack.estimator import estimate_crack

    resolved_path = resolve_wordlist(wordlist)

    type_map: dict[str, HashType] = {
        "md5": HashType.MD5,
        "sha1": HashType.SHA1,
        "sha224": HashType.SHA224,
        "sha256": HashType.SHA256,
        "sha384": HashType.SHA384,
        "sha512": HashType.SHA512,
        "ntlm": HashType.NTLM,
        "md5crypt": HashType.MD5CRYPT,
        "sha256crypt": HashType.SHA256CRYPT,
        "sha512crypt": HashType.SHA512CRYPT,
        "phpass": HashType.PHPASS,
        "wordpress": HashType.PHPASS,
        "drupal7": HashType.DRUPAL7,
        "mysql": HashType.MYSQL41,
        "mssql": HashType.MSSQL2012,
        "django": HashType.DJANGO_PBKDF2,
        "bcrypt": HashType.BCRYPT,
        "argon2": HashType.ARGON2,
        "scrypt": HashType.SCRYPT,
        "yescrypt": HashType.YESCRYPT,
        "netntlmv2": HashType.NETNTLMV2,
        "kerberos": HashType.KERBEROS_TGS,
        "dcc2": HashType.DCC2,
    }

    resolved_type: HashType
    if hash_type.lower() == "auto":
        candidates_id = identify_hash(hash_value)
        resolved_type = candidates_id[0][0] if candidates_id else HashType.UNKNOWN
    else:
        resolved_type = type_map.get(hash_type.lower(), HashType.UNKNOWN)

    target = HashTarget(hash_value=hash_value, hash_type=resolved_type)
    est = estimate_crack(target, resolved_path, rules_preset=rules)

    # Build Rich table
    table = Table(title="Crack Estimate", border_style="cyan", show_header=True)
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right")

    table.add_row("Hash Type", est.hash_type.name)
    table.add_row("Wordlist Size", f"{est.wordlist_size:,}")

    dict_pct = f"{est.dictionary_probability * 100:.1f}%"
    if est.dictionary_probability >= 0.5:
        dict_pct = f"[green]{dict_pct}[/green]"
    elif est.dictionary_probability >= 0.1:
        dict_pct = f"[yellow]{dict_pct}[/yellow]"
    else:
        dict_pct = f"[red]{dict_pct}[/red]"
    table.add_row("Dictionary Probability", dict_pct)
    table.add_row("Dictionary ETA", _format_eta(est.dictionary_eta))

    rules_pct = f"{est.rules_probability * 100:.1f}%"
    if est.rules_probability >= 0.5:
        rules_pct = f"[green]{rules_pct}[/green]"
    elif est.rules_probability >= 0.1:
        rules_pct = f"[yellow]{rules_pct}[/yellow]"
    else:
        rules_pct = f"[red]{rules_pct}[/red]"
    table.add_row("Rules Probability", rules_pct)
    table.add_row("Rules ETA", _format_eta(est.rules_eta))

    if est.mask_eta is not None:
        table.add_row("Mask ETA", _format_eta(est.mask_eta))

    if est.hibp_seen_count is not None:
        hibp_str = f"{est.hibp_seen_count:,}"
        if est.hibp_seen_count > 0:
            hibp_str = f"[red]{hibp_str} times[/red]"
        else:
            hibp_str = "[green]Not seen[/green]"
        table.add_row("HIBP Breaches", hibp_str)

    console.print()
    console.print(table)
    console.print()
    console.print(f"[bold]Recommendation:[/] {est.recommendation}")


def _format_eta(seconds: float) -> str:
    """Format seconds into a human-readable ETA string."""
    if seconds < 0.001:
        return "<1ms"
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    if seconds < 60:
        return f"{seconds:.1f}s"
    if seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    if seconds < 86400:
        hours = seconds / 3600
        return f"{hours:.1f}h"
    days = seconds / 86400
    if days < 365:
        return f"{days:.0f}d"
    years = days / 365
    return f"{years:.1f}y"


@app.command()
def export(
    input: Path = typer.Option(..., "--input", "-i", help="Session JSON file or potfile to import"),
    format: str = typer.Option("html", "--format", "-f", help="Output format: csv, html, markdown"),
    output: Path = typer.Option(..., "--output", "-o", help="Output file path"),
) -> None:
    """Export cracking results as CSV, HTML dashboard, or Markdown report."""
    _print_banner()

    if not input.exists():
        console.print(f"[red]Error: input file not found: {input}[/]")
        raise typer.Exit(code=1)

    from smartcrack.analysis import generate_audit_summary
    from smartcrack.report import (
        generate_csv_report,
        generate_html_dashboard,
        save_report,
    )

    results: list[tuple[str, CrackResult]] = []
    raw_text = input.read_text(encoding="utf-8")

    if raw_text.strip().startswith("{"):
        import json as _json

        data = _json.loads(raw_text)
        session_result = data.get("result")
        target_data = data.get("target", {})
        hash_value = target_data.get("hash_value", "unknown")

        if session_result and session_result.get("found"):
            from smartcrack.session import _crack_result_from_dict

            cr = _crack_result_from_dict(session_result)
            results.append((hash_value, cr))
        else:
            cr = CrackResult(
                found=False,
                attempts=session_result.get("attempts", 0) if session_result else 0,
                duration_seconds=session_result.get("duration_seconds", 0.0) if session_result else 0.0,
            )
            results.append((hash_value, cr))
    else:
        for line in raw_text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                hash_val, plaintext = line.split(":", 1)
                results.append((
                    hash_val.strip(),
                    CrackResult(
                        found=True,
                        plaintext=plaintext.strip(),
                        hash_type=None,
                        attempts=0,
                        duration_seconds=0.0,
                    ),
                ))

    passwords = [r.plaintext for _, r in results if r.found and r.plaintext]
    summary = generate_audit_summary(passwords)

    if format == "csv":
        content = generate_csv_report(results)
    elif format == "html":
        content = generate_html_dashboard(results, summary)
    elif format == "markdown":
        from smartcrack.report import generate_audit_report

        content = generate_audit_report(summary, format="markdown")
    else:
        console.print(f"[red]Unsupported format: {format}. Use csv, html, or markdown.[/]")
        raise typer.Exit(code=1)

    save_report(content, output)
    console.print(f"[green]Report saved to {output}[/]")
    console.print(f"[dim]Format: {format} | Results: {len(results)} | Cracked: {len(passwords)}[/]")


@app.command()
def doctor() -> None:
    """Check system readiness and diagnose configuration issues."""
    _print_banner()

    import os
    import sys

    from rich.table import Table

    table = Table(title="SmartCrack Doctor", show_lines=True)
    table.add_column("Check", style="bold")
    table.add_column("Status")
    table.add_column("Details", style="dim")

    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    py_ok = sys.version_info >= (3, 10)
    table.add_row(
        "Python Version",
        "[green]PASS[/]" if py_ok else "[red]FAIL[/]",
        f"{py_ver} {'(>= 3.10 required)' if not py_ok else ''}",
    )

    try:
        import smartcrack
        bundled = Path(smartcrack.__file__).parent / "data" / "100K.txt"
    except Exception:
        bundled = Path(__file__).parent / "data" / "100K.txt"
    bundled_exists = bundled.exists()
    table.add_row(
        "Bundled Wordlist",
        "[green]PASS[/]" if bundled_exists else "[yellow]WARN[/]",
        f"100K.txt {'found' if bundled_exists else 'MISSING'}",
    )

    system_paths = [
        Path("/usr/share/wordlists/"),
        Path("/usr/share/dict/"),
        Path(os.path.expanduser("~/.local/share/wordlists/")),
    ]
    found_system = [p for p in system_paths if p.exists()]
    table.add_row(
        "System Wordlists",
        "[green]PASS[/]" if found_system else "[dim]NONE[/]",
        ", ".join(str(p) for p in found_system) if found_system else "No system wordlist paths found",
    )

    cpu_count = os.cpu_count() or 1
    table.add_row(
        "CPU Cores",
        "[green]PASS[/]",
        f"{cpu_count} cores available",
    )

    from smartcrack.providers import PROVIDERS, resolve_provider

    llm_key = os.environ.get("SMARTCRACK_API_KEY", "") or os.environ.get("SMARTCRACK_LLM_API_KEY", "")
    llm_base = os.environ.get("SMARTCRACK_LLM_BASE_URL", "")
    llm_provider = os.environ.get("SMARTCRACK_PROVIDER", "")
    resolved_url, _, resolved_model = resolve_provider(
        provider=llm_provider or None, api_key=llm_key, base_url=llm_base, model="",
    )
    if llm_key and resolved_url:
        pinfo = next((p for p in PROVIDERS.values() if p.base_url == resolved_url), None)
        label = pinfo.name if pinfo else resolved_url
        table.add_row("LLM Config", "[green]PASS[/]", f"{label} ({resolved_model})")
    elif llm_key:
        table.add_row("LLM Config", "[yellow]WARN[/]", "Key set but provider unknown — use SMARTCRACK_PROVIDER")
    else:
        table.add_row(
            "LLM Config", "[dim]SKIP[/]",
            "Not configured. Set SMARTCRACK_API_KEY + SMARTCRACK_PROVIDER (gemini, openai, groq)",
        )

    for dep_name in ("bcrypt", "argon2"):
        try:
            __import__(dep_name if dep_name != "argon2" else "argon2")
            table.add_row(f"Optional: {dep_name}", "[green]PASS[/]", "installed")
        except ImportError:
            table.add_row(f"Optional: {dep_name}", "[yellow]WARN[/]", "not installed")

    console.print(table)


@app.command()
def quickstart(
    demo: bool = typer.Option(True, "--demo/--no-demo", help="Run demo crack automatically"),
) -> None:
    """Interactive quickstart wizard for first-time users."""
    _print_banner()
    import hashlib

    console.print("[bold]Welcome to SmartCrack![/]\n")
    console.print("This wizard will walk you through your first hash crack.\n")

    hash_input = typer.prompt(
        "Enter a hash to crack (or press Enter for a demo)",
        default="",
        show_default=False,
    )

    if not hash_input:
        demo_password = "password123"
        hash_input = hashlib.md5(demo_password.encode()).hexdigest()
        console.print(f"\n[dim]Generated demo MD5 hash of '{demo_password}':[/]")
        console.print(f"[bold]{hash_input}[/]\n")

    if demo:
        console.print("[yellow]Running smart crack...[/]\n")

        resolved_path = resolve_wordlist(Path("100K.txt"))
        target = HashTarget(hash_value=hash_input, hash_type=HashType.UNKNOWN)

        candidates_id = identify_hash(hash_input)
        if candidates_id:
            target = HashTarget(
                hash_value=hash_input,
                hash_type=candidates_id[0][0],
            )
            console.print(f"[bold]Detected type:[/] {candidates_id[0][0].name}\n")

        plans = plan_attacks(wordlist_path=resolved_path, rules_preset="quick")
        result = run_orchestrated(target=target, plans=plans)

        if result.found:
            console.print(f"\n[green][+] Cracked:[/] [bold]{result.plaintext}[/]")
            if result.hash_type:
                console.print(f"[green][+] Algorithm:[/] {result.hash_type.name}")
            console.print(f"[green][+] Attempts:[/] {result.attempts:,}")
            console.print(f"[green][+] Time:[/] {result.duration_seconds:.2f}s")
        else:
            console.print(f"\n[red][-] Not found after {result.attempts:,} attempts[/]")

    console.print("\n[bold]Next steps:[/]")
    console.print("  1. Try your own hash:  [cyan]smartcrack smart -H <hash>[/]")
    console.print("  2. Batch crack a file: [cyan]smartcrack batch -f hashes.txt[/]")
    console.print("  3. Add target profile: [cyan]smartcrack smart -H <hash> --profile-name John[/]")
    console.print("  4. Export a report:    [cyan]smartcrack export -i session.json -o report.html[/]")
    console.print("  5. Check your setup:   [cyan]smartcrack doctor[/]")


@app.command()
def analyze(
    potfile: Path = typer.Option(..., "--potfile", "-p", help="Hashcat potfile path"),
    report_format: str = typer.Option("", "--report", help="Generate report: csv, html, markdown"),
    report_output: Optional[Path] = typer.Option(None, "--report-output", "-o", help="Report output path"),
) -> None:
    """Analyze passwords from a hashcat potfile."""
    _print_banner()

    if not potfile.exists():
        console.print(f"[red]Potfile not found: {potfile}[/]")
        raise typer.Exit(code=1)

    from smartcrack.analysis import generate_audit_summary
    from smartcrack.hashcat_compat import parse_potfile

    entries = parse_potfile(potfile)
    if not entries:
        console.print("[yellow]No entries found in potfile.[/]")
        raise typer.Exit(code=0)

    passwords = [plaintext for _, plaintext in entries]
    summary = generate_audit_summary(passwords)

    console.print(f"[bold]Analyzed {summary.total} passwords[/]\n")
    console.print(f"  Average entropy: [bold]{summary.avg_entropy:.1f}[/] bits")
    console.print(f"  Policy failures: [bold]{summary.policy_failures}[/]/{summary.total}")

    if summary.strength_distribution:
        console.print("\n[bold]Strength Distribution:[/]")
        for strength, count in sorted(summary.strength_distribution.items()):
            pct = count / summary.total * 100
            bar = "#" * int(pct / 2)
            console.print(f"  {strength:12s} {count:4d} ({pct:5.1f}%) {bar}")

    if summary.pattern_distribution:
        console.print("\n[bold]Patterns:[/]")
        for pattern, count in sorted(summary.pattern_distribution.items(), key=lambda x: -x[1]):
            console.print(f"  {pattern}: {count}")

    if summary.recommendations:
        console.print("\n[bold]Recommendations:[/]")
        for rec in summary.recommendations:
            console.print(f"  [yellow]![/] {rec}")

    if report_format:
        from smartcrack.report import (
            generate_audit_report,
            generate_csv_report,
            generate_html_dashboard,
            save_report,
        )

        crack_results: list[tuple[str, CrackResult]] = [
            (h, CrackResult(found=True, plaintext=p, hash_type=None, attempts=0, duration_seconds=0.0))
            for h, p in entries
        ]

        if report_format == "csv":
            content = generate_csv_report(crack_results)
        elif report_format == "html":
            content = generate_html_dashboard(crack_results, summary)
        elif report_format == "markdown":
            content = generate_audit_report(summary, format="markdown")
        else:
            console.print(f"[red]Unknown report format: {report_format}[/]")
            raise typer.Exit(code=1)

        out = report_output or Path(f"analyze_report.{report_format if report_format != 'markdown' else 'md'}")
        save_report(content, out)
        console.print(f"\n[green]Report saved to {out}[/]")


@rainbow_app.command("build")
def rainbow_build(
    wordlist: Path = typer.Option(..., "--wordlist", "-w", help="Wordlist file path"),
    hash_type: str = typer.Option("md5", "--type", "-t", help="Hash type (md5, sha1, sha256, etc.)"),
    output: Path = typer.Option(..., "--output", "-o", help="Output rainbow table file path"),
) -> None:
    """Build a rainbow table from a wordlist."""
    _print_banner()

    type_map: dict[str, HashType] = {
        "md5": HashType.MD5,
        "sha1": HashType.SHA1,
        "sha224": HashType.SHA224,
        "sha256": HashType.SHA256,
        "sha384": HashType.SHA384,
        "sha512": HashType.SHA512,
        "ntlm": HashType.NTLM,
    }

    resolved_type = type_map.get(hash_type.lower())
    if resolved_type is None:
        console.print(f"[red]Unsupported hash type: {hash_type}[/]")
        raise typer.Exit(code=1)

    from smartcrack.rainbow import build_rainbow_table

    console.print(f"[bold]Wordlist:[/] {wordlist}")
    console.print(f"[bold]Hash type:[/] {resolved_type.name}")
    console.print(f"[bold]Output:[/] {output}")
    console.print("[yellow]Building...[/]")

    count = build_rainbow_table(wordlist, resolved_type, output)
    console.print(f"[green][+] Built rainbow table with {count:,} entries[/]")


@rainbow_app.command("lookup")
def rainbow_lookup(
    hash_value: str = typer.Option(..., "--hash", "-H", help="Hash to look up"),
    table: Path = typer.Option(..., "--table", "-T", help="Rainbow table file path"),
) -> None:
    """Look up a hash in a rainbow table."""
    _print_banner()

    from smartcrack.rainbow import lookup_rainbow_table

    result = lookup_rainbow_table(hash_value, table)
    if result is not None:
        console.print(f"[green][+] Found:[/] [bold]{result}[/]")
    else:
        console.print("[red][-] Not found in rainbow table[/]")


if __name__ == "__main__":
    app()
