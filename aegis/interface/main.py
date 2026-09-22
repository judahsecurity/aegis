#!/usr/bin/env python3
"""
Aegis Agent Interface
"""

import argparse
import asyncio
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path

from agents.model_settings import ModelSettings
from agents.models.interface import ModelTracing
from docker.errors import DockerException
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from aegis.config import (
    apply_config_override,
    load_settings,
    persist_current,
)
from aegis.config.models import (
    AegisProvider,
    configure_sdk_model_defaults,
    is_known_openai_bare_model,
)
from aegis.core.paths import run_dir_for, runtime_state_dir
from aegis.interface.api_spec import (
    format_spec_for_agent,
    parse_api_spec,
)
from aegis.interface.cli import run_cli
from aegis.interface.tui import run_tui
from aegis.interface.utils import (
    assign_workspace_subdirs,
    build_final_stats_text,
    build_mount_targets_info,
    check_docker_connection,
    clone_repository,
    collect_local_sources,
    dedupe_local_targets,
    find_oversized_local_targets,
    generate_run_name,
    image_exists,
    infer_target_type,
    is_whitebox_scan,
    process_pull_line,
    resolve_diff_scope_context,
    rewrite_localhost_targets,
    validate_config_file,
)
from aegis.report.state import get_global_report_state
from aegis.report.writer import read_run_record, write_run_record
from aegis.telemetry import posthog, scarf
from aegis.telemetry.logging import configure_dependency_logging


HOST_GATEWAY_HOSTNAME = "host.docker.internal"


import logging  # noqa: E402


logger = logging.getLogger(__name__)


def validate_environment() -> None:
    logger.info("Validating environment")
    console = Console()
    missing_required_vars = []
    missing_optional_vars = []

    settings = load_settings()

    if not settings.llm.model:
        missing_required_vars.append("AEGIS_LLM")

    if not settings.llm.api_key:
        missing_optional_vars.append("LLM_API_KEY")

    if not settings.llm.api_base:
        missing_optional_vars.append("LLM_API_BASE")

    if not settings.integrations.perplexity_api_key:
        missing_optional_vars.append("PERPLEXITY_API_KEY")

    if missing_required_vars:
        error_text = Text()
        error_text.append("MISSING REQUIRED ENVIRONMENT VARIABLES", style="bold red")
        error_text.append("\n\n", style="white")

        for var in missing_required_vars:
            error_text.append(f"• {var}", style="bold yellow")
            error_text.append(" is not set\n", style="white")

        if missing_optional_vars:
            error_text.append("\nOptional environment variables:\n", style="dim white")
            for var in missing_optional_vars:
                error_text.append(f"• {var}", style="dim yellow")
                error_text.append(" is not set\n", style="dim white")

        error_text.append("\nRequired environment variables:\n", style="white")
        for var in missing_required_vars:
            if var == "AEGIS_LLM":
                error_text.append("• ", style="white")
                error_text.append("AEGIS_LLM", style="bold cyan")
                error_text.append(
                    " - Model name to use (e.g., 'openai/gpt-5.4' or "
                    "'anthropic/claude-opus-4-7')\n",
                    style="white",
                )

        if missing_optional_vars:
            error_text.append("\nOptional environment variables:\n", style="white")
            for var in missing_optional_vars:
                if var == "LLM_API_KEY":
                    error_text.append("• ", style="white")
                    error_text.append("LLM_API_KEY", style="bold cyan")
                    error_text.append(
                        " - API key for the LLM provider "
                        "(not needed for local models, Vertex AI, AWS, etc.)\n",
                        style="white",
                    )
                elif var == "LLM_API_BASE":
                    error_text.append("• ", style="white")
                    error_text.append("LLM_API_BASE", style="bold cyan")
                    error_text.append(
                        " - Custom API base URL if using local models (e.g., Ollama, LMStudio)\n",
                        style="white",
                    )
                elif var == "PERPLEXITY_API_KEY":
                    error_text.append("• ", style="white")
                    error_text.append("PERPLEXITY_API_KEY", style="bold cyan")
                    error_text.append(
                        " - API key for Perplexity AI web search (enables real-time research)\n",
                        style="white",
                    )
                elif var == "AEGIS_REASONING_EFFORT":
                    error_text.append("• ", style="white")
                    error_text.append("AEGIS_REASONING_EFFORT", style="bold cyan")
                    error_text.append(
                        " - Reasoning effort level: none, minimal, low, medium, high, xhigh "
                        "(default: high)\n",
                        style="white",
                    )

        error_text.append("\nExample setup:\n", style="white")
        error_text.append("export AEGIS_LLM='openai/gpt-5.4'\n", style="dim white")

        if missing_optional_vars:
            for var in missing_optional_vars:
                if var == "LLM_API_KEY":
                    error_text.append(
                        "export LLM_API_KEY='your-api-key-here'  "
                        "# not needed for local models, Vertex AI, AWS, etc.\n",
                        style="dim white",
                    )
                elif var == "LLM_API_BASE":
                    error_text.append(
                        "export LLM_API_BASE='http://localhost:11434'  "
                        "# needed for local models only\n",
                        style="dim white",
                    )
                elif var == "PERPLEXITY_API_KEY":
                    error_text.append(
                        "export PERPLEXITY_API_KEY='your-perplexity-key-here'\n", style="dim white"
                    )
                elif var == "AEGIS_REASONING_EFFORT":
                    error_text.append(
                        "export AEGIS_REASONING_EFFORT='high'\n",
                        style="dim white",
                    )

        panel = Panel(
            error_text,
            title="[bold white]AEGIS",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )

        logger.error("Missing required env vars: %s", missing_required_vars)
        console.print("\n")
        console.print(panel)
        console.print()
        sys.exit(1)
    logger.info(
        "Environment OK (optional missing: %s)",
        missing_optional_vars or "none",
    )


def check_docker_installed() -> None:
    if shutil.which("docker") is None:
        logger.error("Docker CLI not found in PATH")
        console = Console()
        error_text = Text()
        error_text.append("DOCKER NOT INSTALLED", style="bold red")
        error_text.append("\n\n", style="white")
        error_text.append("The 'docker' CLI was not found in your PATH.\n", style="white")
        error_text.append(
            "Please install Docker and ensure the 'docker' command is available.\n\n", style="white"
        )

        panel = Panel(
            error_text,
            title="[bold white]AEGIS",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )
        console.print("\n", panel, "\n")
        sys.exit(1)
    logger.debug("Docker CLI present")


async def warm_up_llm() -> None:
    console = Console()
    logger.info("Warming up LLM connection")

    try:
        settings = load_settings()
        configure_sdk_model_defaults(settings)
        llm = settings.llm

        raw_model = (llm.model or "").strip()
        if (
            raw_model
            and "/" not in raw_model
            and not is_known_openai_bare_model(raw_model)
            and not llm.api_base
        ):
            warn_text = Text()
            warn_text.append("UNKNOWN MODEL NAME", style="bold yellow")
            warn_text.append("\n\n", style="white")
            warn_text.append(f"'{raw_model}'", style="bold cyan")
            warn_text.append(
                " is not a known OpenAI model. Bare names route to OpenAI by default.\n"
                "If you meant a non-OpenAI provider, use the '",
                style="white",
            )
            warn_text.append("<provider>/<model>", style="bold cyan")
            warn_text.append(
                "' form, e.g. 'anthropic/claude-opus-4-7', 'deepseek/deepseek-v4-pro'.",
                style="white",
            )
            console.print(
                Panel(
                    warn_text,
                    title="[bold white]AEGIS",
                    title_align="left",
                    border_style="yellow",
                    padding=(1, 2),
                ),
            )
            sys.exit(1)

        model = AegisProvider().get_model(raw_model)
        await asyncio.wait_for(
            model.get_response(
                system_instructions="You are a helpful assistant.",
                input="Reply with just 'OK'.",
                model_settings=ModelSettings(),
                tools=[],
                output_schema=None,
                handoffs=[],
                tracing=ModelTracing.DISABLED,
                previous_response_id=None,
                conversation_id=None,
                prompt=None,
            ),
            timeout=llm.timeout,
        )
        logger.info("LLM warm-up succeeded for model %s", (llm.model or "").strip())

    except Exception as e:
        logger.exception("LLM warm-up failed")
        error_text = Text()
        error_text.append("LLM CONNECTION FAILED", style="bold red")
        error_text.append("\n\n", style="white")
        error_text.append("Could not establish connection to the language model.\n", style="white")
        error_text.append("Please check your configuration and try again.\n", style="white")
        error_text.append(f"\nError: {e}", style="dim white")

        panel = Panel(
            error_text,
            title="[bold white]AEGIS",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )

        console.print("\n")
        console.print(panel)
        console.print()
        sys.exit(1)


def get_version() -> str:
    try:
        from importlib.metadata import version

        return version("aegis-agent")
    except Exception:
        return "unknown"


def _positive_budget(value: str) -> float:
    try:
        budget = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid float value: {value!r}") from exc
    import math
    if not math.isfinite(budget) or budget <= 0:
        raise argparse.ArgumentTypeError("must be a finite number greater than 0")
    return budget


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Aegis Multi-Agent Cybersecurity Penetration Testing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive configuration mode (no target required)
  aegis --interactive
  aegis -i

  # Web application penetration test
  aegis --target https://example.com

  # GitHub repository analysis
  aegis --target https://github.com/user/repo
  aegis --target git@github.com:user/repo.git

  # Local code analysis
  aegis --target ./my-project

  # Large local repository (bind-mounted read-only instead of copied)
  aegis --mount ./huge-monorepo

  # Domain penetration test
  aegis --target example.com

  # IP address penetration test
  aegis --target 192.168.1.42

  # Multiple targets (e.g., white-box testing with source and deployed app)
  aegis --target https://github.com/user/repo --target https://example.com
  aegis --target ./my-project --target https://staging.example.com --target https://prod.example.com

  # Mobile application security testing
  aegis --apk ./target.apk
  aegis --ipa ./target.ipa
  aegis --apk ./app.apk --target https://api.example.com  # APK + backend API

  # Custom instructions (inline)
  aegis --target example.com --instruction "Focus on authentication vulnerabilities"

  # Custom instructions (from file)
  aegis --target example.com --instruction-file ./instructions.txt
  aegis --target https://app.com --instruction-file /path/to/detailed_instructions.md
        """,
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"aegis {get_version()}",
    )

    parser.add_argument(
        "-t",
        "--target",
        type=str,
        action="append",
        help="Target to test (URL, repository, local directory path, domain name, or IP address). "
        "Can be specified multiple times for multi-target scans. "
        "Required for fresh runs; loaded from disk when ``--resume`` is set.",
    )
    parser.add_argument(
        "--mount",
        type=str,
        action="append",
        metavar="PATH",
        help="Bind-mount a local directory into the sandbox (read-only) instead of "
        "copying it file-by-file. Use this for large repositories that are too big to "
        "stream into the container. Can be specified multiple times.",
    )
    parser.add_argument(
        "--apk",
        type=str,
        metavar="PATH",
        help="Path to an Android APK file for mobile application security testing. "
        "Decompiles and analyzes the APK for vulnerabilities, hardcoded secrets, "
        "and insecure configurations.",
    )
    parser.add_argument(
        "--ipa",
        type=str,
        metavar="PATH",
        help="Path to an iOS IPA file for mobile application security testing. "
        "Extracts and analyzes the IPA for vulnerabilities, insecure configurations, "
        "and privacy issues.",
    )
    parser.add_argument(
        "--instruction",
        type=str,
        help="Custom instructions for the penetration test. This can be "
        "specific vulnerability types to focus on (e.g., 'Focus on IDOR and XSS'), "
        "testing approaches (e.g., 'Perform thorough authentication testing'), "
        "test credentials (e.g., 'Use the following credentials to access the app: "
        "admin:password123'), "
        "or areas of interest (e.g., 'Check login API endpoint for security issues').",
    )

    parser.add_argument(
        "--instruction-file",
        type=str,
        help="Path to a file containing detailed custom instructions for the penetration test. "
        "Use this option when you have lengthy or complex instructions saved in a file "
        "(e.g., '--instruction-file ./detailed_instructions.txt').",
    )

    parser.add_argument(
        "-n",
        "--non-interactive",
        action="store_true",
        help=(
            "Run in non-interactive mode (no TUI, exits on completion). "
            "Default is interactive mode with TUI."
        ),
    )

    parser.add_argument(
        "-m",
        "--scan-mode",
        type=str,
        choices=["quick", "standard", "deep"],
        default="deep",
        help=(
            "Scan mode: "
            "'quick' for fast CI/CD checks, "
            "'standard' for routine testing, "
            "'deep' for thorough security reviews (default). "
            "Default: deep."
        ),
    )

    parser.add_argument(
        "--scope-mode",
        type=str,
        choices=["auto", "diff", "full"],
        default="auto",
        help=(
            "Scope mode for code targets: "
            "'auto' enables PR diff-scope in CI/headless runs, "
            "'diff' forces changed-files scope, "
            "'full' disables diff-scope."
        ),
    )

    parser.add_argument(
        "--diff-base",
        type=str,
        help=(
            "Target branch or commit to compare against (e.g., origin/main). "
            "Defaults to the repository's default branch."
        ),
    )

    parser.add_argument(
        "--config",
        type=str,
        help="Path to a custom config file (JSON) to use instead of ~/.aegis/cli-config.json",
    )

    parser.add_argument(
        "--max-budget-usd",
        type=_positive_budget,
        default=None,
        help="Maximum LLM cost in USD (> 0). The scan stops cleanly when this limit is reached.",
    )

    parser.add_argument(
        "--resume",
        type=str,
        metavar="RUN_NAME",
        help=(
            "Resume a prior scan by its run name (the dir under ./aegis_runs/). "
            "Picks up the root + every non-terminal subagent's full LLM history "
            "and agent topology. Skips fresh run-name generation."
        ),
    )

    parser.add_argument(
        "--api-spec",
        type=str,
        metavar="PATH",
        help="Path to an OpenAPI/Swagger specification file (JSON or YAML). "
        "Endpoints from the spec are injected into the agent context to guide "
        "targeted API testing. Works with --target to test the live API.",
    )

    parser.add_argument(
        "--internal",
        action="store_true",
        help="Enable internal network testing mode. "
        "Use when running from inside the target network "
        "(VPN, jump server, or office workstation). "
        "Adds AD enumeration, credential spraying, lateral movement, "
        "and internal service discovery capabilities.",
    )

    parser.add_argument(
        "-i",
        "--interactive",
        action="store_true",
        help="Start in interactive configuration mode (no target required). "
        "Use slash commands to configure settings, view skills, and manage scans.",
    )

    args = parser.parse_args()

    if args.instruction and args.instruction_file:
        parser.error(
            "Cannot specify both --instruction and --instruction-file. Use one or the other."
        )

    if args.instruction_file:
        instruction_path = Path(args.instruction_file)
        try:
            with instruction_path.open(encoding="utf-8") as f:
                args.instruction = f.read().strip()
                if not args.instruction:
                    parser.error(f"Instruction file '{instruction_path}' is empty")
        except Exception as e:
            parser.error(f"Failed to read instruction file '{instruction_path}': {e}")

    args.user_explicit_instruction = args.instruction if args.resume else None

    if args.resume:
        if args.target or args.mount or args.apk or args.ipa:
            parser.error(
                "Cannot combine --resume with --target/--mount/--apk/--ipa. "
                "--resume picks up where the prior run left off."
            )
        _load_resume_state(args, parser)
        agents_path = runtime_state_dir(run_dir_for(args.resume)) / "agents.json"
        if not agents_path.exists():
            parser.error(
                f"--resume {args.resume}: missing {agents_path}. The run was "
                f"persisted but never reached its first agent snapshot — "
                f"there's nothing to resume from. Pick a fresh --run-name "
                f"or remove --resume to start over with the same targets."
            )
    else:
        # Skip target validation for interactive mode
        has_mobile = bool(args.apk or args.ipa)
        if not args.interactive and not args.target and not args.mount and not has_mobile:
            parser.error(
                "the following arguments are required: -t/--target, --mount, "
                "--apk, or --ipa "
                "(or use --resume <run_name> to continue a prior scan, "
                "or use --interactive for configuration mode)"
            )
        args.targets_info = [] if args.interactive else []
        for target in args.target or []:
            try:
                target_type, target_dict = infer_target_type(target)

                if target_type == "local_code":
                    display_target = target_dict.get("target_path", target)
                else:
                    display_target = target

                args.targets_info.append(
                    {"type": target_type, "details": target_dict, "original": display_target}
                )
            except ValueError:
                parser.error(f"Invalid target '{target}'")

        # Add mobile APK/IPA targets
        if args.apk:
            apk_path = str(Path(args.apk).expanduser().resolve())
            if not Path(apk_path).exists():
                parser.error(f"APK file not found: {args.apk}")
            args.targets_info.append({
                "type": "mobile_app",
                "details": {"mobile_app_path": apk_path, "platform": "android"},
                "original": apk_path,
            })
        if args.ipa:
            ipa_path = str(Path(args.ipa).expanduser().resolve())
            if not Path(ipa_path).exists():
                parser.error(f"IPA file not found: {args.ipa}")
            args.targets_info.append({
                "type": "mobile_app",
                "details": {"mobile_app_path": ipa_path, "platform": "ios"},
                "original": ipa_path,
            })

        try:
            args.targets_info.extend(build_mount_targets_info(args.mount or []))
        except ValueError as e:
            parser.error(str(e))

        args.targets_info = dedupe_local_targets(args.targets_info)

        assign_workspace_subdirs(args.targets_info)
        rewrite_localhost_targets(args.targets_info, HOST_GATEWAY_HOSTNAME)

        max_local_copy_mb = load_settings().runtime.max_local_copy_mb
        max_copy_bytes = max_local_copy_mb * 1024 * 1024
        oversized = find_oversized_local_targets(args.targets_info, max_copy_bytes)
        if oversized:
            details = "; ".join(
                f"{path} ({size / (1024 * 1024):.0f} MB)" for path, size in oversized
            )
            parser.error(
                f"Local target too large to stream into the sandbox: {details}. "
                f"The limit is {max_local_copy_mb} MB "
                "(set AEGIS_MAX_LOCAL_COPY_MB to change it). Re-run with "
                "--mount <path> to bind-mount the directory instead of copying it."
            )

    return args


def _persist_run_record(args: argparse.Namespace) -> None:
    run_dir = run_dir_for(args.run_name)
    run_dir.mkdir(parents=True, exist_ok=True)
    run_record = {
        "run_id": args.run_name,
        "run_name": args.run_name,
        "status": "running",
        "start_time": datetime.now(UTC).isoformat(),
        "end_time": None,
        "targets_info": args.targets_info,
        "scan_mode": args.scan_mode,
        "instruction": args.instruction,
        "non_interactive": args.non_interactive,
        "local_sources": getattr(args, "local_sources", []),
        "diff_scope": getattr(args, "diff_scope", {"active": False}),
        "scope_mode": args.scope_mode,
        "diff_base": args.diff_base,
    }
    write_run_record(run_dir, run_record)


def _load_resume_state(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Populate ``args.targets_info`` and friends from a prior run's run.json."""
    run_dir = run_dir_for(args.resume)
    state_path = run_dir / "run.json"
    if not state_path.exists():
        parser.error(
            f"--resume {args.resume}: no such run "
            f"(missing {state_path}; remove --resume for a fresh start)"
        )
    try:
        state = read_run_record(run_dir)
    except RuntimeError as exc:
        parser.error(f"--resume {args.resume}: run.json unreadable: {exc}")

    args.targets_info = state.get("targets_info") or []
    if not args.targets_info:
        parser.error(f"--resume {args.resume}: run.json has no targets_info")

    for target in args.targets_info:
        if not isinstance(target, dict):
            continue
        details = target.get("details") or {}
        if target.get("type") != "repository":
            continue
        cloned = details.get("cloned_repo_path")
        if not cloned:
            continue
        if not Path(cloned).expanduser().exists():
            parser.error(
                f"--resume {args.resume}: cloned repo at {cloned} is missing. "
                f"It was deleted between runs. Pick a fresh --run-name to "
                f"re-clone, or restore the directory before resuming."
            )

    if args.instruction is None:
        args.instruction = state.get("instruction")
    if state.get("local_sources"):
        args.local_sources = state.get("local_sources")
    if state.get("diff_scope"):
        args.diff_scope = state.get("diff_scope")
    persisted_scan_mode = state.get("scan_mode")
    if persisted_scan_mode and args.scan_mode == "deep":
        args.scan_mode = persisted_scan_mode


def display_completion_message(args: argparse.Namespace, results_path: Path) -> None:
    console = Console()
    report_state = get_global_report_state()

    scan_completed = False
    if report_state:
        scan_completed = report_state.run_record.get("status") in {
            "completed",
            "completed_with_budget_limit",
        }

    completion_text = Text()
    if scan_completed:
        completion_text.append("Penetration test completed", style="bold #22c55e")
    else:
        completion_text.append("SESSION ENDED", style="bold #eab308")

    target_text = Text()
    target_text.append("Target", style="dim")
    target_text.append("  ")
    if len(args.targets_info) == 1:
        target_text.append(args.targets_info[0]["original"], style="bold white")
    else:
        target_text.append(f"{len(args.targets_info)} targets", style="bold white")
        for target_info in args.targets_info:
            target_text.append("\n        ")
            target_text.append(target_info["original"], style="white")

    stats_text = build_final_stats_text(report_state)

    panel_parts: list[Text | str] = [completion_text, "\n\n", target_text]

    if stats_text.plain:
        panel_parts.extend(["\n", stats_text])

    results_text = Text()
    results_text.append("\n")
    results_text.append("Output", style="dim")
    results_text.append("  ")
    results_text.append(str(results_path), style="#60a5fa")
    panel_parts.extend(["\n", results_text])

    if not scan_completed:
        resume_text = Text()
        resume_text.append("\n")
        resume_text.append("Resume", style="dim")
        resume_text.append("  ")
        resume_text.append(f"aegis --resume {args.run_name}", style="#22c55e")
        panel_parts.extend(["\n", resume_text])

    panel_content = Text.assemble(*panel_parts)

    border_style = "#22c55e" if scan_completed else "#eab308"

    panel = Panel(
        panel_content,
        title="[bold white]AEGIS",
        title_align="left",
        border_style=border_style,
        padding=(1, 2),
    )

    console.print("\n")
    console.print(panel)
    console.print()
    console.print(
        "[#60a5fa]aegis.ai[/]  [dim]·[/]  "
        "[#60a5fa]docs.aegis.ai[/]  [dim]·[/]  "
        "[#60a5fa]discord.gg/aegis[/]"
    )
    console.print()


def pull_docker_image() -> None:
    console = Console()
    client = check_docker_connection()

    image = load_settings().runtime.image
    logger.info("Checking docker image: %s", image)
    console.print()
    console.print(f"[dim]Checking image[/] {image}")

    if image_exists(client, image):
        logger.info("Docker image %s already exists locally", image)
        console.print("[green]Docker image ready[/green]")
        console.print()
        return

    with console.status("[bold cyan]Pulling image for the first time...", spinner="dots") as status:
        try:
            layers_info: dict[str, str] = {}
            last_update = ""

            for line in client.api.pull(image, stream=True, decode=True):
                last_update = process_pull_line(line, layers_info, status, last_update)

        except DockerException as e:
            logger.exception("Failed to pull docker image %s", image)
            console.print()
            error_text = Text()
            error_text.append("FAILED TO PULL IMAGE", style="bold red")
            error_text.append("\n\n", style="white")
            error_text.append(f"Could not download: {image}\n", style="white")
            error_text.append(str(e), style="dim red")

            panel = Panel(
                error_text,
                title="[bold white]AEGIS",
                title_align="left",
                border_style="red",
                padding=(1, 2),
            )
            console.print(panel, "\n")
            sys.exit(1)

    logger.info("Docker image %s ready", image)
    success_text = Text()
    success_text.append("Docker image pulled successfully", style="#22c55e")
    console.print(success_text)
    console.print()


def main() -> None:
    configure_dependency_logging()

    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    args = parse_arguments()

    # Handle interactive mode (no target required)
    if args.interactive:
        from aegis.interface.interactive import run_interactive_mode
        run_interactive_mode()
        return

    if args.config:
        apply_config_override(validate_config_file(args.config))

    check_docker_installed()
    pull_docker_image()

    validate_environment()
    asyncio.run(warm_up_llm())

    persist_current()

    args.run_name = args.resume or generate_run_name(args.targets_info)

    if not args.resume:
        for target_info in args.targets_info:
            if target_info["type"] == "repository":
                repo_url = target_info["details"]["target_repo"]
                dest_name = target_info["details"].get("workspace_subdir")
                cloned_path = clone_repository(repo_url, args.run_name, dest_name)
                target_info["details"]["cloned_repo_path"] = cloned_path

        args.local_sources = collect_local_sources(args.targets_info)
        try:
            diff_scope = resolve_diff_scope_context(
                local_sources=args.local_sources,
                scope_mode=args.scope_mode,
                diff_base=args.diff_base,
                non_interactive=args.non_interactive,
            )
        except ValueError as e:
            console = Console()
            error_text = Text()
            error_text.append("DIFF SCOPE RESOLUTION FAILED", style="bold red")
            error_text.append("\n\n", style="white")
            error_text.append(str(e), style="white")

            panel = Panel(
                error_text,
                title="[bold white]AEGIS",
                title_align="left",
                border_style="red",
                padding=(1, 2),
            )
            console.print("\n")
            console.print(panel)
            console.print()
            sys.exit(1)

        args.diff_scope = diff_scope.metadata
        if diff_scope.instruction_block:
            if args.instruction:
                args.instruction = f"{diff_scope.instruction_block}\n\n{args.instruction}"
            else:
                args.instruction = diff_scope.instruction_block

        # Parse and inject API spec if provided
        if getattr(args, "api_spec", None):
            try:
                api_info = parse_api_spec(args.api_spec)
                args.api_spec_info = api_info
                # Add as a target so the agent knows about the API
                base_url = api_info.get("base_url")
                if base_url and not any(
                    t.get("details", {}).get("target_url") == base_url
                    for t in args.targets_info
                ):
                    target_type, target_dict = infer_target_type(base_url)
                    args.targets_info.append(
                        {"type": target_type, "details": target_dict, "original": base_url}
                    )
                # Append spec summary to instructions
                spec_block = format_spec_for_agent(api_info)
                if args.instruction:
                    args.instruction = f"{args.instruction}\n\n{spec_block}"
                else:
                    args.instruction = spec_block
            except (FileNotFoundError, ValueError) as exc:
                console = Console()
                error_text = Text()
                error_text.append("API SPEC PARSING FAILED", style="bold red")
                error_text.append("\n\n", style="white")
                error_text.append(str(exc), style="white")

                panel = Panel(
                    error_text,
                    title="[bold white]AEGIS",
                    title_align="left",
                    border_style="red",
                    padding=(1, 2),
                )
                console.print("\n")
                console.print(panel)
                console.print()
                sys.exit(1)

        _persist_run_record(args)

    _telemetry_start_kwargs = {
        "model": load_settings().llm.model,
        "scan_mode": args.scan_mode,
        "is_whitebox": is_whitebox_scan(args.targets_info),
        "interactive": not args.non_interactive,
        "has_instructions": bool(args.instruction),
    }
    posthog.start(**_telemetry_start_kwargs)
    scarf.start(**_telemetry_start_kwargs)

    exit_reason = "user_exit"
    try:
        if args.non_interactive:
            asyncio.run(run_cli(args))
        else:
            asyncio.run(run_tui(args))
    except KeyboardInterrupt:
        exit_reason = "interrupted"
    except Exception:
        exit_reason = "error"
        posthog.error("unhandled_exception")
        scarf.error("unhandled_exception")
        raise
    finally:
        report_state = get_global_report_state()
        if report_state:
            status = {"interrupted": "interrupted", "error": "failed"}.get(
                exit_reason,
                "stopped",
            )
            report_state.cleanup(status=status)
            posthog.end(report_state, exit_reason=exit_reason)
            scarf.end(report_state, exit_reason=exit_reason)

    results_path = run_dir_for(args.run_name)
    display_completion_message(args, results_path)

    if args.non_interactive:
        report_state = get_global_report_state()
        if report_state and report_state.vulnerability_reports:
            sys.exit(2)


if __name__ == "__main__":
    main()
