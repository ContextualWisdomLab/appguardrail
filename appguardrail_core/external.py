"""External SAST/DAST engine planning for beginner-safe scans."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable


AvailabilityChecker = Callable[[str, tuple[str, ...]], object | None]


@dataclass(frozen=True)
class ExternalEngineDecision:
    """One external engine's selection decision."""

    name: str
    display_name: str
    should_run: bool
    auto_selected: bool
    forced: bool
    auto_applicable: bool
    available: bool
    skip_reason: str | None
    hint: str


@dataclass(frozen=True)
class ExternalScanPlan:
    """External engine run plan shared by CLI, future API, and reports."""

    trivy: ExternalEngineDecision
    bandit: ExternalEngineDecision
    ruff: ExternalEngineDecision
    semgrep: ExternalEngineDecision
    zap: ExternalEngineDecision

    @property
    def decisions(self) -> tuple[ExternalEngineDecision, ...]:
        return (self.trivy, self.bandit, self.ruff, self.semgrep, self.zap)

    @property
    def selected_names(self) -> tuple[str, ...]:
        return tuple(decision.name for decision in self.decisions if decision.should_run)


def build_external_scan_plan(
    languages: Iterable[str],
    *,
    external_mode: str = "auto",
    force_trivy: bool = False,
    force_bandit: bool = False,
    force_ruff: bool = False,
    force_semgrep: bool = False,
    zap_baseline_url: str | None = None,
    force_zap: bool = False,
    tool_available: AvailabilityChecker | None = None,
) -> ExternalScanPlan:
    """Build a deterministic external engine plan from detected languages.

    Forced engines run even when availability cannot be confirmed so the
    concrete runner can fail loudly with its normal installation guidance.
    Auto-selected engines run only when the relevant language is present and
    the executable appears runnable.
    """
    language_set = {language.lower() for language in languages}
    checker = tool_available or _missing_tool
    auto_mode = external_mode == "auto"
    semgrep_languages = {"java", "javascript", "python", "typescript", "web"}

    return ExternalScanPlan(
        trivy=_decision(
            "trivy",
            "Trivy FS",
            forced=force_trivy,
            auto_mode=False,
            auto_applicable=False,
            available=_check_if_needed(checker, force_trivy, "trivy"),
            hint="Install Trivy or run without --trivy.",
        ),
        bandit=_decision(
            "bandit",
            "Bandit",
            forced=force_bandit,
            auto_mode=auto_mode,
            auto_applicable="python" in language_set,
            available=_check_if_needed(
                checker, force_bandit or (auto_mode and "python" in language_set), "bandit"
            ),
            hint="Install Bandit or run without --bandit.",
        ),
        ruff=_decision(
            "ruff",
            "Ruff security rules",
            forced=force_ruff,
            auto_mode=auto_mode,
            auto_applicable="python" in language_set,
            available=_check_if_needed(
                checker, force_ruff or (auto_mode and "python" in language_set), "ruff"
            ),
            hint="Install Ruff or run without --ruff.",
        ),
        semgrep=_decision(
            "semgrep",
            "Semgrep",
            forced=force_semgrep,
            auto_mode=auto_mode,
            auto_applicable=bool(language_set & semgrep_languages),
            available=_check_if_needed(
                checker,
                force_semgrep or (auto_mode and bool(language_set & semgrep_languages)),
                "semgrep",
            ),
            hint="Install Semgrep correctly or run with --external off.",
        ),
        zap=_decision(
            "zap",
            "OWASP ZAP baseline",
            forced=force_zap and bool(zap_baseline_url),
            auto_mode=auto_mode,
            auto_applicable=bool(zap_baseline_url),
            available=_check_if_needed(
                checker,
                bool(zap_baseline_url) and (force_zap or auto_mode),
                "zap-baseline.py",
                ("-h",),
            ),
            hint="Install zap-baseline.py or run without --zap-baseline.",
        ),
    )


def _decision(
    name: str,
    display_name: str,
    *,
    forced: bool,
    auto_mode: bool,
    auto_applicable: bool,
    available: bool,
    hint: str,
) -> ExternalEngineDecision:
    auto_selected = auto_mode and auto_applicable and available and not forced
    should_run = forced or auto_selected
    skip_reason = None
    if auto_mode and auto_applicable and not should_run:
        skip_reason = "executable not found or not runnable"
    return ExternalEngineDecision(
        name=name,
        display_name=display_name,
        should_run=should_run,
        auto_selected=auto_selected,
        forced=forced,
        auto_applicable=auto_applicable,
        available=available,
        skip_reason=skip_reason,
        hint=hint,
    )


def _check_if_needed(
    checker: AvailabilityChecker,
    needed: bool,
    name: str,
    version_args: tuple[str, ...] = ("--version",),
) -> bool:
    if not needed:
        return False
    return bool(checker(name, version_args))


def _missing_tool(name: str, version_args: tuple[str, ...]) -> None:
    return None
