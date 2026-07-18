"""Fail-closed entrypoint for the PMORG Community Edition backend image."""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from collections.abc import Sequence


EE_FLAG_NAMES = (
    "ENABLE_PAID_ENTERPRISE_EDITION_FEATURES",
    "LICENSE_ENFORCEMENT_ENABLED",
)
FIXED_ENVIRONMENT_VALUES = (
    ("DISABLE_TELEMETRY", "true"),
    ("AUTO_LLM_CONFIG_URL", ""),
)
FALSE_VALUES = frozenset({"", "0", "false", "no", "off"})
TRUE_VALUES = frozenset({"1", "true", "yes", "on"})

EXIT_USAGE = 64
EXIT_SOFTWARE = 70
EXIT_CONFIGURATION = 78


class PreflightError(ValueError):
    """Raised when the runtime environment is incompatible with a CE image."""


def validate_environment(environment: Mapping[str, str]) -> None:
    """Reject incompatible Enterprise flags or mutable network defaults.

    Missing values are treated as the image defaults because the image defines
    every guarded variable explicitly. Unknown Enterprise boolean spellings and
    non-exact overrides of fixed values are rejected instead of guessed.
    """

    for name in EE_FLAG_NAMES:
        raw_value = environment.get(name, "false")
        normalized_value = raw_value.strip().lower()
        if normalized_value in TRUE_VALUES:
            raise PreflightError(f"{name} must remain false in a PMORG CE image")
        if normalized_value not in FALSE_VALUES:
            raise PreflightError(
                f"{name} has unsupported boolean value {raw_value!r}; expected false"
            )

    for name, required_value in FIXED_ENVIRONMENT_VALUES:
        raw_value = environment.get(name, required_value)
        if raw_value != required_value:
            raise PreflightError(
                f"{name} must remain {required_value!r} in a PMORG CE image"
            )


def main(
    arguments: Sequence[str] | None = None,
    environment: Mapping[str, str] | None = None,
) -> int:
    """Validate CE invariants and replace this process with the requested command."""

    command = list(sys.argv[1:] if arguments is None else arguments)
    if not command or not command[0]:
        print("PMORG CE preflight requires a command to execute", file=sys.stderr)
        return EXIT_USAGE

    try:
        validate_environment(os.environ if environment is None else environment)
    except PreflightError as error:
        print(f"PMORG CE preflight rejected configuration: {error}", file=sys.stderr)
        return EXIT_CONFIGURATION

    # execvp preserves argument boundaries, the current environment, Unix signal
    # handling, and the child command's exit status. A successful call never returns.
    os.execvp(command[0], command)
    return EXIT_SOFTWARE


if __name__ == "__main__":
    raise SystemExit(main())
