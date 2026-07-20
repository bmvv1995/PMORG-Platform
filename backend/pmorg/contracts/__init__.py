"""Identity of the only supported PMORG V3 wire surface."""

WIRE_SURFACE = "pmorg-contracts/1.0"
SUPPORTED_WIRE_SURFACES = frozenset({WIRE_SURFACE})


class UnsupportedWireSurfaceError(ValueError):
    """Raised when a caller requests a non-V3 PMORG wire surface."""


def require_supported_wire_surface(wire_surface: str) -> str:
    """Return the canonical surface or fail closed for every other value."""

    if wire_surface not in SUPPORTED_WIRE_SURFACES:
        raise UnsupportedWireSurfaceError(
            f"unsupported PMORG wire surface: {wire_surface!r}"
        )
    return wire_surface


__all__ = [
    "SUPPORTED_WIRE_SURFACES",
    "UnsupportedWireSurfaceError",
    "WIRE_SURFACE",
    "require_supported_wire_surface",
]
