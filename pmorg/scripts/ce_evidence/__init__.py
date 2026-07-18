"""Fail-closed PMORG CE evidence generation."""

from ce_evidence.models import EvidenceGenerationError
from ce_evidence.publish import generate_evidence

__all__ = ["EvidenceGenerationError", "generate_evidence"]
