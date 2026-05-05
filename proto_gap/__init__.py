"""proto_gap: Static analyzer for AI-generated prototype codebases.

Produces a prioritized, actionable checklist of production-readiness gaps
covering authentication, error handling, environment configuration, security
vulnerabilities, database migrations, logging, and test coverage.
"""

__version__ = "0.1.0"
__author__ = "proto_gap contributors"
__license__ = "MIT"

# Top-level symbols re-exported for convenient access
from proto_gap.models import (
    Category,
    Finding,
    ScanReport,
    Severity,
)
from proto_gap.scanner import Scanner

__all__ = [
    "__version__",
    "Category",
    "Finding",
    "ScanReport",
    "Severity",
    "Scanner",
]
