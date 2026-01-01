"""
Project Airdump - Analysis Module

Post-flight analysis, whitelist comparison, and reporting.
"""

__all__ = [
    "Analyzer",
    "WhitelistComparer",
    "Reporter",
]


def __getattr__(name):
    """Lazy import to avoid RuntimeWarning when running submodules as __main__."""
    if name == "Analyzer":
        from .analyzer import Analyzer
        return Analyzer
    elif name == "WhitelistComparer":
        from .analyzer import WhitelistComparer
        return WhitelistComparer
    elif name == "Reporter":
        from .reporter import Reporter
        return Reporter
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
