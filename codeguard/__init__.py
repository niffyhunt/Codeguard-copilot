"""CodeGuard — Security analysis ecosystem.
One engine. Multiple workflows. Zero duplication.

Usage:
    from codeguard import CodeGuardEngine
    engine = CodeGuardEngine()
    findings = engine.scan_directory("./my-project")
"""

__version__ = "0.3.2"
__all__ = ["CodeGuardEngine", "Finding", "__version__"]

from .engine import CodeGuardEngine, Finding
