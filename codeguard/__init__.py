"""CodeGuard — Security analysis ecosystem.
One engine. Multiple workflows. Zero duplication.

Usage:
    from codeguard import CodeGuardEngine
    engine = CodeGuardEngine()
    findings = engine.scan_directory("./my-project")

New in v0.4.0:
    from codeguard import (
        secret_detection,
        exploitability,
        PythonAnalyzer, JSAnalyzer, TypeScriptAnalyzer,
        GoAnalyzer, RustAnalyzer, JavaAnalyzer,
        PHPAnalyzer, RubyAnalyzer, CSharpAnalyzer, KotlinAnalyzer,
    )
"""

__version__ = "0.5.0"
__all__ = [
    "CodeGuardEngine", "Finding",
    "PythonAnalyzer", "JSAnalyzer", "TypeScriptAnalyzer",
    "GoAnalyzer", "RustAnalyzer", "JavaAnalyzer",
    "PHPAnalyzer", "RubyAnalyzer", "CSharpAnalyzer", "KotlinAnalyzer",
    "secret_detection", "exploitability",
    "WraithCore", "get_wraithcore",
    "__version__",
]

from .engine import CodeGuardEngine, Finding

from .treesitter_ast import (
    PythonAnalyzer, JSAnalyzer, GoAnalyzer, RustAnalyzer,
    JavaAnalyzer, PHPAnalyzer, RubyAnalyzer, CSharpAnalyzer,
    TypeScriptAnalyzer, KotlinAnalyzer,
)

from . import secret_detection
from . import exploitability

try:
    from .wraithcore import WraithCore, get_wraithcore
except ImportError:
    pass
