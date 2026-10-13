"""SAST Lint rules."""

from actionlens.sast.rules.lint.unpinned_action import UnpinnedActionRule
from actionlens.sast.rules.lint.untrusted_namespace import UntrustedNamespaceRule

__all__ = ["UnpinnedActionRule", "UntrustedNamespaceRule"]
