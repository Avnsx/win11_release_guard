"""Import-safe public API for Windows release evaluation."""

from .api import check_current_system
from .config import ReleaseCheckerConfig
from .evaluator import derive_display_os_name, evaluate_windows_update_state, infer_installed_release
from .local_state import get_local_windows_state
from .models import (
    BuildEvidenceSource,
    EvaluationResult,
    EvaluationStatus,
    EditionScope,
    InstalledBuildClassification,
    InstalledBuildOrigin,
    InstalledReleaseInference,
    LocalConsensus,
    LocalSignal,
    LocalSignalSet,
    LocalWindowsState,
    QualityPolicy,
    ReleaseHistoryEntry,
    ReleasePolicy,
    ReleasePolicyEntry,
    ServicingChannel,
    SourceProblem,
    SourceStatus,
)
from .remote_policy import fetch_release_policy, load_policy_bytes, load_policy_text
from .signing import load_trusted_policy, verify_policy_signature
from .state_store import (
    STATE_FORMAT_VERSION,
    StateEvent,
    describe_state,
    purge_state,
    read_state_bytes,
)
from .version import package_version

__version__ = package_version()

__all__ = [
    "check_current_system",
    "__version__",
    "evaluate_windows_update_state",
    "derive_display_os_name",
    "infer_installed_release",
    "EvaluationResult",
    "EvaluationStatus",
    "EditionScope",
    "BuildEvidenceSource",
    "InstalledBuildClassification",
    "InstalledBuildOrigin",
    "InstalledReleaseInference",
    "LocalConsensus",
    "LocalSignal",
    "LocalSignalSet",
    "fetch_release_policy",
    "load_policy_bytes",
    "load_policy_text",
    "load_trusted_policy",
    "verify_policy_signature",
    "get_local_windows_state",
    "LocalWindowsState",
    "QualityPolicy",
    "ReleaseHistoryEntry",
    "ReleaseCheckerConfig",
    "ReleasePolicy",
    "ReleasePolicyEntry",
    "ServicingChannel",
    "SourceProblem",
    "SourceStatus",
    "STATE_FORMAT_VERSION",
    "StateEvent",
    "describe_state",
    "purge_state",
    "read_state_bytes",
]
