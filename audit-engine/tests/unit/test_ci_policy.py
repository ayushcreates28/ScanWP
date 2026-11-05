"""Required checks must run even for documentation-only changes."""

from fnmatch import fnmatchcase
from pathlib import Path

import pytest
import yaml


@pytest.mark.parametrize("event", ["push", "pull_request"])
def test_required_ci_is_not_skipped_for_documentation_changes(event):
    workflow = Path(__file__).resolve().parents[3] / ".github/workflows/audit-engine-ci.yml"
    config = yaml.safe_load(workflow.read_text())
    # PyYAML's YAML 1.1 parser treats the unquoted event key "on" as True.
    events = config.get("on", config.get(True))
    assert event in events
    if isinstance(events, list):
        return
    settings = events[event] or {}
    includes = settings.get("paths")
    excludes = settings.get("paths-ignore", [])
    for changed in ("README.md", "HANDOFF.md", "SETUP.md"):
        assert not includes or any(fnmatchcase(changed, p) for p in includes), (
            "Required CI would stay pending for a documentation-only change"
        )
        assert not any(fnmatchcase(changed, p) for p in excludes)
