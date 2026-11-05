"""Required checks must run even for documentation-only changes."""

from fnmatch import fnmatchcase
from pathlib import Path

import pytest
import yaml


@pytest.mark.parametrize("event", ["push", "pull_request"])
def test_required_ci_is_not_skipped_for_documentation_changes(event):
    workflow = Path(__file__).resolve().parents[3] / ".github/workflows/audit-engine-ci.yml"
    config = yaml.load(workflow.read_text(), Loader=yaml.BaseLoader)
    events = config["on"]
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
