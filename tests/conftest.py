import shutil
from pathlib import Path

import pytest

DEMO = Path(__file__).resolve().parent.parent / "examples" / "demo-app"


@pytest.fixture()
def demo(tmp_path: Path) -> Path:
    """A fresh copy of the demo app, so tests can modify files freely."""
    target = tmp_path / "demo-app"
    shutil.copytree(DEMO, target)
    return target
