"""
Pytest configuration and fixtures for Peerix tests.
"""
import pytest
import sys
from pathlib import Path

# Add peerix to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


@pytest.fixture
def temp_state_dir(tmp_path):
    """Provide a temporary state directory."""
    state_dir = tmp_path / "peerix"
    state_dir.mkdir()
    return state_dir
