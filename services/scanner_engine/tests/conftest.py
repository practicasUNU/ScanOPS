"""Pytest configuration and shared fixtures."""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

import pytest


@pytest.fixture(scope="session")
def event_loop_policy():
    """Set event loop policy for tests."""
    if sys.platform == "win32":
        import asyncio
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
