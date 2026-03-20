"""
plugins/__init__.py
Plugin auto-discovery and loader.
Scans the plugins/ folder for any .py file that contains
a class inheriting from BasePlugin and loads it automatically.
"""

import importlib
import inspect
import logging
from pathlib import Path
from typing import TYPE_CHECKING

from plugins.base import BasePlugin

logger = logging.getLogger(__name__)


def load_plugins() -> list[BasePlugin]:
    """
    Auto-discover and load all plugins in the plugins/ folder.
    Skips base.py, __init__.py, and example_plugin.py.
    Returns a list of instantiated plugin objects.
    """
    plugins      = []
    plugins_dir  = Path(__file__).parent
    skip_files   = {"__init__.py", "base.py"}

    for path in sorted(plugins_dir.glob("*.py")):
        if path.name in skip_files:
            continue

        module_name = f"plugins.{path.stem}"

        try:
            module = importlib.import_module(module_name)

            for _, obj in inspect.getmembers(module, inspect.isclass):
                if (
                    issubclass(obj, BasePlugin)
                    and obj is not BasePlugin
                ):
                    instance = obj()
                    plugins.append(instance)
                    logger.info(f"Loaded plugin: {instance}")

        except Exception as e:
            logger.warning(f"Failed to load plugin {path.name}: {e}")

    if plugins:
        logger.info(f"Plugin loader: {len(plugins)} plugin(s) loaded")
    else:
        logger.info("Plugin loader: no plugins found")

    return plugins


__all__ = ["BasePlugin", "load_plugins"]