"""promptlink: detect memory-poisoning prompts hidden in AI-assistant links."""

__version__ = "0.1.0"

from .detector import check_url, scan_html, analyse_prompt, Report, Finding  # noqa: E402,F401
