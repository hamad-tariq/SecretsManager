"""Sentinel: alerts on suspicious use of the secrets manager, from a copy of
its audit stream. Alerts only; it never blocks or changes anything."""

from .detector import Alert, Config, Detector, parse_line

__all__ = ["Alert", "Config", "Detector", "parse_line"]
