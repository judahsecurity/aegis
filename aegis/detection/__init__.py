"""Shared attack-surface and hypothesis-driven detection primitives."""

from aegis.detection.benchmark import BenchmarkRunRecorder
from aegis.detection.store import DetectionStore, get_detection_store


__all__ = ["BenchmarkRunRecorder", "DetectionStore", "get_detection_store"]
