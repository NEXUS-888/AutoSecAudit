"""
AutoSecAudit Benchmark Suite.
Measures vulnerability detection precision, recall, and F1 score against
ground truth for built-in and external intentionally vulnerable testbeds.
"""

from benchmark.metrics import compute_metrics, GroundTruth, GroundTruthItem
from benchmark.run_benchmark import run_single_benchmark, run_all_benchmarks

__all__ = [
    "compute_metrics",
    "GroundTruth",
    "GroundTruthItem",
    "run_single_benchmark",
    "run_all_benchmarks",
]
