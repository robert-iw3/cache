"""
ebpf/src - Core package for v2.8

This package contains the main components:
- Baseline learning engine
- eBPF collectors (BCC and libbpf)
- Factory for backend selection
"""

__version__ = "2.8"

# Make key classes easily importable
from .baseline_learner import BaselineLearner
from .ebpf_collector_base import EBPFCollectorBase
from .bcc_collector import BCCCollector
from .libbpf_collector import LibBPFCollector
from .collector_factory import CollectorFactory

__all__ = [
    "BaselineLearner",
    "EBPFCollectorBase",
    "BCCCollector",
    "LibBPFCollector",
    "CollectorFactory",
]