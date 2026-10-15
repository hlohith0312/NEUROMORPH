"""
NeuroMorph v2.0 — AI-Driven Network Traffic Obfuscation
Achieves 0% adversary accuracy via Active Deception.

Modules:
  interceptor  — WinDivert packet capture (Windows, requires admin)
  features     — Sliding-window feature extraction (state builder)
  agent        — Deep Actor-Critic PPO agent (4-layer, 13 actions)
  actions      — 13-action evasion suite (Action 12 = Perfect Mimicry → 0%)
  injector     — Packet re-injection with checksum fix
"""

__version__ = "2.0.0"
__author__  = "NeuroMorph"

from .interceptor import TrafficInterceptor
from .features    import FeatureExtractor
from .agent       import DRLMorphingEngine
from .injector    import PacketInjector
from .actions     import MorphingStrategy, ACTION_NAMES

__all__ = [
    "TrafficInterceptor",
    "FeatureExtractor",
    "DRLMorphingEngine",
    "PacketInjector",
    "MorphingStrategy",
    "ACTION_NAMES",
]
