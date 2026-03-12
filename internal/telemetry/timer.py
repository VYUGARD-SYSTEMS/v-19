"""
v-19 Performance Telemetry

Tracks the 19ms execution time benchmark across scan phases.
"""

import time
import logging
from dataclasses import dataclass, field
from typing import Dict

logger = logging.getLogger(__name__)


@dataclass
class ScanTimer:
    """Tracks execution time across scan phases."""

    _phases: Dict[str, float] = field(default_factory=dict)
    _active: str = ""
    _start: float = 0.0

    def start(self, phase: str):
        """Begin timing a scan phase."""
        self._active = phase
        self._start = time.perf_counter()

    def stop(self) -> float:
        """Stop timing the current phase and return elapsed ms."""
        if not self._active:
            return 0.0
        elapsed_ms = (time.perf_counter() - self._start) * 1000
        self._phases[self._active] = elapsed_ms
        logger.debug(f"[timer] {self._active}: {elapsed_ms:.1f}ms")
        self._active = ""
        return elapsed_ms

    @property
    def total_ms(self) -> float:
        return sum(self._phases.values())

    @property
    def breakdown(self) -> Dict[str, float]:
        return dict(self._phases)

    def report(self) -> str:
        lines = [f"  {phase:<20} {ms:>6.1f}ms" for phase, ms in self._phases.items()]
        lines.append(f"  {'TOTAL':<20} {self.total_ms:>6.1f}ms")
        return "\n".join(lines)
