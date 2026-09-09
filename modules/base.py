"""Base scanner module class shared by all detection modules."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List

from modules.reporting.models import Finding
from modules.http_client import HttpClient
from modules.logger import ScanLogger


class BaseModule(ABC):
    """Abstract base class for all scanner modules.

    Subclasses implement :meth:`scan` and return a list of findings.
    """

    name: str = "base"

    def __init__(self, http: HttpClient, logger: ScanLogger,
                 target: str, config=None):
        self.http = http
        self.logger = logger
        self.target = target.rstrip("/")
        self.config = config

    @abstractmethod
    def scan(self) -> List[Finding]:
        """Run the module and return findings."""
        raise NotImplementedError
