"""Event bus.

Modules publish discovery/finding events; the rules engine and attack
queue subscribe and react. This decouples "what was found" from
"what tests become relevant".

Event types (prefixed DISCOVERY_ or FINDING_):
- DISCOVERY_NEW_ENDPOINT
- DISCOVERY_NEW_PARAMETER
- DISCOVERY_NEW_API
- DISCOVERY_NEW_TECHNOLOGY
- DISCOVERY_NEW_AUTH_FLOW
- DISCOVERY_NEW_SERVICE
- DISCOVERY_NEW_COOKIE
- FINDING_NEW
"""
from __future__ import annotations

from collections import defaultdict
from typing import Callable, Dict, List


class EventBus:
    """Simple publish/subscribe event bus."""

    def __init__(self):
        self._subscribers: Dict[str, List[Callable]] = defaultdict(list)
        self.history: List[dict] = []

    def subscribe(self, event_type: str, handler: Callable) -> None:
        self._subscribers[event_type].append(handler)

    def publish(self, event_type: str, **payload) -> None:
        event = {"type": event_type, **payload}
        self.history.append(event)
        for handler in list(self._subscribers.get(event_type, [])):
            try:
                handler(event)
            except Exception:
                pass  # a failing subscriber must not break the scan

    def has_event(self, event_type: str) -> bool:
        return any(e["type"] == event_type for e in self.history)

    def events_of(self, event_type: str) -> List[dict]:
        return [e for e in self.history if e["type"] == event_type]

    def publish_discovery_events(self, discovery) -> None:
        """Translate a discovery result into events."""
        if discovery is None:
            return
        for page in (discovery.pages or []):
            self.publish("DISCOVERY_NEW_ENDPOINT", endpoint=page)
        for ep in (discovery.api_endpoints or []):
            self.publish("DISCOVERY_NEW_API", endpoint=ep)
        for p in (discovery.url_params or []):
            self.publish("DISCOVERY_NEW_PARAMETER", parameter=p)
        for tech in (discovery.technologies or []):
            self.publish("DISCOVERY_NEW_TECHNOLOGY", technology=tech)
        for c in (discovery.cookies or []):
            self.publish("DISCOVERY_NEW_COOKIE", name=c.get("name", ""))
        for port in (discovery.open_ports or []):
            self.publish("DISCOVERY_NEW_SERVICE",
                         port=port.get("port"), service=port.get("service"))
        for sub in (discovery.subdomains or []):
            host = sub.get("hostname", "") if isinstance(sub, dict) else str(sub)
            if host:
                self.publish("DISCOVERY_NEW_SUBDOMAIN", hostname=host)

    def finding_event(self, finding) -> None:
        self.publish("FINDING_NEW", title=finding.title,
                     severity=finding.severity.value,
                     endpoint=finding.endpoint)
