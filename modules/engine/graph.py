"""Attack knowledge graph.

Models the target as a graph of nodes (domain, subdomain, IP, port,
service, technology, endpoint, parameter, cookie, api, file, vuln)
connected by typed edges (hosts, redirects_to, calls, contains, uses,
exposes, authenticated_by, possibly_leads_to, depends_on).

The graph is updated after every module and drives the rules engine,
the attack queue, and the report's attack-path visualization.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Set, Tuple


class AttackGraph:
    """A lightweight directed graph of the target's attack surface."""

    def __init__(self, root: str = ""):
        self.root = root
        self.nodes: Dict[str, dict] = {}      # id -> {type, label, attrs}
        self.edges: List[dict] = []           # {src, dst, rel, attrs}

    # ------------------------------------------------------------- nodes
    def add_node(self, node_id: str, ntype: str = "unknown",
                 label: str = "", **attrs) -> bool:
        """Add a node. Returns True if it is *new* (changed the graph)."""
        if not node_id:
            return False
        existing = node_id in self.nodes
        if not existing:
            self.nodes[node_id] = {
                "id": node_id, "type": ntype,
                "label": label or node_id, "attrs": attrs,
            }
        else:
            # enrich type if it was generic
            if self.nodes[node_id]["type"] == "unknown" and ntype != "unknown":
                self.nodes[node_id]["type"] = ntype
            self.nodes[node_id]["attrs"].update(attrs)
        return not existing

    def node(self, node_id: str) -> Optional[dict]:
        return self.nodes.get(node_id)

    @property
    def node_count(self) -> int:
        return len(self.nodes)

    # ------------------------------------------------------------- edges
    def add_edge(self, src: str, dst: str, rel: str = "related_to",
                 **attrs) -> bool:
        """Add a typed edge. Returns True if new."""
        if src == dst or not src or not dst:
            return False
        key = (src, dst, rel)
        for e in self.edges:
            if (e["src"], e["dst"], e["rel"]) == key:
                e["attrs"].update(attrs)
                return False
        self.edges.append({"src": src, "dst": dst, "rel": rel, "attrs": attrs})
        return True

    def neighbors(self, node_id: str, rel: Optional[str] = None) -> List[str]:
        out = []
        for e in self.edges:
            if e["src"] == node_id and (rel is None or e["rel"] == rel):
                out.append(e["dst"])
        return out

    # ------------------------------------------------------------ updates
    def ingest_discovery(self, discovery) -> bool:
        """Add discovery results to the graph. Returns True if changed."""
        changed = False
        if discovery is None:
            return changed
        root = self.root
        host = discovery.hostname or root
        changed |= self.add_node(root, "domain", label=host)

        # technologies
        for tech in (discovery.technologies or []):
            tid = f"tech:{tech.lower()}"
            changed |= self.add_node(tid, "technology", label=tech)
            changed |= self.add_edge(root, tid, "uses")

        # pages/endpoints
        for page in (discovery.pages or [])[:200]:
            pid = f"url:{page}"
            changed |= self.add_node(pid, "endpoint", label=page)
            changed |= self.add_edge(root, pid, "contains")

        # API endpoints
        for ep in (discovery.api_endpoints or [])[:100]:
            eid = f"api:{ep}"
            changed |= self.add_node(eid, "api", label=ep)
            changed |= self.add_edge(root, eid, "calls")

        # parameters
        for p in (discovery.url_params or [])[:100]:
            pid = f"param:{p}"
            changed |= self.add_node(pid, "parameter", label=p)
            changed |= self.add_edge(root, pid, "contains")

        # cookies
        for c in (discovery.cookies or [])[:50]:
            cid = f"cookie:{c.get('name', '')}"
            changed |= self.add_node(cid, "cookie", label=c.get("name", ""))
            changed |= self.add_edge(root, cid, "uses")

        # JS files
        for js in (discovery.js_files or [])[:50]:
            jid = f"js:{js}"
            changed |= self.add_node(jid, "file", label=js)
            changed |= self.add_edge(root, jid, "contains")

        # ports
        for port in (discovery.open_ports or [])[:30]:
            pid = f"port:{port.get('port')}"
            changed |= self.add_node(pid, "port",
                                     label=f"{port.get('service')}/{port.get('port')}",
                                     service=port.get("service"))
            changed |= self.add_edge(root, pid, "hosts")

        # IPs
        for ip in (discovery.ip_addresses or [])[:10]:
            iid = f"ip:{ip}"
            changed |= self.add_node(iid, "ip", label=ip)
            changed |= self.add_edge(root, iid, "hosts")

        # subdomains (from the subdomains module)
        for sub in (getattr(discovery, "subdomains", None) or [])[:60]:
            hostname = sub.get("hostname", "") if isinstance(sub, dict) else str(sub)
            if not hostname:
                continue
            sid = f"sub:{hostname}"
            changed |= self.add_node(sid, "subdomain", label=hostname)
            changed |= self.add_edge(root, sid, "contains")
            ip = sub.get("ip", "") if isinstance(sub, dict) else ""
            if ip:
                iid = f"ip:{ip}"
                changed |= self.add_node(iid, "ip", label=ip)
                changed |= self.add_edge(sid, iid, "hosts")

        return changed

    def add_finding_node(self, finding) -> None:
        """Register a vulnerability node linked to its endpoint."""
        vid = f"vuln:{finding.title}:{finding.endpoint}:{finding.parameter}"
        self.add_node(vid, "vulnerability",
                      label=f"{finding.severity.value} {finding.title}",
                      severity=finding.severity.value,
                      confidence=finding.confidence,
                      endpoint=finding.endpoint,
                      parameter=finding.parameter)
        if finding.endpoint:
            self.add_edge(finding.endpoint if finding.endpoint.startswith(("url:", "api:"))
                          else f"url:{finding.endpoint}", vid, "possibly_leads_to")
        elif self.root:
            self.add_edge(self.root, vid, "possibly_leads_to")

    # ----------------------------------------------------------- queries
    def tech_names(self) -> List[str]:
        return [n["label"] for n in self.nodes.values()
                if n["type"] == "technology"]

    def has_type(self, ntype: str) -> bool:
        return any(n["type"] == ntype for n in self.nodes.values())

    def count_type(self, ntype: str) -> int:
        return sum(1 for n in self.nodes.values() if n["type"] == ntype)

    def node_ids(self, ntype: Optional[str] = None) -> List[str]:
        if ntype is None:
            return list(self.nodes.keys())
        return [nid for nid, n in self.nodes.items() if n["type"] == ntype]

    def to_dict(self) -> Dict:
        return {
            "root": self.root,
            "nodes": [dict(n) for n in self.nodes.values()],
            "edges": [{"src": e["src"], "dst": e["dst"], "rel": e["rel"]}
                      for e in self.edges],
        }

    def ascii_tree(self, max_depth: int = 4) -> str:
        """Render a simple ASCII tree rooted at self.root."""
        if not self.root or self.root not in self.nodes:
            return "(empty graph)"
        lines: List[str] = []
        visited: Set[str] = set()

        def walk(nid: str, depth: int, prefix: str = "") -> None:
            if depth > max_depth or nid in visited:
                return
            visited.add(nid)
            node = self.nodes.get(nid, {})
            label = node.get("label", nid)
            lines.append(f"{prefix}{label}  [{node.get('type', '')}]")
            for child in self.neighbors(nid)[:6]:
                walk(child, depth + 1, prefix + "    ")

        walk(self.root, 0)
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Semantic parameter classification
# ---------------------------------------------------------------------------
_PARAM_CLASSES = {
    "url": ["url", "redirect", "next", "dest", "target", "rurl", "return",
            "callback", "goto", "continue", "to", "from", "uri", "link",
            "href", "src", "source", "feed", "webhook", "callback_url"],
    "file": ["file", "path", "page", "include", "doc",
             "document", "download", "filename", "dir", "folder", "read"],
    "id": ["id", "uuid", "uid", "user_id", "account", "account_id", "item",
           "object", "ref", "guid", "order", "invoice", "ticket"],
    "search": ["q", "query", "search", "keyword", "text", "term", "find"],
    "template": ["template", "render", "view", "layout", "theme"],
    "sort": ["sort", "order", "orderby", "sortby", "filter", "limit",
             "offset", "page"],
    "numeric": ["quantity", "qty", "amount", "price", "total", "count",
                "num", "number", "step"],
    "auth": ["token", "jwt", "session", "apikey", "api_key", "key", "auth",
             "password", "pass", "secret", "credential"],
    "email": ["email", "mail", "user", "username", "login", "name"],
}


def classify_parameter(name: str) -> str:
    """Return the semantic class of a parameter name.

    Uses word-boundary matching to avoid false positives like
    'q' in 'quantity' matching the search class.
    """
    import re
    low = name.lower()
    # Normalize separators to underscores for boundary matching
    normed = re.sub(r'[^a-z0-9]+', '_', low).strip('_')
    for cls, keywords in _PARAM_CLASSES.items():
        # Exact match first
        if low in keywords:
            return cls
        # Word-boundary match: keyword must be a complete segment
        for kw in keywords:
            pattern = r'(?:^|_)' + re.escape(kw) + r'(?:$|_)'
            if re.search(pattern, normed):
                return cls
    return "generic"


_PARAM_CLASS_IMPLICATIONS = {
    "url": ["ssrf", "redirect", "param_mining"],
    "file": ["path_traversal", "files"],
    "id": ["access_control", "api"],
    "search": ["xss", "sqli"],
    "template": ["ssti"],
    "sort": ["sqli", "nosqli"],
    "numeric": ["business_logic"],
    "auth": ["jwt", "auth_session"],
    "email": ["access_control", "auth_session"],
}


def implications_for_class(cls: str) -> List[str]:
    """Which modules a parameter class makes relevant."""
    return _PARAM_CLASS_IMPLICATIONS.get(cls, [])
