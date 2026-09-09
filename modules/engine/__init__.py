"""Adaptive attack engine package.

Components:
- graph:    AttackKnowledgeGraph (nodes/edges) + semantic parameter classifier
- events:   EventBus (DISCOVERY_NEW_*, FINDING_*)
- rules:    RulesEngine (config/rules.yaml -> actions)
- queue:    AttackQueue (dynamic prioritized test queue)
- chains:   attack chain builder (links findings into paths)
"""
