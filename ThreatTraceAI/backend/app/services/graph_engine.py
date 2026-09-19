"""
Produces a simple infrastructure graph structure for the frontend.
Nodes = sender, domains, IPs, final URLs.
Edges = observed relationships.
"""
from typing import Dict, List

def build_infrastructure_graph(case: dict) -> Dict:
    nodes = []
    edges = []
    node_ids = set()

    def add_node(nid: str, ntype: str, label: str = None):
        if nid not in node_ids:
            nodes.append({
                "id": nid,
                "type": ntype,
                "label": label or nid
            })
            node_ids.add(nid)

    sender = case.get("sender") or "unknown-sender"
    add_node(sender, "sender", sender)

    origin_ip = case.get("origin_ip")
    if origin_ip:
        add_node(origin_ip, "origin_ip", f"Origin: {origin_ip}")
        edges.append({"from": sender, "to": origin_ip, "label": "originates from"})

    resolved_ips = case.get("resolved_ips") or {}

    for d in case.get("domains") or []:
        add_node(d, "domain", d)
        edges.append({"from": sender, "to": d, "label": "uses domain"})
        if d in resolved_ips:
            r_ip = resolved_ips[d]
            add_node(r_ip, "payload_ip", f"Server: {r_ip}")
            edges.append({"from": d, "to": r_ip, "label": "resolves to host"})

    for ip in case.get("ips") or []:
        if ip != origin_ip and ip not in resolved_ips.values():
            add_node(ip, "ip", ip)
            edges.append({"from": sender, "to": ip, "label": "associated IP"})

    for u in case.get("urls") or []:
        final = u if isinstance(u, str) else u.get("final") or u.get("original")
        if final:
            add_node(final, "url", final[:60])
            edges.append({"from": sender, "to": final, "label": "contains link"})

    return {
        "nodes": nodes,
        "edges": edges
    }
