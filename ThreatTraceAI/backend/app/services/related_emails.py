"""
Simple related-email / campaign clustering (seeded for demo).
In production this would query a larger case store.
"""
from typing import List, Dict

def find_related(current_case: dict, all_cases: List[dict]) -> List[dict]:
    """
    Very lightweight similarity: shared domains or similar subject tokens.
    """
    related = []
    cur_domains = set(current_case.get("domains") or [])
    cur_subj = (current_case.get("subject") or "").lower().split()

    for c in all_cases:
        if c.get("case_id") == current_case.get("case_id"):
            continue
        score = 0
        other_domains = set(c.get("domains") or [])
        if cur_domains & other_domains:
            score += 2
        other_subj = (c.get("subject") or "").lower().split()
        common = set(cur_subj) & set(other_subj)
        if len(common) >= 2:
            score += 1
        if score > 0:
            related.append({
                "case_id": c.get("case_id"),
                "subject": c.get("subject"),
                "risk_score": c.get("risk_score"),
                "similarity_score": score
            })
    return sorted(related, key=lambda x: x["similarity_score"], reverse=True)[:5]
