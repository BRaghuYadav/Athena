from __future__ import annotations

from typing import Any, Dict, List

from article_analyzer import ArticleAnalysis
from compiler import compile_behavior_query, compile_ioc_query, compile_supply_chain_query, rank_query_pack
from validator import validate_query


def _validated(compiled: Dict[str, Any]) -> Dict[str, Any]:
    validation = validate_query(compiled["query"])
    compiled["validation"] = validation
    compiled["confidence"] = validation.get("confidence", 0.0)
    return compiled


def build_hunt_pack(analysis: ArticleAnalysis) -> Dict[str, Any]:
    hunts: List[Dict[str, Any]] = []

    if analysis.supply_chain_artifacts:
        supply_chain_hunt = compile_supply_chain_query(analysis.supply_chain_artifacts)
        if supply_chain_hunt.get("query"):
            hunts.append(_validated(supply_chain_hunt))

    for behavior in analysis.behaviors[:5]:
        compiled = compile_behavior_query(behavior, analysis.iocs)
        if not compiled.get("query"):
            continue
        hunts.append(_validated(compiled))

    if analysis.iocs.total:
        ioc_hunt = compile_ioc_query(analysis.iocs)
        if ioc_hunt.get("query"):
            ioc_hunt["pack_type"] = "ioc_confirmation"
            hunts.append(_validated(ioc_hunt))

    ranked = rank_query_pack(hunts)
    primary = ranked[0] if ranked else None
    followups = ranked[1:]
    return {
        "title": analysis.title,
        "summary": analysis.summary,
        "attack_stages": analysis.attack_stages,
        "analysis": analysis.to_dict(),
        "primary_hunt": primary,
        "supporting_hunts": followups,
        "warnings": analysis.warnings,
    }
