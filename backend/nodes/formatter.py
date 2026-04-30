from backend.models import WorkflowState


def formatter_node(state: WorkflowState) -> WorkflowState:
    merged = state.get("merged", {})
    ranked = state.get("ranked", [])
    lines = []
    lines.append("Update Prioritization Results")
    lines.append("=" * 30)
    lines.append(f"Query: {state['user_query']}")
    lines.append(f"Orchestration rationale: {merged.get('plan', {}).get('rationale', 'n/a')}")
    lines.append("")
    lines.append("Ranked Updates:")
    if not ranked:
        lines.append("- No ranked candidates generated. Try a more specific query.")
    for item in ranked:
        badge = "" if item.get("grounded") else " [unverified]"
        prov = item.get("evidence_attached_by") or "unknown"
        lines.append(
            f"- #{item['rank']} {item['software']}{badge} | score={item['priority_score']} | "
            f"evidence={prov} | action={item['suggested_action']}"
        )
        if item.get("grounding_warnings"):
            lines.append(f"  - Checks: {', '.join(item['grounding_warnings'])}")
        for reason in item.get("reasons", []):
            lines.append(f"  - {reason}")
        sb = item.get("signal_breakdown") or {}
        if sb.get("label") != "no_evidence":
            lines.append(
                f"  - Evidence mix (cited signals): CVE {sb.get('cve_pct', 0)}% | "
                f"release {sb.get('release_pct', 0)}% | news {sb.get('news_pct', 0)}%"
            )
        for ev in item.get("evidence") or []:
            tool = ev.get("source_tool") or "?"
            k = ev.get("kind", "?")
            ok = "ok" if ev.get("resolved") else "missing"
            lines.append(
                f"  - Evidence [{ok}] {ev.get('ref')} via {tool} ({k}): {ev.get('title', '')[:200]}"
            )
    lines.append("")
    lines.append(
        f"Signals: CVEs={len(merged.get('cves', []))}, "
        f"release_notes={len(merged.get('release_notes', []))}, "
        f"news={len(merged.get('news', []))}"
    )
    lines.append("")
    lines.append("Top news links:")
    for n in merged.get("news", [])[:5]:
        lines.append(f"- {n.get('title', '')}: {n.get('link', '')}")
    return {"formatted_response": "\n".join(lines)}
