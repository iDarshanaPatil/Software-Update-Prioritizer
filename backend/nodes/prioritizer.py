import json
import re
from typing import Any, Dict, List, Set

from backend.config import (
    AGENT_PIPELINE_META,
    CVE_ID_PATTERN,
    MAX_CVES_FOR_LLM,
    MAX_FIELD_CHARS,
    MAX_NEWS_FOR_LLM,
    MAX_RELEASE_NOTES_FOR_LLM,
)
from backend.llm import get_llm, get_repair_llm
from backend.models import EvidenceRepairOutput, PrioritizedOutput, WorkflowState


# ---------------------------------------------------------------------------
# Text helpers
# ---------------------------------------------------------------------------

def _truncate_text(value: Any, max_len: int) -> str:
    if value is None:
        return ""
    s = str(value).strip()
    return s if len(s) <= max_len else s[: max_len - 3] + "..."


def _norm_token(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").lower()).strip()


# ---------------------------------------------------------------------------
# Compact payload builder
# ---------------------------------------------------------------------------

def _compact_merged_for_llm(merged: Dict[str, Any]) -> Dict[str, Any]:
    """Trim merged data to a token-safe payload for the prioritizer LLM."""
    plan = merged.get("plan") or {}
    cves = merged.get("cves") or []
    release_notes = merged.get("release_notes") or []
    news = merged.get("news") or []
    reddit_questions = merged.get("reddit_questions") or []

    slim_cves = [
        {
            "id": f"cve:{i}",
            "component": _truncate_text(c.get("component"), 120),
            "version": _truncate_text(c.get("version"), 64),
            "title": _truncate_text(c.get("title"), MAX_FIELD_CHARS),
            "severity": _truncate_text(c.get("severity"), 32),
            **({"cvss_score": c["cvss_score"]} if c.get("cvss_score") is not None else {}),
            **({"cve_id": c["cve_id"]} if c.get("cve_id") else {}),
            **({"source": "NVD"} if c.get("_nvd") else {}),
        }
        for i, c in enumerate(cves[:MAX_CVES_FOR_LLM])
    ]
    sorted_releases = sorted(
        release_notes,
        key=lambda r: r.get("release_date") or "",
        reverse=True
    )
    slim_releases = [
        {
            "id": f"release:{i}",
            "component": _truncate_text(r.get("component"), 120),
            "version": _truncate_text(r.get("version"), 64),
            "title": _truncate_text(r.get("title"), MAX_FIELD_CHARS),
            **({"release_date": r["release_date"]} if r.get("release_date") else {}),
        }
        for i, r in enumerate(sorted_releases[:MAX_RELEASE_NOTES_FOR_LLM])
    ]
    # News is NOT sent to LLM — it's evidence-only for the frontend panel
    slim_news = []
    slim_reddit = [
        _truncate_text(q.get("title"), 200)
        for q in reddit_questions[:10]
        if q.get("title")
    ]

    return {
        "user_query": _truncate_text(merged.get("user_query"), 2000),
        "plan": {
            "rationale": _truncate_text(plan.get("rationale"), 1200),
            "components": (plan.get("components") or [])[:15],
        },
        "cves": slim_cves,
        "release_notes": slim_releases,
        "news": slim_news,
        "reddit_community_questions": slim_reddit,
        "counts": {
            "cves_total": len(cves),
            "release_notes_total": len(release_notes),
            "news_total": len(news),
            "reddit_questions_total": len(reddit_questions),
        },
    }


# ---------------------------------------------------------------------------
# Evidence index helpers
# ---------------------------------------------------------------------------

def _repair_catalog_from_compact(compact: Dict[str, Any]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for key in ("cves", "release_notes", "news"):
        for row in compact.get(key) or []:
            rid = row.get("id")
            if not isinstance(rid, str):
                continue
            comp = str(row.get("component") or "")
            title = str(row.get("title") or "")
            out[rid] = _truncate_text(f"{comp} | {title}".strip(" |"), 400)
    return out


def _allowed_ids_from_compact(compact: Dict[str, Any]) -> Set[str]:
    return set(_repair_catalog_from_compact(compact).keys())


def _index_compact_evidence(compact: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    by_id: Dict[str, Dict[str, Any]] = {}
    for key in ("cves", "release_notes", "news"):
        for row in compact.get(key) or []:
            rid = row.get("id")
            if isinstance(rid, str):
                by_id[rid] = row
    return by_id


def _has_evidence_rows(merged: Dict[str, Any]) -> bool:
    return bool(
        (merged.get("cves") or [])
        or (merged.get("release_notes") or [])
        or (merged.get("news") or [])
    )


def _collect_allowed_cve_ids(merged: Dict[str, Any]) -> Set[str]:
    found: Set[str] = set()
    for key in ("cves", "release_notes"):
        for row in merged.get(key) or []:
            blob = f"{row.get('title', '')} {row.get('component', '')}"
            for m in CVE_ID_PATTERN.findall(str(blob)):
                found.add(m.upper())
    return found


# ---------------------------------------------------------------------------
# Evidence provenance tagging
# ---------------------------------------------------------------------------

def _tag_initial_evidence_provenance(ranked: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    for item in ranked:
        if item.get("evidence_refs"):
            item.setdefault("evidence_attached_by", "llm")
        else:
            item.setdefault("evidence_attached_by", "none")
    return ranked


def _summarize_evidence_provenance(ranked: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {"llm": 0, "repair_llm": 0, "deterministic": 0, "none": 0}
    for item in ranked:
        k = str(item.get("evidence_attached_by") or "none")
        counts[k if k in counts else "none"] += 1
    return counts


# ---------------------------------------------------------------------------
# Evidence repair (LLM + deterministic fallback)
# ---------------------------------------------------------------------------

def _repair_missing_evidence_refs_llm(
    ranked: List[Dict[str, Any]],
    compact: Dict[str, Any],
    merged_in: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """One batched LLM call to fill missing evidence_refs."""
    needs = [it for it in ranked if not (it.get("evidence_refs") or [])]
    if not needs or not _has_evidence_rows(merged_in):
        return ranked
    allowed = _allowed_ids_from_compact(compact)
    if not allowed:
        return ranked
    catalog = _repair_catalog_from_compact(compact)
    payload = json.dumps(
        {
            "user_query": merged_in.get("user_query", ""),
            "items": [{"rank": it.get("rank"), "software": it.get("software")} for it in needs],
            "allowed_ids": sorted(allowed),
            "id_summaries": catalog,
        },
        ensure_ascii=True,
    )
    repair_llm = get_repair_llm().with_structured_output(EvidenceRepairOutput)
    prompt = (
        "Attach evidence only. For EACH item in items[], output one repairs[] row with the same rank.\n"
        "evidence_refs must be 1–4 strings copied EXACTLY from allowed_ids.\n"
        "Choose ids whose id_summaries best match the software name; prefer cve:* over release:* over news:* "
        "when relevance is similar.\n"
        "Do not invent ids. If nothing fits, use the single closest match anyway if similarity is plausible.\n\n"
        f"{payload}"
    )
    try:
        out = repair_llm.invoke(prompt)
    except Exception:
        return ranked
    by_rank: Dict[int, List[str]] = {}
    for row in out.repairs:
        r = int(row.rank)
        refs = [x for x in row.evidence_refs if isinstance(x, str) and x in allowed]
        if refs:
            by_rank[r] = refs[:6]
    for item in ranked:
        r = int(item.get("rank") or 0)
        if (item.get("evidence_refs") or []) or r not in by_rank:
            continue
        item["evidence_refs"] = by_rank[r]
        item["evidence_attached_by"] = "repair_llm"
    return ranked


def _match_score_software_to_blob(software: str, blob: str) -> float:
    sw = _norm_token(software)
    tx = _norm_token(blob)
    if not sw or not tx:
        return 0.0
    if sw == tx:
        return 1.0
    if sw in tx or tx in sw:
        return 0.88
    sw_words = [w for w in sw.split() if len(w) > 2]
    if not sw_words:
        return 0.0
    hits = sum(1 for w in sw_words if w in tx)
    return min(0.85, 0.35 + 0.12 * hits)


def _deterministic_evidence_fallback(
    ranked: List[Dict[str, Any]],
    merged_in: Dict[str, Any],
    compact: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Rule-based match when LLM + repair omitted refs."""
    allowed = _allowed_ids_from_compact(compact)
    if not allowed:
        return ranked
    cves = merged_in.get("cves") or []
    rels = merged_in.get("release_notes") or []
    news = merged_in.get("news") or []

    for item in ranked:
        if item.get("evidence_refs"):
            continue
        sw = str(item.get("software") or "")
        scored: List[tuple[float, str]] = []
        for i, row in enumerate(cves):
            s = _match_score_software_to_blob(sw, f"{row.get('component', '')} {row.get('title', '')}")
            if s > 0.2:
                scored.append((s + 0.05, f"cve:{i}"))
        for i, row in enumerate(rels):
            s = _match_score_software_to_blob(sw, f"{row.get('component', '')} {row.get('title', '')}")
            if s > 0.2:
                scored.append((s, f"release:{i}"))
        for i, row in enumerate(news):
            s = _match_score_software_to_blob(sw, f"{row.get('title', '')} {row.get('query', '')}") * 0.95
            if s > 0.2:
                scored.append((s, f"news:{i}"))
        scored.sort(key=lambda x: -x[0])
        chosen = [ref for sc, ref in scored if ref in allowed and sc >= 0.34][:3]
        if chosen:
            item["evidence_refs"] = chosen
            item["evidence_attached_by"] = "deterministic"
    return ranked


# ---------------------------------------------------------------------------
# Grounding validation
# ---------------------------------------------------------------------------

def _validate_ranked_grounding(
    ranked: List[Dict[str, Any]],
    compact: Dict[str, Any],
    full_merged: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Flag likely hallucinations by checking refs against fetched data."""
    by_id = _index_compact_evidence(compact)
    allowed_cve = _collect_allowed_cve_ids(full_merged)
    plan_components = list((full_merged.get("plan") or {}).get("components") or [])

    enriched: List[Dict[str, Any]] = []
    for item in ranked:
        refs = [r for r in (item.get("evidence_refs") or []) if isinstance(r, str)]
        warnings: List[str] = []

        if not refs:
            warnings.append("missing_evidence_refs")
        for r in refs:
            if r not in by_id:
                warnings.append(f"unknown_evidence_ref:{r}")

        reason_blob = " ".join(item.get("reasons") or []) + " " + str(item.get("suggested_action") or "")
        for m in CVE_ID_PATTERN.findall(reason_blob):
            if m.upper() not in allowed_cve:
                warnings.append(f"cve_not_in_fetched_data:{m.upper()}")

        sw = _norm_token(str(item.get("software") or ""))
        software_ok = False
        if sw:
            for pc in plan_components:
                pn = _norm_token(str(pc))
                if pn and (pn in sw or sw in pn):
                    software_ok = True
                    break
            if not software_ok:
                for r in refs:
                    row = by_id.get(r)
                    if not row:
                        continue
                    comp = _norm_token(str(row.get("component") or ""))
                    if comp and (comp == sw or comp in sw or sw in comp):
                        software_ok = True
                        break
                    if r.startswith("news:"):
                        if sw in _norm_token(str(row.get("title") or "")):
                            software_ok = True
                            break

        if sw and bool(refs) and all(r in by_id for r in refs) and not software_ok:
            warnings.append("software_not_aligned_with_evidence")

        enriched.append({**item, "grounded": len(warnings) == 0, "grounding_warnings": warnings})
    return enriched


# ---------------------------------------------------------------------------
# Evidence resolution & signal breakdown
# ---------------------------------------------------------------------------

def _parse_evidence_ref(ref: str):
    if not isinstance(ref, str) or ":" not in ref:
        return None
    prefix, _, idx_s = ref.partition(":")
    prefix = prefix.strip().lower()
    if prefix not in ("cve", "release", "news"):
        return None
    try:
        idx = int(idx_s)
    except ValueError:
        return None
    return (prefix, idx) if idx >= 0 else None


def _kind_label(prefix: str) -> str:
    return {"cve": "cve", "release": "release_note"}.get(prefix, "news")


def _resolve_evidence_refs(refs: List[str], merged: Dict[str, Any]) -> List[Dict[str, Any]]:
    key_map = {"cve": "cves", "release": "release_notes", "news": "news"}
    out: List[Dict[str, Any]] = []
    for ref in refs:
        parsed = _parse_evidence_ref(ref)
        if not parsed:
            out.append({"ref": ref, "kind": "unknown", "source_tool": None,
                        "title": "Invalid evidence ref", "resolved": False})
            continue
        prefix, idx = parsed
        mkey = key_map.get(prefix)
        if not mkey:
            continue
        rows = merged.get(mkey) or []
        kind = _kind_label(prefix)
        source_tool = "google_news_rss" if kind == "news" else "release_train_api"
        if idx >= len(rows):
            out.append({"ref": ref, "kind": kind, "source_tool": source_tool,
                        "title": f"No row at index {idx} (only {len(rows)} in dataset)",
                        "resolved": False})
            continue
        row = rows[idx]
        ev: Dict[str, Any] = {
            "ref": ref, "kind": kind, "source_tool": source_tool, "resolved": True,
            "title": _truncate_text(row.get("title"), 600),
            "component": row.get("component"),
            "version": row.get("version"),
        }
        if kind in ("cve", "release_note"):
            ev["severity"] = row.get("severity")
            ev["source_query"] = row.get("source_query")
            ev["link"] = row.get("link")
        if kind == "news":
            ev["source"] = row.get("source")
            ev["published"] = row.get("published")
            ev["link"] = row.get("link")
        out.append(ev)
    return out


def _signal_breakdown_from_evidence(evidence: List[Dict[str, Any]]) -> Dict[str, Any]:
    w_cve = sum(4 for e in evidence if e.get("kind") == "cve" and e.get("resolved"))
    w_rel = sum(2 for e in evidence if e.get("kind") == "release_note" and e.get("resolved"))
    w_news = sum(1 for e in evidence if e.get("kind") == "news" and e.get("resolved"))
    total = w_cve + w_rel + w_news
    if total <= 0:
        return {"cve_pct": 0, "release_pct": 0, "news_pct": 0, "label": "no_evidence"}
    cve_pct = int(round(100 * w_cve / total))
    rel_pct = int(round(100 * w_rel / total))
    news_pct = int(round(100 * w_news / total))
    drift = 100 - (cve_pct + rel_pct + news_pct)
    if drift != 0:
        if w_cve >= w_rel and w_cve >= w_news:
            cve_pct += drift
        elif w_rel >= w_news:
            rel_pct += drift
        else:
            news_pct += drift
    return {
        "cve_pct": max(0, min(100, cve_pct)),
        "release_pct": max(0, min(100, rel_pct)),
        "news_pct": max(0, min(100, news_pct)),
        "label": "share_of_cited_signals",
    }


def _enrich_ranked_with_evidence(ranked: List[Dict[str, Any]], merged: Dict[str, Any]) -> List[Dict[str, Any]]:
    kind_order = {"cve": 0, "release_note": 1, "news": 2, "unknown": 3}
    enriched = []
    for item in ranked:
        refs = [r for r in (item.get("evidence_refs") or []) if isinstance(r, str)]
        evidence = _resolve_evidence_refs(refs, merged)
        evidence.sort(key=lambda e: (kind_order.get(str(e.get("kind")), 9), str(e.get("ref", ""))))
        enriched.append({**item, "evidence": evidence,
                         "signal_breakdown": _signal_breakdown_from_evidence(evidence)})
    return enriched


# ---------------------------------------------------------------------------
# Prioritize node
# ---------------------------------------------------------------------------

def prioritize_node(state: WorkflowState) -> WorkflowState:
    merged_in = state.get("merged", {})

    # Short-circuit for out_of_scope queries
    plan = merged_in.get("plan", {})
    if plan.get("intent") == "out_of_scope":
        reply = plan.get("out_of_scope_reply", "This tool is for security patch prioritization. Try asking about CVEs or whether a specific software should be patched.")
        return {
            "ranked": [],
            "merged": {**merged_in, "llm_summary": reply},
        }

    llm = get_llm()
    ranker = llm.with_structured_output(PrioritizedOutput)
    compact = _compact_merged_for_llm(merged_in)
    payload = json.dumps(compact, ensure_ascii=True)
    prompt = (
        "You are a software update prioritization agent. Answer ONLY from the JSON data below.\n\n"
        "1. SUMMARY rules (strictly follow):\n"
        "   - If cves[] AND release_notes[] are BOTH empty: respond ONLY 'I don't know — no data found for this query.'\n"
        "   - Keep the summary to ONE sentence maximum.\n"
        "   - NEVER include ref IDs like (release:0) or (cve:1) in the summary — those are internal only.\n"
        "   - Date-specific question (e.g. 'version on 20260101', 'version in March 2026', 'version in May 2026'): "
        "Convert the asked date to YYYYMMDD end-of-period (e.g. 'May 2026'='20260531', 'March 2026'='20260331'). "
        "Scan ALL entries in release_notes[] that have a release_date field. "
        "Find the entry with the LARGEST release_date that is still <= the asked YYYYMMDD. "
        "IMPORTANT: choose by release_date value only, NOT by version number. A lower version number with a later date wins. "
        "State: 'The latest [software] release as of [asked period] was [version], released on [release_date].' "
        "If ALL entries have release_date > asked date, say: 'No [software] release found on or before [asked period].'\n"
        "   - Yes/no question: start with 'Yes.' or 'No.' + one short reason with CVE ID or version.\n"
        "   - Version/patch question: state only the version number found + source. e.g. 'Latest patch: v3.5.1 (CVE-2025-1234, CVSS 9.1).'\n"
        "   - General patch question: one sentence, name the top CVE ID + severity only.\n"
        "   - Do NOT explain, do NOT add context, do NOT mention unrelated software.\n\n"
        "2. RANKED LIST: Rank only software that appears in the data. If nothing relevant found, return empty list.\n\n"
        "Hard rules:\n"
        "- Each ranked item MUST include evidence_refs copied exactly from cves[].id, release_notes[].id, or news[].id.\n"
        "- Do NOT invent CVE IDs. Only cite a CVE if its exact ID appears in cve_id or title fields in the JSON.\n"
        "- NVD entries (source=NVD) carry real CVSS scores — use cvss_score for urgency ranking.\n"
        "- If data is sparse, return fewer items; never fabricate products or vulnerabilities.\n\n"
        "Ranking policy: CVE severity (CVSS score) first, then CVE volume, then release signals, then news.\n"
        "At most 5 items. priority_score 0-100.\n\n"
        f"Input JSON:\n{payload}"
    )
    print(f"[DEBUG prioritizer] cves={len(compact.get('cves',[]))} releases={len(compact.get('release_notes',[]))} news={len(compact.get('news',[]))}")
    print(f"[DEBUG prioritizer] raw_cves_in_merged={len(merged_in.get('cves', []))} raw_releases={len(merged_in.get('release_notes', []))}")
    print(f"[DEBUG prioritizer] cves_sample={compact.get('cves', [])[:2]}")
    print(f"[DEBUG prioritizer] slim_releases[:5]={compact.get('release_notes', [])[:5]}")
    prioritized = ranker.invoke(prompt)
    print(f"[DEBUG prioritizer] summary={prioritized.summary!r}")
    ranked = [item.model_dump() for item in prioritized.ranked_list]
    ranked = _tag_initial_evidence_provenance(ranked)
    ranked = _repair_missing_evidence_refs_llm(ranked, compact, merged_in)
    ranked = _deterministic_evidence_fallback(ranked, merged_in, compact)
    ranked = _validate_ranked_grounding(ranked, compact, merged_in)
    ranked = _enrich_ranked_with_evidence(ranked, merged_in)
    grounded_n = sum(1 for r in ranked if r.get("grounded"))
    prov = _summarize_evidence_provenance(ranked)
    return {
        "ranked": ranked,
        "merged": {
            **merged_in,
            "llm_summary": prioritized.summary,
            "grounding_summary": {"ranked_count": len(ranked), "grounded_count": grounded_n},
            "evidence_provenance_summary": prov,
            "agent_pipeline": AGENT_PIPELINE_META,
        },
    }
