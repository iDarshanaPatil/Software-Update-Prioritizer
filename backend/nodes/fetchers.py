import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List
from urllib.parse import urlencode

import feedparser
import requests

from backend.config import (
    GOOGLE_NEWS_RSS,
    MAX_NVD_RESULTS,
    MAX_REDDIT_QUESTIONS_FETCH,
    MAX_RELEASETRAIN_ITEMS_TOTAL,
    NVD_API_BASE,
    REDDIT_QUESTIONS_API,
    RELEASETRAIN_BASE,
)
from backend.models import WorkflowState


# ---------------------------------------------------------------------------
# Shared helper
# ---------------------------------------------------------------------------

def _get_components(state: WorkflowState) -> List[str]:
    enriched = state.get("enriched_components")
    if enriched:
        return enriched
    plan = state.get("orchestration_plan", {})
    return plan.get("components") or [state["user_query"]]


# ---------------------------------------------------------------------------
# ReleaseTrain
# ---------------------------------------------------------------------------

def _fetch_releasetrain_component(keyword: str) -> List[Dict[str, Any]]:
    try:
        resp = requests.get(RELEASETRAIN_BASE, params={"q": keyword}, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, dict):
            for key in ("results", "data", "items"):
                if key in data and isinstance(data[key], list):
                    return data[key]
        if isinstance(data, list):
            return data
        return []
    except Exception:
        return []


def _fetch_releasetrain_by_vendor(vendor: str) -> List[Dict[str, Any]]:
    """Fetch structured release notes from the specific vendor endpoint."""
    try:
        resp = requests.get(
            f"https://releasetrain.io/api/c/name/{vendor.lower()}",
            timeout=20
        )
        resp.raise_for_status()
        data = resp.json()
        # Response is {vendor: [...items]}
        if isinstance(data, dict):
            for v in data.values():
                if isinstance(v, list):
                    return v
        return []
    except Exception:
        return []


def _normalize_vendor_item(item: Dict[str, Any], vendor: str) -> Dict[str, Any]:
    """Normalize specific vendor endpoint item to standard entry format."""
    return {
        "component": item.get("versionProductBrand") or item.get("versionProductName") or vendor,
        "version": item.get("versionNumber") or "n/a",
        "title": item.get("versionReleaseNotes") or item.get("versionReleaseComments") or "",
        "severity": item.get("severity") or "unknown",
        "isCve": bool(item.get("isCve", False)),
        "source_query": vendor,
        "link": item.get("link") or f"https://releasetrain.io/api/c/name/{vendor.lower()}",
        "release_channel": item.get("versionReleaseChannel") or "",
        "release_date": item.get("versionReleaseDate") or "",
    }


def release_train_node(state: WorkflowState) -> WorkflowState:
    plan = state.get("orchestration_plan", {})
    if not plan.get("use_release_train", True):
        return {"release_notes": [], "cves": []}

    matched_vendor = state.get("matched_vendor", "")
    raw_items: List[Dict[str, Any]] = []

    if matched_vendor:
        print(f"[DEBUG release_train] using specific vendor endpoint: {matched_vendor}")
        vendor_items = _fetch_releasetrain_by_vendor(matched_vendor)
        for it in vendor_items:
            channel = (it.get("versionReleaseChannel") or "").lower()
            if channel == "beta":
                continue
            normalized = _normalize_vendor_item(it, matched_vendor)
            raw_items.append(normalized)
    else:
        components = _get_components(state)
        for comp in components:
            fetched = _fetch_releasetrain_component(comp)
            for it in fetched:
                it_copy = dict(it) if isinstance(it, dict) else {"value": it}
                it_copy["_source_query"] = comp
                raw_items.append(it_copy)

    import re as _re
    user_query = state.get("user_query", "")
    date_match = _re.search(r'\b(20\d{6}|\d{4}[-/]\d{2}[-/]\d{2})\b', user_query)
    if date_match and raw_items:
        # Normalize asked date to YYYYMMDD for comparison
        asked_date = _re.sub(r'[-/]', '', date_match.group(1))
        raw_items.sort(key=lambda x: x.get("release_date") or x.get("versionReleaseDate") or "", reverse=True)
        # Keep items after asked_date (context) + first item on/before asked_date (the answer)
        after = [x for x in raw_items if (x.get("release_date") or x.get("versionReleaseDate") or "") > asked_date]
        on_or_before = [x for x in raw_items if (x.get("release_date") or x.get("versionReleaseDate") or "") <= asked_date and (x.get("release_date") or x.get("versionReleaseDate") or "")]
        raw_items = after[:40] + on_or_before[:10]
    elif len(raw_items) > MAX_RELEASETRAIN_ITEMS_TOTAL:
        raw_items = raw_items[:MAX_RELEASETRAIN_ITEMS_TOTAL]

    release_notes: List[Dict[str, Any]] = []
    cves: List[Dict[str, Any]] = []
    for item in raw_items:
        source_query = (item.get("_source_query") or "").strip()
        computed_link = (
            f"{RELEASETRAIN_BASE}?{urlencode({'q': source_query})}" if source_query else None
        )
        link = (
            item.get("link")
            or item.get("url")
            or item.get("releaseUrl")
            or item.get("componentUrl")
            or item.get("releaseNotesUrl")
            or computed_link
        )
        release_date = item.get("release_date") or item.get("versionReleaseDate") or ""
        entry = {
            "component": item.get("component") or item.get("name") or "unknown",
            "version": item.get("version") or item.get("releaseVersion") or "n/a",
            "title": item.get("title") or item.get("summary") or "",
            "severity": item.get("severity") or item.get("cvssScore") or item.get("cvss") or "unknown",
            "isCve": bool(item.get("isCve", False)),
            "source_query": source_query,
            "link": link,
            **({"release_date": release_date} if release_date else {}),
        }
        if entry["isCve"]:
            cves.append(entry)
        else:
            release_notes.append(entry)

    return {"release_notes": release_notes, "cves": cves}


# ---------------------------------------------------------------------------
# Google News RSS
# ---------------------------------------------------------------------------

def google_news_node(state: WorkflowState) -> WorkflowState:
    plan = state.get("orchestration_plan", {})
    if not plan.get("use_google_news", True):
        return {"news": []}

    components = _get_components(state)
    seen: set[str] = set()
    collected: List[Dict[str, Any]] = []
    for comp in components:
        q = (comp or "").strip()
        if not q:
            continue
        feed_url = f"{GOOGLE_NEWS_RSS}?{urlencode({'q': q, 'hl': 'en-US', 'gl': 'US', 'ceid': 'US:en'})}"
        parsed = feedparser.parse(feed_url)
        print(f"[DEBUG google_news] q={q!r} status={parsed.get('status')} entries={len(parsed.entries)}")
        for entry in parsed.entries[:8]:
            link = entry.get("link", "")
            if link in seen:
                continue
            seen.add(link)
            collected.append(
                {
                    "query": comp,
                    "title": entry.get("title", ""),
                    "link": link,
                    "published": entry.get("published", ""),
                    "source": entry.get("source", {}).get("title", "Google News"),
                }
            )
    return {"news": collected}


# ---------------------------------------------------------------------------
# Reddit questions
# ---------------------------------------------------------------------------

def _fetch_reddit_questions() -> List[Dict[str, Any]]:
    try:
        resp = requests.get(REDDIT_QUESTIONS_API, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for key in ("results", "data", "items", "questions", "posts"):
                if key in data and isinstance(data[key], list):
                    return data[key]
        return []
    except Exception:
        return []


# ---------------------------------------------------------------------------
# NVD (NIST National Vulnerability Database)
# ---------------------------------------------------------------------------

def _fetch_nvd_for_keyword(keyword: str, api_key: str | None) -> List[Dict[str, Any]]:
    # NVD requires ISO 8601 format: 2025-01-01T00:00:00.000
    since = (datetime.now(timezone.utc) - timedelta(days=120)).strftime("%Y-%m-%dT%H:%M:%S.000")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")
    params: Dict[str, Any] = {
        "keywordSearch": keyword,
        "pubStartDate": since,
        "pubEndDate": now,
        "resultsPerPage": min(MAX_NVD_RESULTS, 2000),
    }
    headers = {"apiKey": api_key} if api_key else {}
    try:
        resp = requests.get(NVD_API_BASE, params=params, headers=headers, timeout=20)
        print(f"[DEBUG nvd] keyword={keyword!r} status={resp.status_code} body_preview={resp.text[:200]!r}")
        resp.raise_for_status()
        data = resp.json()
        print(f"[DEBUG nvd] total={data.get('totalResults','?')} returned={len(data.get('vulnerabilities', []))}")
        return data.get("vulnerabilities", [])
    except Exception as e:
        print(f"[DEBUG nvd] ERROR keyword={keyword!r} err={e}")
        return []


def nvd_node(state: WorkflowState) -> WorkflowState:
    plan = state.get("orchestration_plan", {})
    components = _get_components(state)
    api_key = os.getenv("NVD_API_KEY")

    seen: set[str] = set()
    collected: List[Dict[str, Any]] = []

    for comp in components:
        for vuln in _fetch_nvd_for_keyword(comp, api_key):
            cve_obj = vuln.get("cve", {})
            cve_id = cve_obj.get("id", "")
            if not cve_id or cve_id in seen:
                continue
            seen.add(cve_id)

            # Description (English preferred)
            desc = ""
            for d in cve_obj.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break

            # CVSS score — try v3.1 first, fall back to v2
            score = None
            severity = "unknown"
            metrics = cve_obj.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                entries = metrics.get(key, [])
                if entries:
                    cvss_data = entries[0].get("cvssData", {})
                    score = cvss_data.get("baseScore")
                    severity = cvss_data.get("baseSeverity") or entries[0].get("baseSeverity", "unknown")
                    break

            collected.append({
                "component": comp,
                "cve_id": cve_id,
                "title": desc[:500] if desc else cve_id,
                "severity": str(severity).upper() if severity else "unknown",
                "cvss_score": score,
                "published": cve_obj.get("published", ""),
                "link": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "isCve": True,
                "source_query": comp,
            })

        if len(collected) >= MAX_NVD_RESULTS:
            break

    return {"nvd_cves": collected[:MAX_NVD_RESULTS]}


def reddit_questions_node(state: WorkflowState) -> WorkflowState:
    matched_subreddit = state.get("matched_subreddit", "")

    if matched_subreddit:
        print(f"[DEBUG reddit] using specific subreddit: {matched_subreddit}")
        try:
            resp = requests.get(
                "https://releasetrain.io/api/reddit/by-subreddit",
                params={"q": matched_subreddit.lower()},
                timeout=15
            )
            resp.raise_for_status()
            raw = resp.json().get("data", [])
        except Exception:
            raw = _fetch_reddit_questions()
    else:
        raw = _fetch_reddit_questions()

    questions: List[Dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title") or "").strip()
        if not title:
            continue
        questions.append(
            {
                "title": title,
                "url": item.get("url") or item.get("link") or item.get("permalink") or "",
                "score": item.get("score") or item.get("ups") or 0,
                "subreddit": item.get("subreddit") or "",
                "author_description": str(item.get("author_description") or "")[:600],
            }
        )
        if len(questions) >= MAX_REDDIT_QUESTIONS_FETCH:
            break
    return {"reddit_questions": questions}
