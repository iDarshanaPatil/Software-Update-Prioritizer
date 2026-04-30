from typing import List, Optional
import requests

from backend.models import WorkflowState

_NAMES_URL = "https://releasetrain.io/api/c/names"
_SUBREDDITS_URL = "https://releasetrain.io/api/reddit/meta/subreddits"

# Module-level cache so we only fetch once per server process
_names_cache: Optional[List[str]] = None
_subreddits_cache: Optional[List[str]] = None


def _get_names() -> List[str]:
    global _names_cache
    if _names_cache is None:
        try:
            _names_cache = requests.get(_NAMES_URL, timeout=10).json()
        except Exception:
            _names_cache = []
    return _names_cache


def _get_subreddits() -> List[str]:
    global _subreddits_cache
    if _subreddits_cache is None:
        try:
            data = requests.get(_SUBREDDITS_URL, timeout=10).json()
            _subreddits_cache = data.get("data", []) if isinstance(data, dict) else []
        except Exception:
            _subreddits_cache = []
    return _subreddits_cache


def _match(keywords: List[str], candidates: List[str]) -> Optional[str]:
    candidates_lower = {c.lower(): c for c in candidates}
    for kw in keywords:
        kw_lower = kw.lower()
        # Exact match first
        if kw_lower in candidates_lower:
            return candidates_lower[kw_lower]
        # Substring match
        for cl, orig in candidates_lower.items():
            if kw_lower in cl or cl in kw_lower:
                return orig
    return None


def vendor_match_node(state: WorkflowState) -> WorkflowState:
    plan = state.get("orchestration_plan", {})
    keywords = plan.get("components") or [state["user_query"].strip().lower()]

    names = _get_names()
    subreddits = _get_subreddits()

    matched_vendor = _match(keywords, names) or ""
    matched_subreddit = _match(keywords, subreddits) or ""

    print(f"[DEBUG vendor_match] keywords={keywords} vendor={matched_vendor!r} subreddit={matched_subreddit!r}")
    return {
        "matched_vendor": matched_vendor,
        "matched_subreddit": matched_subreddit,
    }
