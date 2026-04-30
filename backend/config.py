import re
from typing import Any, Dict, List

RELEASETRAIN_BASE = "https://releasetrain.io/api/component/"
GOOGLE_NEWS_RSS = "https://news.google.com/rss/search"
REDDIT_QUESTIONS_API = "https://releasetrain.io/api/reddit/query/questions"
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_NVD_RESULTS = 40

# Groq has per-request token limits; cap data volume for the prioritizer prompt.
MAX_RELEASETRAIN_ITEMS_TOTAL = 80
MAX_CVES_FOR_LLM = 35
MAX_RELEASE_NOTES_FOR_LLM = 35
MAX_NEWS_FOR_LLM = 18
MAX_FIELD_CHARS = 500
MAX_REDDIT_QUESTIONS_FETCH = 20
MAX_REDDIT_QUESTIONS_ANSWER = 5

CVE_ID_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# Shipped with API for UI: maps LangGraph nodes to agentic roles (plan → tools → reason).
AGENT_PIPELINE_META: List[Dict[str, Any]] = [
    {
        "id": "orchestrate",
        "role": "llm_agent",
        "node": "orchestrator",
        "label": "Orchestrator",
        "detail": "Classifies query as security or out-of-scope. Extracts 1-3 software component keywords. Out-of-scope queries are rejected here before any data is fetched.",
    },
    {
        "id": "vendor_match",
        "role": "deterministic",
        "node": "vendor_match",
        "label": "Vendor Match",
        "detail": "Matches keywords against 14,000 known vendor names from ReleaseTrain. Returns canonical vendor name and matched subreddit for precise API targeting.",
    },
    {
        "id": "reddit_fetch",
        "role": "tool",
        "node": "reddit_questions_fetch",
        "label": "Reddit Fetch",
        "detail": "Fetches posts from the matched subreddit. Uses vendor-specific subreddit endpoint when available, falls back to general security feed.",
    },
    {
        "id": "reddit_enrich",
        "role": "llm_agent",
        "node": "reddit_enrich",
        "label": "Keyword Enrichment",
        "detail": "LLM reads Reddit post titles and author descriptions to expand vague query terms into specific product keywords before fetching CVE and release data.",
    },
    {
        "id": "gather",
        "role": "parallel_tools",
        "node": "nvd_fetch + release_train_fetch + google_news_fetch",
        "label": "Parallel Fetch",
        "detail": "Three sources run concurrently: NVD API (CVSS scores), ReleaseTrain vendor endpoint (version records), Google News RSS (display context only).",
    },
    {
        "id": "merge",
        "role": "state_merge",
        "node": "merge",
        "label": "Context Assembly",
        "detail": "Combines NVD CVEs, release notes, and news into one structured context. NVD entries tagged separately for CVSS-based ranking.",
    },
    {
        "id": "prioritize",
        "role": "llm_agent",
        "node": "prioritize + evidence_repair + deterministic_match",
        "label": "Prioritizer",
        "detail": "LLM ranks by CVSS score with evidence IDs. Missing refs filled by repair LLM then deterministic token-overlap fallback. Grounding validator flags hallucinated CVE IDs.",
    },
    {
        "id": "format",
        "role": "presentation",
        "node": "format",
        "label": "Response Formatter",
        "detail": "Shapes ranked results and evidence for the UI. Includes signal breakdown, grounding warnings, and supporting news panel.",
    },
]
