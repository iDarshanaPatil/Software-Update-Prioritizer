from typing import Any, Dict, List, TypedDict

from pydantic import BaseModel, Field


class WorkflowState(TypedDict, total=False):
    user_query: str
    orchestration_plan: Dict[str, Any]
    release_notes: List[Dict[str, Any]]
    cves: List[Dict[str, Any]]
    news: List[Dict[str, Any]]
    reddit_questions: List[Dict[str, Any]]
    nvd_cves: List[Dict[str, Any]]
    enriched_components: List[str]
    matched_vendor: str
    matched_subreddit: str
    merged: Dict[str, Any]
    ranked: List[Dict[str, Any]]
    formatted_response: str


class DataSourcePlan(BaseModel):
    use_release_train: bool = True
    use_google_news: bool = True
    components: List[str] = Field(default_factory=list)
    rationale: str


class RankedItem(BaseModel):
    software: str
    priority_score: int = Field(ge=0, le=100)
    rank: int = Field(ge=1)
    reasons: List[str]
    suggested_action: str
    evidence_refs: List[str] = Field(
        default_factory=list,
        description="Stable ids from input JSON only, e.g. cve:0, release:1, news:2",
    )


class PrioritizedOutput(BaseModel):
    summary: str
    ranked_list: List[RankedItem]


class EvidenceRepairRow(BaseModel):
    rank: int = Field(ge=1)
    evidence_refs: List[str] = Field(default_factory=list)


class EvidenceRepairOutput(BaseModel):
    repairs: List[EvidenceRepairRow]
