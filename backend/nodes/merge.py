from backend.models import WorkflowState


def merge_node(state: WorkflowState) -> WorkflowState:
    # Merge ReleaseTrain CVEs + NVD CVEs into one list; NVD entries are tagged with source
    releasetrain_cves = state.get("cves", [])
    nvd_cves = [{"_nvd": True, **c} for c in state.get("nvd_cves", [])]
    merged = {
        "user_query": state["user_query"],
        "plan": state.get("orchestration_plan", {}),
        "release_notes": state.get("release_notes", []),
        "cves": releasetrain_cves + nvd_cves,
        "news": state.get("news", []),
        "reddit_questions": state.get("reddit_questions", []),
    }
    return {"merged": merged}
