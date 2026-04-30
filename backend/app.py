from typing import Any, Dict

from langgraph.graph import END, StateGraph

from backend.models import WorkflowState
from backend.nodes.enrich import reddit_enrich_node
from backend.nodes.fetchers import google_news_node, nvd_node, reddit_questions_node, release_train_node
from backend.nodes.formatter import formatter_node
from backend.nodes.merge import merge_node
from backend.nodes.orchestrator import orchestrator_node
from backend.nodes.prioritizer import prioritize_node
from backend.nodes.vendor_match import vendor_match_node


def build_graph():
    graph = StateGraph(WorkflowState)
    graph.add_node("orchestrator", orchestrator_node)
    graph.add_node("vendor_match", vendor_match_node)
    graph.add_node("reddit_questions_fetch", reddit_questions_node)
    graph.add_node("reddit_enrich", reddit_enrich_node)
    graph.add_node("release_train_fetch", release_train_node)
    graph.add_node("google_news_fetch", google_news_node)
    graph.add_node("nvd_fetch", nvd_node)
    graph.add_node("merge", merge_node)
    graph.add_node("prioritize", prioritize_node)
    graph.add_node("format", formatter_node)

    graph.set_entry_point("orchestrator")
    # Step 1: match vendor from known list
    graph.add_edge("orchestrator", "vendor_match")
    # Step 2: fetch Reddit using matched subreddit if available
    graph.add_edge("vendor_match", "reddit_questions_fetch")
    # Step 3: enrich keywords from Reddit context
    graph.add_edge("reddit_questions_fetch", "reddit_enrich")
    # Step 4: all three fetchers run in parallel with enriched keywords + matched vendor
    graph.add_edge("reddit_enrich", "release_train_fetch")
    graph.add_edge("reddit_enrich", "google_news_fetch")
    graph.add_edge("reddit_enrich", "nvd_fetch")
    # Step 5: all three complete before merge
    graph.add_edge("release_train_fetch", "merge")
    graph.add_edge("google_news_fetch", "merge")
    graph.add_edge("nvd_fetch", "merge")
    graph.add_edge("merge", "prioritize")
    graph.add_edge("prioritize", "format")
    graph.add_edge("format", END)
    return graph.compile()


def run_query(user_query: str) -> Dict[str, Any]:
    app = build_graph()
    return app.invoke({"user_query": user_query})
