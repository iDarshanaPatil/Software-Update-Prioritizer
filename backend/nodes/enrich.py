from typing import List

from pydantic import BaseModel, Field

from backend.llm import get_llm
from backend.models import WorkflowState


class EnrichedPlan(BaseModel):
    components: List[str] = Field(
        description="Precise lowercase software/component keywords for NVD and release database search"
    )
    rationale: str


def reddit_enrich_node(state: WorkflowState) -> WorkflowState:
    plan = state.get("orchestration_plan", {})
    original_components = plan.get("components") or [state["user_query"]]
    reddit_posts = state.get("reddit_questions", [])

    # Build slim reddit context for LLM
    reddit_context = [
        {
            "title": p.get("title", ""),
            "subreddit": p.get("subreddit", ""),
            "description": p.get("author_description", "")[:400],
        }
        for p in reddit_posts[:5]
        if p.get("title")
    ]

    llm = get_llm()
    enricher = llm.with_structured_output(EnrichedPlan)
    prompt = (
        "You are a keyword extraction agent for a software vulnerability search engine.\n"
        "Given the user query, existing component keywords, and Reddit community context, "
        "extract 1-5 precise lowercase product/software keywords to search NVD and release databases.\n\n"
        "Rules:\n"
        "- Use subreddit name as a strong hint for the vendor/product (e.g. subreddit='Ubiquiti' → add 'ubiquiti')\n"
        "- Expand short names using context (e.g. 'Protect 7.0.104' + 'Ubiquiti' subreddit → ['ubiquiti protect', 'unifi protect'])\n"
        "- Keep existing keywords if they are already specific enough\n"
        "- Prefer specific product names over generic terms\n"
        "- Return only the most relevant 1-5 keywords\n\n"
        f"User query: {state['user_query']}\n"
        f"Existing components: {original_components}\n"
        f"Reddit context: {reddit_context}"
    )

    try:
        result = enricher.invoke(prompt)
        components = result.components if result.components else original_components
    except Exception:
        components = original_components

    print(f"[DEBUG enrich] original={original_components} → enriched={components}")
    return {"enriched_components": components}
