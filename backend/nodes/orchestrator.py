from typing import Any, Dict

from pydantic import BaseModel, Field

from backend.llm import get_llm
from backend.models import DataSourcePlan, WorkflowState


class OrchestratorOutput(BaseModel):
    intent: str = Field(
        description=(
            "Classify the query intent as one of: "
            "'security' (CVEs, vulnerabilities, patch urgency, should I update, is it safe), "
            "'out_of_scope' (version lookup, how to install, general how-to, pricing, comparisons). "
        )
    )
    out_of_scope_reply: str = Field(
        default="",
        description=(
            "Only fill this if intent=out_of_scope. "
            "Write a short 1-sentence message telling the user what this tool does "
            "and suggest how to rephrase their query as a security/patch question."
        )
    )
    use_release_train: bool = True
    use_google_news: bool = True
    components: list = Field(default_factory=list)
    rationale: str = ""


def orchestrator_node(state: WorkflowState) -> WorkflowState:
    llm = get_llm()
    planner = llm.with_structured_output(OrchestratorOutput)
    prompt = (
        "You are an orchestration agent for a software security patch prioritization tool.\n"
        "This tool answers: CVEs, vulnerabilities, patch urgency, whether to update, latest patches/security fixes, version history, what version was released on a specific date.\n"
        "Mark as 'out_of_scope' ONLY for: how-to install guides, pricing, feature comparisons, purely general knowledge with no patch angle.\n"
        "When in doubt, classify as 'security' — it is better to try and find no data than to wrongly reject.\n\n"
        "Examples of 'security': 'what is the latest patch for linux', 'do I need to update chrome', 'any CVEs in nginx'\n"
        "Examples of 'out_of_scope': 'how do I install python', 'what is the price of Windows', 'compare vim vs emacs'\n\n"
        "Given the user query:\n"
        "1. Classify intent as 'security' or 'out_of_scope'\n"
        "2. If out_of_scope: write a short out_of_scope_reply suggesting a security-focused rephrasing\n"
        "3. If security: set use_release_train=true, use_google_news=true, and extract 1-3 lowercase software/component keywords\n\n"
        f"User query: {state['user_query']}"
    )
    plan = planner.invoke(prompt)

    print(f"[DEBUG orchestrator] intent={plan.intent} components={plan.components} use_news={plan.use_google_news} use_rt={plan.use_release_train}")

    if plan.intent == "out_of_scope":
        return {
            "orchestration_plan": {
                "intent": "out_of_scope",
                "out_of_scope_reply": plan.out_of_scope_reply,
                "use_release_train": False,
                "use_google_news": False,
                "components": [],
                "rationale": plan.rationale,
            }
        }

    components = plan.components or [state["user_query"].strip().lower()]
    return {
        "orchestration_plan": {
            "intent": "security",
            "use_release_train": True,
            "use_google_news": True,
            "components": components,
            "rationale": plan.rationale,
        }
    }
