import os

from langchain_groq import ChatGroq


def get_llm() -> ChatGroq:
    model_name = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
    return ChatGroq(model=model_name, temperature=0)


def get_repair_llm() -> ChatGroq:
    model_name = os.getenv("GROQ_REPAIR_MODEL") or os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
    return ChatGroq(model=model_name, temperature=0)
