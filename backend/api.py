import os
from pathlib import Path
from typing import Any, Dict

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from backend.app import run_query

# Load env from project root and/or backend (common when key lives in backend/.env only).
_ROOT = Path(__file__).resolve().parents[1]
_BACKEND_DIR = Path(__file__).resolve().parent
load_dotenv(_ROOT / ".env")
load_dotenv(_BACKEND_DIR / ".env")


class QueryRequest(BaseModel):
    query: str = Field(min_length=2, max_length=300)


class QueryResponse(BaseModel):
    formatted_response: str
    merged: Dict[str, Any]
    ranked: list[Dict[str, Any]]


api = FastAPI(title="Software Update Prioritizer API", version="1.0.0")

api.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@api.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@api.post("/prioritize", response_model=QueryResponse)
def prioritize_updates(payload: QueryRequest) -> QueryResponse:
    if not os.getenv("GROQ_API_KEY"):
        raise HTTPException(status_code=500, detail="GROQ_API_KEY is missing in environment.")

    try:
        result = run_query(payload.query)
        return QueryResponse(
            formatted_response=result.get("formatted_response", ""),
            merged=result.get("merged", {}),
            ranked=result.get("ranked", []),
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Prioritization failed: {exc}") from exc
