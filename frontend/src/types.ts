export type SignalBreakdown = {
  cve_pct: number;
  release_pct: number;
  news_pct: number;
  label?: string;
};

export type EvidenceRow = {
  ref: string;
  kind: string;
  source_tool?: string | null;
  resolved?: boolean;
  title?: string;
  component?: string;
  version?: string;
  severity?: string;
  source_query?: string;
  source?: string;
  published?: string;
  link?: string;
};

export type EvidenceAttachedBy = "llm" | "repair_llm" | "deterministic" | "none";

export type RankedItem = {
  software: string;
  priority_score: number;
  rank: number;
  reasons: string[];
  suggested_action: string;
  evidence_refs?: string[];
  evidence_attached_by?: EvidenceAttachedBy | string;
  evidence?: EvidenceRow[];
  signal_breakdown?: SignalBreakdown;
  grounded?: boolean;
  grounding_warnings?: string[];
};

export type AgentPipelineStep = {
  id: string;
  role: string;
  node: string;
  label: string;
  detail: string;
};

export type MergedPayload = {
  user_query?: string;
  llm_summary?: string;
  plan?: { rationale?: string; components?: string[] };
  cves?: unknown[];
  release_notes?: unknown[];
  news?: Array<{ title?: string; link?: string; source?: string; published?: string }>;
  grounding_summary?: { ranked_count?: number; grounded_count?: number };
  evidence_provenance_summary?: Partial<Record<"llm" | "repair_llm" | "deterministic" | "none", number>>;
  agent_pipeline?: AgentPipelineStep[];
};

export type PrioritizeResponse = {
  formatted_response: string;
  merged: MergedPayload;
  ranked: RankedItem[];
};
