import os
import json
import logging
import uuid

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("shannon")

app = FastAPI(title="Shannon Plugin", version="1.0.0")


# -- LLM Client (reused from backend/ai/llm_client.py) -----------------------

class LLMClient:
    def __init__(self):
        self.api_key = os.environ.get("AI_API_KEY") or os.environ.get("MIMO_API_KEY")
        self.base_url = os.environ.get("AI_API_BASE_URL", "https://api.xiaomimimo.com/v1")
        self.model = os.environ.get("AI_MODEL", "mimo-v2.5-pro")
        self._client = None

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    def _get_client(self):
        if self._client is None:
            from openai import OpenAI
            self._client = OpenAI(base_url=self.base_url, api_key=self.api_key)
        return self._client

    def chat(self, system_prompt: str, user_prompt: str) -> str | None:
        if not self.available:
            return None
        try:
            client = self._get_client()
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.3,
                max_tokens=4096,
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.warning("LLM call failed: %s", e)
            return None


llm = LLMClient()


# -- Prompts ------------------------------------------------------------------

PLAN_SYSTEM = """You are Shannon, an automated attack chain orchestration engine.
Given a list of vulnerabilities and target information, produce an ordered attack chain
that a penetration tester should follow.

Rules:
- Order steps from highest impact / easiest to exploit to lowest
- Each step must be actionable and reference a specific tool or technique
- Include dependencies between steps (which steps require which to complete first)
- Only suggest techniques for authorized security testing

Respond in JSON with key: chain_id, target, steps (list).
Each step: step_id, action, tool, description, depends_on (list of step_ids), risk_level."""


EXECUTE_SYSTEM = """You are Shannon, an automated attack chain orchestration engine.
Given a single attack step to execute, generate the exact command(s) and parameters.

Rules:
- Output the precise shell command or tool invocation
- Include all necessary flags and arguments
- Note any prerequisites or environment setup needed
- Only generate commands for authorized security testing

Respond in JSON with keys: step_id, commands (list of strings), notes, expected_output."""


# -- Request / Response models ------------------------------------------------

class PlanRequest(BaseModel):
    target: str
    vulnerabilities: list = []
    scan_results: dict = {}
    constraints: dict = {}


class ExecuteRequest(BaseModel):
    step_id: str
    action: str
    tool: str = ""
    target: str = ""
    parameters: dict = {}


# -- In-memory chain store (ephemeral) ----------------------------------------

chains: dict[str, dict] = {}


# -- Endpoints ----------------------------------------------------------------

@app.post("/plan")
def plan(req: PlanRequest):
    if not llm.available:
        raise HTTPException(status_code=503, detail="LLM API key not configured")

    vuln_summary = json.dumps(req.vulnerabilities, indent=2) if req.vulnerabilities else "None provided"
    scan_summary = json.dumps(req.scan_results, indent=2) if req.scan_results else "None provided"
    constraints = json.dumps(req.constraints, indent=2) if req.constraints else "None"

    user_prompt = (
        f"Target: {req.target}\n\n"
        f"Vulnerabilities:\n{vuln_summary}\n\n"
        f"Scan results:\n{scan_summary}\n\n"
        f"Constraints: {constraints}"
    )

    result = llm.chat(PLAN_SYSTEM, user_prompt)
    if result is None:
        raise HTTPException(status_code=502, detail="LLM call failed")

    try:
        parsed = json.loads(result)
    except json.JSONDecodeError:
        parsed = {"raw_response": result}

    chain_id = parsed.get("chain_id", f"chain-{uuid.uuid4().hex[:8]}")
    parsed["chain_id"] = chain_id
    chains[chain_id] = parsed

    return {"status": "ok", "chain": parsed}


@app.post("/execute")
def execute(req: ExecuteRequest):
    if not llm.available:
        raise HTTPException(status_code=503, detail="LLM API key not configured")

    user_prompt = (
        f"Step ID: {req.step_id}\n"
        f"Action: {req.action}\n"
        f"Tool: {req.tool}\n"
        f"Target: {req.target}\n"
        f"Parameters: {json.dumps(req.parameters, indent=2)}"
    )

    result = llm.chat(EXECUTE_SYSTEM, user_prompt)
    if result is None:
        raise HTTPException(status_code=502, detail="LLM call failed")

    try:
        parsed = json.loads(result)
    except json.JSONDecodeError:
        parsed = {"raw_response": result}

    return {"status": "ok", "execution": parsed}


@app.get("/chains")
def list_chains():
    return {"chains": list(chains.values())}


@app.get("/chains/{chain_id}")
def get_chain(chain_id: str):
    if chain_id not in chains:
        raise HTTPException(status_code=404, detail="Chain not found")
    return chains[chain_id]


@app.get("/health")
def health():
    return {"status": "ok", "llm_available": llm.available}
