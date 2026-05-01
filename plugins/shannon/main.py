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

PLAN_SYSTEM = """你是 Shannon，一个自动化攻击链编排引擎。请用中文回答。
给定漏洞列表和目标信息，生成渗透测试人员应遵循的有序攻击链。

规则：
- 按影响最大/最容易利用到最低排序
- 每个步骤必须可执行，并引用具体工具或技术
- 包含步骤间的依赖关系
- 仅建议授权安全测试的技术

请用以下 JSON 结构回复（不要输出任何其他内容）：
{
  "chain_id": "chain-xxx",
  "target": "目标",
  "steps": [
    {
      "step_id": "step-1",
      "action": "动作",
      "tool": "工具",
      "description": "描述",
      "depends_on": [],
      "risk_level": "低|中|高|严重"
    }
  ]
}"""


EXECUTE_SYSTEM = """你是 Shannon，一个自动化攻击链编排引擎。请用中文回答。
给定要执行的单个攻击步骤，生成确切的命令和参数。

规则：
- 输出精确的 shell 命令或工具调用
- 包含所有必要的标志和参数
- 注意任何前置条件或环境设置
- 仅生成授权安全测试的命令

请用以下 JSON 结构回复（不要输出任何其他内容）：
{"step_id": "step-1", "commands": ["命令1"], "notes": "备注", "expected_output": "预期输出"}"""


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
