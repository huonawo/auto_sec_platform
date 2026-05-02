import os
import re
import json
import logging
import uuid

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("shannon")

app = FastAPI(title="Shannon Plugin", version="1.0.0")


def _parse_json(text: str) -> dict:
    """Strip markdown code fences and parse JSON from LLM response."""
    cleaned = re.sub(r"^```(?:json)?\s*\n?", "", text.strip())
    cleaned = re.sub(r"\n?```\s*$", "", cleaned)
    return json.loads(cleaned)


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


REVIEW_SYSTEM = """你是 Shannon，一个命令审查和优化专家。请用中文回答。
给定一组待执行的命令，你的任务是：
1. 检查命令是否正确、完整
2. 结合专业知识补充遗漏的参数（如 curl 缺少 -k、nmap 缺少 -sV 等）
3. 优化命令以提高成功率
4. 移除明显错误或危险的命令

规则：
- 保持命令的核心意图不变
- 如果命令已经正确，保持原样
- 确保所有 curl 命令包含 -k 参数
- 仅处理授权安全测试的命令

请用以下 JSON 结构回复（不要输出任何其他内容）：
{{"commands": ["优化后的命令1", "优化后的命令2"], "changes": ["修改说明1"], "notes": "备注"}}"""


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


class ReviewRequest(BaseModel):
    commands: list[str]       # Commands from PentestGPT to review
    target: str = ""
    category: str = ""
    skill_content: str = ""   # For context-aware review
    context: str = ""         # Why these commands were suggested


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
        parsed = _parse_json(result)
    except (json.JSONDecodeError, Exception):
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
        parsed = _parse_json(result)
    except (json.JSONDecodeError, Exception):
        parsed = {"raw_response": result}

    return {"status": "ok", "execution": parsed}


@app.post("/review")
def review(req: ReviewRequest):
    """Review and optimize commands from PentestGPT against skill knowledge."""
    if not req.commands:
        return {"status": "ok", "reviewed": {"commands": [], "changes": [], "notes": "No commands to review"}}

    if not llm.available:
        # Fallback: return original commands with no changes
        return {"status": "ok", "reviewed": {"commands": req.commands, "changes": [], "notes": "LLM unavailable, returning original commands"}}

    # Build user prompt with commands and context
    commands_text = "\n".join(f"{i+1}. {cmd}" for i, cmd in enumerate(req.commands))
    user_prompt = f"待审查的命令：\n{commands_text}\n\n目标: {req.target}\n类别: {req.category}\n"

    if req.context:
        user_prompt += f"上下文: {req.context}\n"

    if req.skill_content:
        # Truncate skill content to avoid overwhelming the review
        skill = req.skill_content[:3000]
        user_prompt += f"\n相关专业知识:\n{skill}\n"

    result = llm.chat(REVIEW_SYSTEM, user_prompt)
    if result is None:
        # Fallback: return original commands
        return {"status": "ok", "reviewed": {"commands": req.commands, "changes": [], "notes": "LLM call failed, returning original commands"}}

    try:
        parsed = _parse_json(result)
    except (json.JSONDecodeError, Exception):
        parsed = {"raw_response": result}

    # Ensure we always return a valid commands list
    reviewed_commands = parsed.get("commands", [])
    if not reviewed_commands:
        # Fallback to original if LLM returned empty commands
        reviewed_commands = req.commands
        parsed["commands"] = reviewed_commands
        parsed.setdefault("changes", []).append("LLM returned empty commands, using originals")

    return {"status": "ok", "reviewed": parsed}


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
