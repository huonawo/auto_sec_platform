import os
import logging

logger = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://api.xiaomimimo.com/v1"
DEFAULT_MODEL = "mimo-v2.5-pro"


class LLMClient:
    def __init__(self):
        self.api_key = os.environ.get("AI_API_KEY") or os.environ.get("MIMO_API_KEY")
        self.base_url = os.environ.get("AI_API_BASE_URL", DEFAULT_BASE_URL)
        self.model = os.environ.get("AI_MODEL", DEFAULT_MODEL)
        self._client = None

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    def _get_client(self):
        if self._client is None:
            from openai import OpenAI
            self._client = OpenAI(
                base_url=self.base_url,
                api_key=self.api_key,
            )
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
            logger.warning("LLM API call failed: %s", e)
            return None
