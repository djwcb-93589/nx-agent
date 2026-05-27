import time

from openai import OpenAI

from env_utils import get_env, load_dotenv


class DeepSeekClient:
    def __init__(
        self,
        model=None,
        api_key=None,
        api_key_env="DEEPSEEK_API_KEY",
        base_url=None,
        timeout=120,
        max_retries=5,
        temperature=0.0,
        reasoning_effort="high",
        thinking_enabled=True,
    ):
        load_dotenv()
        model = model or get_env("DEEPSEEK_MODEL", "deepseek-v4-flash")
        base_url = base_url or get_env(
            "DEEPSEEK_BASE_URL",
            "https://api.deepseek.com",
            aliases=("OPENAI_BASE_URL", "LLM_BASE_URL"),
        )
        resolved_api_key = (
            api_key
            or get_env(api_key_env)
            or get_env("DEEPSEEK_API_KEY", aliases=("DS_TOKEN", "OPENAI_API_KEY", "OPENAI_KEY"))
        )
        if not resolved_api_key:
            raise ValueError(
                "DeepSeek API key is missing. Set DEEPSEEK_API_KEY or pass --api_key."
            )

        self.model = model
        self.max_retries = max_retries
        self.temperature = temperature
        self.reasoning_effort = reasoning_effort
        self.thinking_enabled = thinking_enabled
        self.client = OpenAI(
            api_key=resolved_api_key,
            base_url=base_url.rstrip("/"),
            timeout=timeout,
            max_retries=0,
        )

    def generate(
        self,
        messages,
        max_tokens=1024,
        temperature=None,
        response_format_json=True,
        reasoning_effort=None,
        thinking_enabled=None,
    ):
        last_error = None
        request_temperature = (
            self.temperature if temperature is None else temperature
        )

        for attempt in range(1, self.max_retries + 1):
            try:
                request_kwargs = {
                    "model": self.model,
                    "messages": messages,
                    "max_tokens": max_tokens,
                    "temperature": request_temperature,
                    "reasoning_effort": reasoning_effort or self.reasoning_effort,
                    "extra_body": {
                        "thinking": {
                            "type": "enabled"
                            if (
                                self.thinking_enabled
                                if thinking_enabled is None
                                else thinking_enabled
                            )
                            else "disabled"
                        }
                    },
                }
                if response_format_json:
                    request_kwargs["response_format"] = {"type": "json_object"}
                response = self.client.chat.completions.create(**request_kwargs)
                content = response.choices[0].message.content
                if isinstance(content, list):
                    text_parts = []
                    for item in content:
                        if isinstance(item, dict) and item.get("type") == "text":
                            text_parts.append(item.get("text", ""))
                    content = "".join(text_parts)
                if not isinstance(content, str) or not content.strip():
                    raise ValueError("DeepSeek returned an empty response.")
                return content.strip()
            except Exception as exc:
                last_error = exc
                if attempt == self.max_retries:
                    break
                wait_seconds = min(2 ** (attempt - 1), 8)
                print(
                    f"DeepSeek request failed on attempt {attempt}/{self.max_retries}: {exc}. "
                    f"Retrying in {wait_seconds}s...",
                    flush=True,
                )
                time.sleep(wait_seconds)

        raise RuntimeError(f"DeepSeek request failed after retries: {last_error}")
