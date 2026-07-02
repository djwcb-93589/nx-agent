from env_utils import get_env, load_dotenv


load_dotenv()

DEFAULT_LLM_API_KEY = ""
DEFAULT_LLM_MODEL_ID = get_env(
    "GLM_MODEL",
    "glm-5.2",
    aliases=("ZAI_MODEL", "LLM_MODEL"),
)
DEFAULT_LLM_BASE_URL = get_env(
    "GLM_BASE_URL",
    "https://api.z.ai/api/paas/v4/",
    aliases=("ZAI_BASE_URL", "OPENAI_BASE_URL", "LLM_BASE_URL"),
)
DEFAULT_SERPAPI_API_KEY = get_env("SERPAPI_API_KEY")
