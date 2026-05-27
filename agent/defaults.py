from env_utils import get_env, load_dotenv


load_dotenv()

DEFAULT_LLM_API_KEY = get_env(
    "DEEPSEEK_API_KEY",
    aliases=("DS_TOKEN", "OPENAI_API_KEY", "OPENAI_KEY"),
)
DEFAULT_LLM_MODEL_ID = get_env("DEEPSEEK_MODEL", "deepseek-v4-flash", aliases=("LLM_MODEL",))
DEFAULT_LLM_BASE_URL = get_env(
    "DEEPSEEK_BASE_URL",
    "https://api.deepseek.com",
    aliases=("OPENAI_BASE_URL", "LLM_BASE_URL"),
)
DEFAULT_SERPAPI_API_KEY = get_env("SERPAPI_API_KEY")
