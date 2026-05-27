from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parent.parent
PARSER_DIR = REPO_ROOT / "parser"


def ensure_parser_path():
    parser_dir = str(PARSER_DIR)
    if parser_dir not in sys.path:
        sys.path.insert(0, parser_dir)


ensure_parser_path()

