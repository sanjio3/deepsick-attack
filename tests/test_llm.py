import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import json
import os
import tempfile
import unittest
from unittest.mock import patch

from deepsick_attack.llm import (
    LLMConfigError,
    MiniMaxClient,
    get_config,
    load_dotenv,
)


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def read(self):
        return json.dumps(self._payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class LLMTest(unittest.TestCase):
    def setUp(self):
        self.keys = ["MINIMAX_API_KEY", "ANTHROPIC_API_KEY", "MINIMAX_BASE_URL",
                     "MINIMAX_MODEL", "MINIMAX_EFFORT", "MINIMAX_MAX_TOKENS"]
        self.saved = {k: os.environ.pop(k, None) for k in self.keys}

    def tearDown(self):
        for key, value in self.saved.items():
            os.environ.pop(key, None)
            if value is not None:
                os.environ[key] = value

    def test_load_dotenv_reads_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".env"
            path.write_text("A=one\n# comment\nB=two\nbroken\n", encoding="utf-8")
            values = load_dotenv(path)
        self.assertEqual(values["A"], "one")
        self.assertEqual(values["B"], "two")
        self.assertEqual(len(values), 2)
        os.environ.pop("A", None)
        os.environ.pop("B", None)

    def test_get_config_requires_key(self):
        with patch("deepsick_attack.llm.load_dotenv", return_value={}):
            with self.assertRaises(LLMConfigError):
                get_config()

    def test_get_config_defaults(self):
        os.environ["MINIMAX_API_KEY"] = "dummy"
        with patch("deepsick_attack.llm.load_dotenv", return_value={}):
            config = get_config()
        self.assertEqual(config["base_url"], "https://api.minimax.cn/anthropic")
        self.assertEqual(config["model"], "MiniMax-M3.1-Flash")
        self.assertEqual(config["effort"], "low")
        self.assertEqual(config["max_tokens"], 4096)

    def test_complete_extracts_text_blocks_only(self):
        payload = {
            "content": [
                {"type": "thinking", "thinking": "internal"},
                {"type": "text", "text": "OK"},
            ],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 10},
            "model": "MiniMax-M3.1-Flash",
        }
        config = {
            "api_key": "dummy",
            "base_url": "https://api.minimax.cn/anthropic",
            "model": "MiniMax-M3.1-Flash",
            "effort": "low",
            "max_tokens": 1024,
        }
        with patch("urllib.request.urlopen", return_value=FakeResponse(payload)) as mocked:
            result = MiniMaxClient(config).check()
        self.assertEqual(result["text"], "OK")
        self.assertEqual(result["stop_reason"], "end_turn")
        request = mocked.call_args[0][0]
        self.assertEqual(request.full_url,
                         "https://api.minimax.cn/anthropic/v1/messages")
        self.assertTrue(request.get_header("Authorization").startswith("Bearer "))
        body = json.loads(request.data.decode("utf-8"))
        self.assertEqual(body["model"], "MiniMax-M3.1-Flash")
        self.assertIn("output_config", body)


if __name__ == "__main__":
    unittest.main()
