from __future__ import annotations

from pathlib import Path
import json
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
EDC_ROOT = REPO_ROOT / "edc-log"
if str(EDC_ROOT) not in sys.path:
    sys.path.insert(0, str(EDC_ROOT))

from agent.tools.schema_tools import infer_schema_type
from agent.tools.llm_tools import generate_log_regex
from log_pipeline_agent.config import AIT_ROOT, DATASET_PATTERNS, build_ait_output_tag
from log_pipeline_agent.firewall_events import build_customer_events


class FirewallCustomerEventTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        with (REPO_ROOT / "schemas" / "firewall_customer_event_schema.json").open(
            "r",
            encoding="utf-8",
        ) as file:
            cls.schema = json.load(file)

    def test_builds_all_four_customer_alarm_types(self) -> None:
        rows = [
            self._login_row("1", "terminal", "10.0.0.1"),
            self._login_row("2", "webui", "10.0.0.2"),
            self._login_row("3", "cli", "10.0.0.3"),
            {
                "alarm_type": "4",
                "time": "2026/06/25 10:00:04",
                "device_name": "themis",
                "event_type": "policy_rule",
                "event_action": "add",
                "user": "admin",
                "rule_id": "10",
                "policy_type": "permit",
                "src_addr": "10.1.0.0/24",
                "dst_addr": "10.2.0.10",
            },
        ]
        payload = build_customer_events(
            rows,
            schema=self.schema,
            assets={},
            devices={
                "themis": {
                    "device_type": "防火墙",
                    "management_ip": "10.0.0.254",
                    "control_owner": "责任人",
                    "control_owner_department": "安全部",
                    "protocol": "TCP",
                    "web_port": "443",
                    "terminal_port": "22",
                }
            },
            source_name="test",
        )

        self.assertEqual([1, 2, 3, 4], [item["alarm_type"] for item in payload["events"]])
        self.assertEqual(0, payload["report"]["rejected_count"])
        self.assertEqual("02:00:00:00:00:01", payload["events"][0]["data"]["src_mac"])
        self.assertEqual("允许", payload["events"][3]["data"]["policy"])

    def test_rejects_event_types_not_defined_by_customer_contract(self) -> None:
        payload = build_customer_events(
            [
                {
                    "time": "2026/06/25 10:00:00",
                    "event_type": "blacklist",
                    "event_action": "add",
                    "module": "blacklist",
                }
            ],
            schema=self.schema,
            assets={},
            devices={},
            source_name="test",
        )

        self.assertEqual([], payload["events"])
        self.assertEqual(1, payload["report"]["rejected_count"])
        self.assertIn("客户协议未定义事件类型", payload["rejected"][0]["reason"])

    def test_keeps_duplicate_customer_events(self) -> None:
        row = self._login_row("3", "cli", "192.168.100.50")
        payload = build_customer_events(
            [dict(row), dict(row)],
            schema=self.schema,
            assets={},
            devices={},
            source_name="test",
        )

        self.assertEqual(2, payload["report"]["event_count"])
        self.assertEqual(payload["events"][0], payload["events"][1])

    def test_firewall_example_uses_default_device_table_for_missing_fields(self) -> None:
        payload = build_customer_events(
            [
                {
                    "time": "2026/06/25 10:00:00",
                    "device_name": "themis",
                    "module": "cli",
                    "event_type": "admin_session",
                    "event_action": "login",
                }
            ],
            schema=self.schema,
            assets={
                "192.168.100.50": {
                    "src_mac": "00:e0:4c:fe:ad:50",
                    "src_owner": "root",
                    "src_department": "管理端",
                    "default_user": "root",
                }
            },
            devices={
                "themis": {
                    "device_name": "themis",
                    "device_type": "防火墙",
                    "management_ip": "192.168.100.80",
                    "control_owner": "root",
                    "control_owner_department": "防火墙服务",
                    "protocol": "TCP",
                    "web_port": "443",
                    "cli_port": "22",
                    "terminal_port": "22",
                    "default_user": "root",
                }
            },
            source_name="firewall_example_2_1_2_1",
        )

        self.assertEqual(0, payload["report"]["rejected_count"])
        data = payload["events"][0]["data"]
        self.assertEqual("192.168.100.50", data["src_ip"])
        self.assertEqual("00:e0:4c:fe:ad:50", data["src_mac"])
        self.assertEqual("192.168.100.80", data["dst_ip"])
        self.assertEqual("22", data["dst_port"])
        self.assertEqual("root", data["login_account"])

    def test_firewall_example_keeps_non_login_cli_event(self) -> None:
        payload = build_customer_events(
            [
                {
                    "time": "2013/05/21 09:56:00",
                    "device_name": "themis",
                    "module": "cli",
                    "event_type": "admin_session",
                    "event_action": "leave",
                    "management_ip": "192.168.100.50",
                    "user": "root",
                }
            ],
            schema=self.schema,
            assets={
                "192.168.100.50": {
                    "src_mac": "00:e0:4c:fe:ad:50",
                    "default_user": "root",
                }
            },
            devices={
                "themis": {
                    "device_name": "themis",
                    "device_type": "防火墙",
                    "management_ip": "192.168.100.80",
                    "protocol": "TCP",
                    "cli_port": "22",
                    "default_user": "root",
                }
            },
            source_name="firewall_example_2_1_2_1",
        )

        self.assertEqual(1, payload["report"]["event_count"])
        self.assertEqual(0, payload["report"]["rejected_count"])
        self.assertEqual(3, payload["events"][0]["alarm_type"])

    def test_firewall_example_keeps_unknown_device_event_as_control_event(self) -> None:
        payload = build_customer_events(
            [
                {
                    "time": "2013/05/21 09:56:00",
                    "device_name": "themis",
                    "module": "blacklist",
                    "event_type": "blacklist",
                    "event_action": "show",
                    "management_ip": "192.168.100.50",
                    "user": "root",
                }
            ],
            schema=self.schema,
            assets={
                "192.168.100.50": {
                    "src_mac": "00:e0:4c:fe:ad:50",
                    "default_user": "root",
                }
            },
            devices={
                "themis": {
                    "device_name": "themis",
                    "device_type": "防火墙",
                    "management_ip": "192.168.100.80",
                    "protocol": "TCP",
                    "cli_port": "22",
                    "default_user": "root",
                }
            },
            source_name="firewall_example_2_5_7",
        )

        self.assertEqual(1, payload["report"]["event_count"])
        self.assertEqual(0, payload["report"]["rejected_count"])
        self.assertEqual(4, payload["events"][0]["alarm_type"])
        self.assertEqual("显示", payload["events"][0]["data"]["action"])

    def test_firewall_folder_uses_existing_firewall_schema(self) -> None:
        schema_type = infer_schema_type(
            "firewallexample/customer_event_simulated.log",
            REPO_ROOT / "schemas",
        )
        self.assertEqual("firewall", schema_type)

    def test_pipeline_registers_current_firewall_folder_and_simulated_source(self) -> None:
        firewall_patterns = [
            pattern.path_fragment
            for pattern in DATASET_PATTERNS
            if pattern.family == "firewall"
        ]
        self.assertEqual(6, len(firewall_patterns))
        self.assertTrue(
            all(path.startswith("firewallexample/") for path in firewall_patterns)
        )
        self.assertIn(
            "firewallexample/customer_event_simulated/3.csv",
            firewall_patterns,
        )

    def test_template_generation_has_deterministic_api_failure_fallback(self) -> None:
        class FailingTemplateEngine:
            max_new_tokens = 128

            @staticmethod
            def generate_log_template_using_pipeline(**_kwargs):
                raise RuntimeError("empty API response")

            @staticmethod
            def template_to_regex(template):
                return template.replace("<*>", "(.*?)")

            @staticmethod
            def clean_regex(_log, regex):
                return regex

        regex = generate_log_regex(
            FailingTemplateEngine(),
            [
                "device action=add user=alice",
                "device action=del user=bob",
            ],
        )
        self.assertIn("(.*?)", regex)

    def test_chinese_firewall_paths_have_unique_artifact_tags(self) -> None:
        tags = {
            build_ait_output_tag(AIT_ROOT / pattern.path_fragment)
            for pattern in DATASET_PATTERNS
            if pattern.family == "firewall"
        }
        self.assertEqual(6, len(tags))

    @staticmethod
    def _login_row(alarm_type: str, module: str, src_ip: str) -> dict[str, str]:
        suffix = alarm_type
        return {
            "alarm_type": alarm_type,
            "time": f"2026/06/25 10:00:0{suffix}",
            "device_name": "themis",
            "module": module,
            "event_type": "admin_session",
            "event_action": "login",
            "user": f"user{suffix}",
            "src_ip": src_ip,
            "src_mac": f"02:00:00:00:00:0{suffix}",
            "src_owner": f"owner{suffix}",
            "src_department": "department",
            "dst_ip": "10.0.0.254",
            "dst_port": "22" if alarm_type == "1" else "443",
            "protocol": "TCP",
        }


if __name__ == "__main__":
    unittest.main()
