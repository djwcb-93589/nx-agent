import unittest

from backend.server import merge_customer_events_into_poi_preview


class FirewallPoiDisplayMergeTests(unittest.TestCase):
    def test_customer_events_fill_missing_poi_fields_by_time_without_overwrite(self) -> None:
        poi_result = {
            "available": True,
            "columns": [
                "time",
                "event_type",
                "event_action",
                "user",
                "management_ip",
                "dst_addr",
            ],
            "rows": [
                {
                    "time": "2013/05/21 09:59:19",
                    "event_type": "",
                    "event_action": "",
                    "user": "",
                    "management_ip": "",
                    "dst_addr": "",
                },
                {
                    "time": "2013/05/21 09:56:00",
                    "event_type": "",
                    "event_action": "leave",
                    "user": "",
                    "management_ip": "",
                    "dst_addr": "",
                },
            ],
            "truncated": False,
        }
        customer_events = {
            "available": True,
            "rows": [
                {
                    "alarm_type": 3,
                    "src_ip": "192.168.100.50",
                    "dst_ip": "192.168.100.80",
                    "login_account": "root",
                    "login_time": "2013/05/21 09:56:00",
                },
                {
                    "alarm_type": 3,
                    "src_ip": "192.168.100.50",
                    "dst_ip": "192.168.100.80",
                    "login_account": "root",
                    "login_time": "2013/05/21 09:59:19",
                },
            ],
        }

        merged = merge_customer_events_into_poi_preview(poi_result, customer_events)

        self.assertEqual("root", merged["rows"][0]["user"])
        self.assertEqual("192.168.100.50", merged["rows"][0]["management_ip"])
        self.assertEqual("192.168.100.80", merged["rows"][0]["dst_addr"])
        self.assertEqual("login", merged["rows"][0]["event_action"])
        self.assertEqual("leave", merged["rows"][1]["event_action"])
        self.assertEqual("root", merged["rows"][1]["user"])


if __name__ == "__main__":
    unittest.main()
