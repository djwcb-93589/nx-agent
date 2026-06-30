# extra_server.py
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from http import HTTPStatus
from urllib.parse import urlparse, parse_qs
import os
import json
import glob

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# 相对于当前文件(backend目录)获取 result_deepseek/firewallexample 的绝对路径
EVENTS_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "result_deepseek", "firewallexample"))

# 资产表
asset_list = [
    dict(ip="192.168.100.10", name="终端A", mac="00:e0:4c:fe:ad:10", owner="用户A", department="终端部门1"),
    dict(ip="192.168.100.11", name="终端B", mac="00:e0:4c:fe:ad:11", owner="用户B", department="终端部门2"),
    dict(ip="192.168.100.50", name="管理端", mac="00:e0:4c:fe:ad:50", owner="管理员", department="IT部门"),
    dict(ip="192.168.100.80", name="防火墙服务", mac="00:e0:4c:fe:ad:80", owner="管理员", department="IT部门"),
]


def load_events(base_dir: str) -> list:
    all_events = []
    search_pattern = os.path.join(base_dir, "防火墙安全策略日志", "customer_events.json")
    print(f"search_pattern: {search_pattern}")
    for file_path in glob.glob(search_pattern, recursive=True):
        print(f"file_path: {file_path}")
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                events = json.load(f)
                if isinstance(events, list):
                    all_events.extend(events)
        except Exception:
            continue
    return all_events


def get_asset_by_ip(ip: str, assets: list) -> dict:
    for a in assets:
        if a.get("ip") == ip:
            return a
    return {}


def get_alarm_list(page: int = 1, page_size: int = 10) -> dict:
    events = load_events(EVENTS_DIR)
    
    event_list = []
    for item in events:
        alarm_type = item.get("alarm_type")
        data = item.get("data", {})
        
        src_ip = data.get("src_ip", "")
        src_mac = data.get("src_mac", data.get("srp_mac", ""))
        dst_ip = data.get("dst_ip", "")
        dst_port = data.get("dst_port", "")
        login_account = data.get("login_account", "")
        
        # # 条件1: scp_ip/mac = 终端A或者B的信息
        # cond1 = src_ip in ["192.168.100.10", "192.168.100.11"] or src_mac in ["00:e0:4c:fe:ad:10", "00:e0:4c:fe:ad:11"]
        # # 条件2: dst_ip/mac/port = 防火墙服务, 并且login_account=root
        # cond2 = dst_ip == "192.168.100.80" and login_account == "root"
        
        # # 事件1: 用户终端违规登录运维管理员账户
        # if alarm_type == 1 and cond1 and cond2:
        #     asset_info = get_asset_by_ip(src_ip, asset_list)
        #     event_info = {
        #         "event_name": "用户终端违规登录运维管理员账户",
        #         "event_type": alarm_type,
        #         "time": data.get("login_time", ""),
        #         "involved_assets": asset_info.get("name", ""),
        #         "involved_ip": src_ip,
        #         "src_ip": src_ip,
        #         "srp_mac": src_mac,
        #         "src_owner": asset_info.get("owner", ""),
        #         "src_department": asset_info.get("department", ""),
        #         "dst_ip": dst_ip,
        #         "dst_port": dst_port,
        #         "login_account": login_account,
        #         "login_time": data.get("login_time", "")
        #     }
        #     event_list.append(event_info)
            
        # # 事件2: 用户终端违规登录非运维管理员账户
        # elif alarm_type in [2, 3] and cond1 and cond2:
        #     asset_info = get_asset_by_ip(src_ip, asset_list)
        #     event_info = {
        #         "event_name": "用户终端违规登录非运维管理员账户",
        #         "event_type": alarm_type,
        #         "time": data.get("login_time", ""),
        #         "involved_assets": asset_info.get("name", ""),
        #         "involved_ip": src_ip,
        #         "src_ip": src_ip,
        #         "src_mac": src_mac,
        #         "src_owner": asset_info.get("owner", ""),
        #         "src_department": asset_info.get("department", ""),
        #         "dst_ip": dst_ip,
        #         "dst_port": dst_port,
        #         "protocol": data.get("protocol", "IP协议TCP"),
        #         "login_account": login_account,
        #         "login_time": data.get("login_time", "")
        #     }
        #     event_list.append(event_info)

        # 事件3: 管理员修改防火墙策略为全通  
        if alarm_type == 4:
            # 条件1: src_ip = "any", 条件2: dst_ip = "any"
            if src_ip == "any" and dst_ip == "any":
                control_ip = data.get("control_ip", "")
                asset_info = get_asset_by_ip(control_ip, asset_list)
                event_info = {
                    "event_name": "管理员修改防火墙策略为全通",
                    "event_type": alarm_type,
                    "time": data.get("login_time", ""),
                    "involved_assets": data.get("control_name", ""),
                    "involved_ip": control_ip,
                    "control_device_type": data.get("control_device_type", ""),
                    "control_name": data.get("control_name", ""),
                    "control_ip": control_ip,
                    "control_owner": asset_info.get("owner", ""),
                    "control_owner_department": asset_info.get("department", ""),
                    "action": data.get("action", ""),
                    "policy": data.get("policy", ""),
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "login_account": login_account,
                    "login_time": data.get("login_time", "")
                }
                event_list.append(event_info)

    # 按照 time 降序排序
    event_list.sort(key=lambda x: x.get("time", ""), reverse=True)

    # 按 control_ip (或 involved_ip) 去重，保留 time 最大的记录
    # 由于已经按 time 降序排列，每个 IP 第一次出现的记录即为最大时间记录
    dedup_list = []
    seen_ips = set()
    for event in event_list:
        group_ip = event.get("control_ip", event.get("involved_ip", ""))
        if group_ip not in seen_ips:
            seen_ips.add(group_ip)
            dedup_list.append(event)

    total = len(dedup_list)
    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    paginated_list = dedup_list[start_idx:end_idx]

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "data": paginated_list
    }


class ExtraHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/alarm/list":
            query = parse_qs(parsed.query)
            try:
                page = int(query.get("page", ["1"])[0])
                page_size = int(query.get("page_size", ["10"])[0])
            except ValueError:
                page = 1
                page_size = 10
                
            response_data = get_alarm_list(page, page_size)
            print(f"response_data: {response_data}")
            body = json.dumps(response_data, ensure_ascii=False).encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_error(404)


def main():
    server = ThreadingHTTPServer(("0.0.0.0", 9000), ExtraHandler)
    server.serve_forever()

if __name__ == "__main__":
    main()
