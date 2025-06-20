import base64
import json
import os
import subprocess
import time
import requests
import re
from urllib.parse import urlparse, parse_qs, unquote
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
import yaml

# 常量定义
SOCKS_PORT = 1080
HTTP_PORT = 8080
TEST_URL = "https://www.tiktok.com"
TIMEOUT = 5  # 秒
MAX_NODES = 1000  # 最大测试节点数
MAX_CONCURRENT = 10  # 最大并发线程数
OUTPUT_DIR = "data"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "sub.txt")
LATENCY_THRESHOLD = 1000  # 延迟阈值（毫秒）

# 支持的协议
SINGBOX_PROTOCOLS = {"vmess", "vless", "trojan", "ss", "ssr", "hysteria2"}
XRAY_PROTOCOLS = {"vmess", "vless", "trojan", "ss"}

# 日志记录
def log_message(level, message):
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"[{timestamp}] [{level.upper()}] {message}")

# 解析 vmess://
def parse_vmess_url(url):
    if not url.startswith("vmess://"):
        return None
    try:
        encoded = url[len("vmess://"):]
        decoded = base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)).decode("utf-8")
        return json.loads(decoded)
    except Exception as e:
        log_message("error", f"解析 vmess:// 失败: {e}")
        return None

# 解析 vless://
def parse_vless_url(url):
    if not url.startswith("vless://"):
        return None
    try:
        parsed_url = urlparse(url)
        return {
            "protocol": "vless",
            "id": parsed_url.username or "",
            "address": parsed_url.hostname or "",
            "port": parsed_url.port or 443,
            "encryption": parse_qs(parsed_url.query).get("encryption", ["none"])[0],
            "flow": parse_qs(parsed_url.query).get("flow", [""])[0],
            "security": parse_qs(parsed_url.query).get("security", [""])[0],
            "sni": parse_qs(parsed_url.query).get("sni", [""])[0],
            "network": parse_qs(parsed_url.query).get("type", ["tcp"])[0],
            "path": parse_qs(parsed_url.query).get("path", ["/"])[0],
            "host": parse_qs(parsed_url.query).get("host", [""])[0],
            "remarks": unquote(parsed_url.fragment) or "VLESS Node"
        }
    except Exception as e:
        log_message("error", f"解析 vless:// 失败: {e}")
        return None

# 解析 trojan://
def parse_trojan_url(url):
    if not url.startswith("trojan://"):
        return None
    try:
        parsed_url = urlparse(url)
        return {
            "protocol": "trojan",
            "password": parsed_url.username or "",
            "address": parsed_url.hostname or "",
            "port": parsed_url.port or 443,
            "sni": parse_qs(parsed_url.query).get("sni", [""])[0],
            "network": parse_qs(parsed_url.query).get("type", ["tcp"])[0],
            "path": parse_qs(parsed_url.query).get("path", ["/"])[0],
            "host": parse_qs(parsed_url.query).get("host", [""])[0],
            "remarks": unquote(parsed_url.fragment) or "Trojan Node"
        }
    except Exception as e:
        log_message("error", f"解析 trojan:// 失败: {e}")
        return None

# 解析 ssr://
def parse_ssr_url(url):
    if not url.startswith("ssr://"):
        return None
    try:
        encoded = url[len("ssr://"):]
        decoded = base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)).decode("utf-8")
        parts = decoded.split(':')
        if len(parts) < 6:
            return None
        server, port, protocol, method, obfs, password = parts[:6]
        password = base64.urlsafe_b64decode(password + '=' * (-len(password) % 4)).decode("utf-8")
        query = parse_qs(decoded.split('?')[-1]) if '?' in decoded else {}
        return {
            "server": server,
            "port": int(port),
            "protocol": protocol,
            "method": method,
            "obfs": obfs,
            "password": password,
            "obfs_param": query.get("obfsparam", [""])[0],
            "protocol_param": query.get("protoparam", [""])[0],
            "remarks": base64.urlsafe_b64decode(query.get("remarks", [""])[0] + '=' * (-len(query.get("remarks", [""])[0]) % 4)).decode("utf-8") if query.get("remarks") else "SSR Node"
        }
    except Exception as e:
        log_message("error", f"解析 ssr:// 失败: {e}")
        return None

# 解析 ss://
def parse_ss_url(url):
    if not url.startswith("ss://"):
        return None
    try:
        encoded = url[len("ss://"):url.index('@')]
        decoded = base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)).decode("utf-8")
        method, password = decoded.split(':')
        parsed_url = urlparse(url)
        return {
            "method": method,
            "password": password,
            "server": parsed_url.hostname or "",
            "port": parsed_url.port or 443,
            "remarks": unquote(parsed_url.fragment) or "SS Node"
        }
    except Exception as e:
        log_message("error", f"解析 ss:// 失败: {e}")
        return None

# 解析 hysteria2://
def parse_hysteria2_url(url):
    if not url.startswith("hysteria2://"):
        return None
    try:
        parsed_url = urlparse(url)
        return {
            "password": parsed_url.username or "",
            "server": parsed_url.hostname or "",
            "port": parsed_url.port or 443,
            "sni": parse_qs(parsed_url.query).get("sni", [""])[0],
            "insecure": parse_qs(parsed_url.query).get("insecure", ["0"])[0] == "1",
            "remarks": unquote(parsed_url.fragment) or "Hysteria2 Node"
        }
    except Exception as e:
        log_message("error", f"解析 hysteria2:// 失败: {e}")
        return None

# 生成 Sing-Box 配置
def generate_singbox_config(node_url):
    try:
        if node_url.startswith("hysteria2://"):
            node_data = parse_hysteria2_url(node_url)
            if not node_data or not node_data["server"] or not node_data["password"]:
                return None
            return json.dumps({
                "log": {"level": "warn"},
                "inbounds": [
                    {"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": SOCKS_PORT},
                    {"type": "http", "tag": "http-in", "listen": "127.0.0.1", "listen_port": HTTP_PORT}
                ],
                "outbounds": [
                    {
                        "type": "hysteria2",
                        "tag": "proxy",
                        "server": node_data["server"],
                        "server_port": node_data["port"],
                        "password": node_data["password"],
                        "tls": {
                            "disable_sni": node_data["insecure"],
                            "server_name": node_data["sni"] or node_data["server"]
                        }
                    },
                    {"type": "direct", "tag": "direct"},
                    {"type": "block", "tag": "block"}
                ],
                "route": {"default_outbound": "proxy"}
            }, indent=2)
        elif node_url.startswith("vmess://"):
            node_data = parse_vmess_url(node_url)
            if not node_data or not node_data.get("add") or not node_data.get("id"):
                return None
            return json.dumps({
                "log": {"level": "warn"},
                "inbounds": [
                    {"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": SOCKS_PORT},
                    {"type": "http", "tag": "http-in", "listen": "127.0.0.1", "listen_port": HTTP_PORT}
                ],
                "outbounds": [
                    {
                        "type": "vmess",
                        "tag": "proxy",
                        "server": node_data.get("add"),
                        "server_port": int(node_data.get("port", 443)),
                        "uuid": node_data.get("id"),
                        "security": node_data.get("scy", "auto"),
                        "alter_id": int(node_data.get("aid", 0)),
                        "transport": {
                            "type": node_data.get("net", "tcp"),
                            "path": node_data.get("path", ""),
                            "host": node_data.get("host", "")
                        }
                    },
                    {"type": "direct", "tag": "direct"},
                    {"type": "block", "tag": "block"}
                ],
                "route": {"default_outbound": "proxy"}
            }, indent=2)
        elif node_url.startswith("vless://"):
            node_data = parse_vless_url(node_url)
            if not node_data or not node_data["address"] or not node_data["id"]:
                return None
            return json.dumps({
                "log": {"level": "warn"},
                "inbounds": [
                    {"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": SOCKS_PORT},
                    {"type": "http", "tag": "http-in", "listen": "127.0.0.1", "listen_port": HTTP_PORT}
                ],
                "outbounds": [
                    {
                        "type": "vless",
                        "tag": "proxy",
                        "server": node_data["address"],
                        "server_port": node_data["port"],
                        "uuid": node_data["id"],
                        "flow": node_data["flow"],
                        "tls": {
                            "enabled": node_data["security"] in ["tls", "reality"],
                            "server_name": node_data["sni"] or node_data["address"],
                            "insecure": node_data["security"] == "none"
                        },
                        "transport": {
                            "type": node_data["network"],
                            "path": node_data["path"],
                            "host": node_data["host"]
                        }
                    },
                    {"type": "direct", "tag": "direct"},
                    {"type": "block", "tag": "block"}
                ],
                "route": {"default_outbound": "proxy"}
            }, indent=2)
        elif node_url.startswith("trojan://"):
            node_data = parse_trojan_url(node_url)
            if not node_data or not node_data["address"] or not node_data["password"]:
                return None
            return json.dumps({
                "log": {"level": "warn"},
                "inbounds": [
                    {"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": SOCKS_PORT},
                    {"type": "http", "tag": "http-in", "listen": "127.0.0.1", "listen_port": HTTP_PORT}
                ],
                "outbounds": [
                    {
                        "type": "trojan",
                        "tag": "proxy",
                        "server": node_data["address"],
                        "server_port": node_data["port"],
                        "password": node_data["password"],
                        "tls": {
                            "enabled": True,
                            "server_name": node_data["sni"] or node_data["address"]
                        },
                        "transport": {
                            "type": node_data["network"],
                            "path": node_data["path"],
                            "host": node_data["host"]
                        }
                    },
                    {"type": "direct", "tag": "direct"},
                    {"type": "block", "tag": "block"}
                ],
                "route": {"default_outbound": "proxy"}
            }, indent=2)
        elif node_url.startswith("ss://"):
            node_data = parse_ss_url(node_url)
            if not node_data or not node_data["server"] or not node_data["password"]:
                return None
            return json.dumps({
                "log": {"level": "warn"},
                "inbounds": [
                    {"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": SOCKS_PORT},
                    {"type": "http", "tag": "http-in", "listen": "127.0.0.1", "listen_port": HTTP_PORT}
                ],
                "outbounds": [
                    {
                        "type": "shadowsocks",
                        "tag": "proxy",
                        "server": node_data["server"],
                        "server_port": node_data["port"],
                        "method": node_data["method"],
                        "password": node_data["password"]
                    },
                    {"type": "direct", "tag": "direct"},
                    {"type": "block", "tag": "block"}
                ],
                "route": {"default_outbound": "proxy"}
            }, indent=2)
        elif node_url.startswith("ssr://"):
            node_data = parse_ssr_url(node_url)
            if not node_data or not node_data["server"] or not node_data["password"]:
                return None
            return json.dumps({
                "log": {"level": "warn"},
                "inbounds": [
                    {"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": SOCKS_PORT},
                    {"type": "http", "tag": "http-in", "listen": "127.0.0.1", "listen_port": HTTP_PORT}
                ],
                "outbounds": [
                    {
                        "type": "shadowsocksr",
                        "tag": "proxy",
                        "server": node_data["server"],
                        "server_port": node_data["port"],
                        "method": node_data["method"],
                        "password": node_data["password"],
                        "obfs": node_data["obfs"],
                        "obfs_param": node_data["obfs_param"],
                        "protocol": node_data["protocol"],
                        "protocol_param": node_data["protocol_param"]
                    },
                    {"type": "direct", "tag": "direct"},
                    {"type": "block", "tag": "block"}
                ],
                "route": {"default_outbound": "proxy"}
            }, indent=2)
        else:
            log_message("warn", f"Sing-Box 不支持的协议: {node_url}")
            return None
    except Exception as e:
        log_message("error", f"生成 Sing-Box 配置失败: {e} - {node_url}")
        return None

# 生成 Xray 配置
def generate_xray_config(node_url):
    try:
        if node_url.startswith("hysteria2://") or node_url.startswith("ssr://"):
            return None
        elif node_url.startswith("vmess://"):
            node_data = parse_vmess_url(node_url)
            if not node_data or not node_data.get("add") or not node_data.get("id"):
                return None
            return json.dumps({
                "log": {"loglevel": "warning"},
                "inbounds": [
                    {"protocol": "socks", "listen": "127.0.0.1", "port": SOCKS_PORT},
                    {"protocol": "http", "listen": "127.0.0.1", "port": HTTP_PORT}
                ],
                "outbounds": [
                    {
                        "protocol": "vmess",
                        "settings": {
                            "vnext": [{
                                "address": node_data.get("add"),
                                "port": int(node_data.get("port", 443)),
                                "users": [{"id": node_data.get("id"), "alterId": int(node_data.get("aid", 0))}]
                            }]
                        },
                        "streamSettings": {
                            "network": node_data.get("net", "tcp"),
                            "security": "none" if node_data.get("tls", "") == "" else "tls",
                            "tlsSettings": {"serverName": node_data.get("host", "")} if node_data.get("tls") else {}
                        }
                    },
                    {"protocol": "freedom", "tag": "direct"},
                    {"protocol": "blackhole", "tag": "block"}
                ]
            }, indent=2)
        elif node_url.startswith("vless://"):
            node_data = parse_vless_url(node_url)
            if not node_data or not node_data["address"] or not node_data["id"]:
                return None
            return json.dumps({
                "log": {"loglevel": "warning"},
                "inbounds": [
                    {"protocol": "socks", "listen": "127.0.0.1", "port": SOCKS_PORT},
                    {"protocol": "http", "listen": "127.0.0.1", "port": HTTP_PORT}
                ],
                "outbounds": [
                    {
                        "protocol": "vless",
                        "settings": {
                            "vnext": [{
                                "address": node_data["address"],
                                "port": node_data["port"],
                                "users": [{"id": node_data["id"], "encryption": node_data["encryption"]}]
                            }]
                        },
                        "streamSettings": {
                            "network": node_data["network"],
                            "security": node_data["security"],
                            "tlsSettings": {"serverName": node_data["sni"] or node_data["address"]} if node_data["security"] == "tls" else {}
                        }
                    },
                    {"protocol": "freedom", "tag": "direct"},
                    {"protocol": "blackhole", "tag": "block"}
                ]
            }, indent=2)
        elif node_url.startswith("trojan://"):
            node_data = parse_trojan_url(node_url)
            if not node_data or not node_data["address"] or not node_data["password"]:
                return None
            return json.dumps({
                "log": {"loglevel": "warning"},
                "inbounds": [
                    {"protocol": "socks", "listen": "127.0.0.1", "port": SOCKS_PORT},
                    {"protocol": "http", "listen": "127.0.0.1", "port": HTTP_PORT}
                ],
                "outbounds": [
                    {
                        "protocol": "trojan",
                        "settings": {
                            "servers": [{
                                "address": node_data["address"],
                                "port": node_data["port"],
                                "password": node_data["password"]
                            }]
                        },
                        "streamSettings": {
                            "network": node_data["network"],
                            "security": "tls",
                            "tlsSettings": {"serverName": node_data["sni"] or node_data["address"]}
                        }
                    },
                    {"protocol": "freedom", "tag": "direct"},
                    {"protocol": "blackhole", "tag": "block"}
                ]
            }, indent=2)
        elif node_url.startswith("ss://"):
            node_data = parse_ss_url(node_url)
            if not node_data or not node_data["server"] or not node_data["password"]:
                return None
            return json.dumps({
                "log": {"loglevel": "warning"},
                "inbounds": [
                    {"protocol": "socks", "listen": "127.0.0.1", "port": SOCKS_PORT},
                    {"protocol": "http", "listen": "127.0.0.1", "port": HTTP_PORT}
                ],
                "outbounds": [
                    {
                        "protocol": "shadowsocks",
                        "settings": {
                            "servers": [{
                                "address": node_data["server"],
                                "port": node_data["port"],
                                "method": node_data["method"],
                                "password": node_data["password"]
                            }]
                        }
                    },
                    {"protocol": "freedom", "tag": "direct"},
                    {"protocol": "blackhole", "tag": "block"}
                ]
            }, indent=2)
        else:
            log_message("warn", f"Xray 不支持的协议: {node_url}")
            return None
    except Exception as e:
        log_message("error", f"生成 Xray 配置失败: {e} - {node_url}")
        return None

# 测试节点延迟
def run_test(core_name, config_path, node_url_original):
    try:
        if core_name == "sing-box":
            process = subprocess.Popen(["sing-box", "run", "-c", config_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        elif core_name == "xray":
            process = subprocess.Popen(["xray", "-c", config_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            return None, "Unknown core"

        time.sleep(1)
        start_time = time.time()
        response = requests.get(TEST_URL, proxies={"http": f"socks5://127.0.0.1:{SOCKS_PORT}"}, timeout=TIMEOUT)
        latency = (time.time() - start_time) * 1000
        process.kill()

        if response.status_code == 200:
            return latency, "Success"
        else:
            return None, f"HTTP Status {response.status_code}"
    except requests.exceptions.RequestException as e:
        if process:
            process.kill()
        return None, f"Request failed: {e}"
    except Exception as e:
        if process:
            process.kill()
        return None, f"Test failed: {e}"

# 处理单个节点
def process_node(node_url, index, total_nodes):
    log_message("info", f"处理节点 {index}/{total_nodes}: {node_url}")
    protocol = node_url.split("://")[0].lower()
    singbox_latency, singbox_result = None, "Skipped"
    xray_latency, xray_result = None, "Skipped"

    # 测试 Sing-Box
    if protocol in SINGBOX_PROTOCOLS:
        singbox_config = generate_singbox_config(node_url)
        if singbox_config:
            singbox_config_path = f"singbox_config_{index}.json"
            with open(singbox_config_path, "w") as f:
                f.write(singbox_config)
            singbox_latency, singbox_result = run_test("sing-box", singbox_config_path, node_url)
            os.remove(singbox_config_path)
        else:
            singbox_latency, singbox_result = None, "Config generation failed"

    # 测试 Xray
    if protocol in XRAY_PROTOCOLS:
        xray_config = generate_xray_config(node_url)
        if xray_config:
            xray_config_path = f"xray_config_{index}.json"
            with open(xray_config_path, "w") as f:
                f.write(xray_config)
            xray_latency, xray_result = run_test("xray", xray_config_path, node_url)
            os.remove(xray_config_path)
        else:
            xray_latency, xray_result = None, "Config generation failed"

    log_message("info", f"节点 {index} 结果: Sing-Box 延迟={singbox_latency}ms, 结果={singbox_result}; Xray 延迟={xray_latency}ms, 结果={xray_result}")
    return singbox_latency, node_url, singbox_result, xray_latency, xray_result

# 加载本地节点列表
def load_node_list(file_path="all_nodes.txt"):
    if not os.path.exists(file_path):
        log_message("error", f"节点文件 {file_path} 不存在")
        return []
    try:
        log_message("info", f"从 {file_path} 加载节点列表...")
        with open(file_path, "r", encoding="utf-8") as f:
            nodes = [line.strip() for line in f.readlines() if line.strip()]
        pattern = re.compile(r"^(vmess|vless|trojan|ss|ssr|hysteria2)://[^\s]+$")
        nodes = [node for node in nodes if pattern.match(node)]
        if not nodes:
            log_message("error", "节点列表为空或无有效节点")
            return []
        log_message("info", f"成功加载 {len(nodes)} 个节点")
        return nodes[:MAX_NODES]
    except Exception as e:
        log_message("error", f"加载节点列表失败: {e}")
        return []

# 主函数
def main():
    start_time = time.time()
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    nodes = load_node_list()
    if not nodes:
        log_message("error", "无节点可测试，退出")
        return

    results = []
    with ThreadPoolExecutor(max_workers=MAX_CONCURRENT) as executor:
        future_to_node = {executor.submit(process_node, node_url, i + 1, len(nodes)): node_url for i, node_url in enumerate(nodes)}
        for future in as_completed(future_to_node):
            try:
                result = future.result()
                if result[0] and result[0] < LATENCY_THRESHOLD:
                    results.append(result)
            except Exception as e:
                log_message("error", f"节点处理失败: {e}")

    # 按 Sing-Box 延迟排序
    results.sort(key=lambda x: x[0] if x[0] is not None else float('inf'))

    # 保存结果到 data/sub.txt（追加模式）
    with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        f.write(f"\n# Updated at {timestamp}\n")
        valid_nodes = [node[1] for node in results if node[0] is not None]
        for node_url in valid_nodes:
            f.write(f"{node_url}\n")
        if valid_nodes:
            subscription_content = "\n".join(valid_nodes)
            base64_subscription = base64.urlsafe_b64encode(subscription_content.encode()).decode().rstrip("=")
            f.write(f"#base64\n{base64_subscription}\n")
        log_message("info", f"保存了 {len(valid_nodes)} 个有效节点到 {OUTPUT_FILE}")

    log_message("info", f"总运行时间: {time.time() - start_time:.2f} 秒")

if __name__ == "__main__":
    main()
