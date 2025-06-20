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
# 增加多个测试URL，提高测试的全面性
TEST_URLS = [
    "https://www.tiktok.com",
    "https://www.google.com/generate_204", # Google的无内容页面，常用于检测网络连通性
    "http://connectivitycheck.gstatic.com/generate_204", # Android系统常用连通性检测URL
    # "https://www.youtube.com", # 如果需要测试YouTube解锁，但可能更耗时且易被检测
]
TEST_COUNT = 3  # 每个节点测试次数
TIMEOUT = 5  # 单次请求超时时间（秒）
MAX_NODES = 1000  # 最大测试节点数
MAX_CONCURRENT = 10  # 最大并发线程数
OUTPUT_DIR = "data"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "sub.txt")
LATENCY_THRESHOLD = 500  # 延迟阈值（毫秒），从1000降至500，筛选更高质量节点

# 支持的协议
SINGBOX_PROTOCOLS = {"vmess", "vless", "trojan", "ss", "ssr", "hysteria2"}
XRAY_PROTOCOLS = {"vmess", "vless", "trojan", "ss"}

# 日志记录
def log_message(level, message):
    """
    记录带时间戳的日志信息。
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"[{timestamp}] [{level.upper()}] {message}")

# --- 节点解析函数 ---
# 这些函数负责将不同协议的URL解析成字典，以便生成代理核心的配置

def parse_vmess_url(url):
    """解析 vmess:// 链接"""
    if not url.startswith("vmess://"):
        return None
    try:
        encoded = url[len("vmess://"):]
        # Base64解码时，需要填充'='以确保长度是4的倍数
        decoded = base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)).decode("utf-8")
        return json.loads(decoded)
    except Exception as e:
        log_message("error", f"解析 vmess:// 失败: {e}")
        return None

def parse_vless_url(url):
    """解析 vless:// 链接"""
    if not url.startswith("vless://"):
        return None
    try:
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        return {
            "protocol": "vless",
            "id": parsed_url.username or "",
            "address": parsed_url.hostname or "",
            "port": parsed_url.port or 443,
            "encryption": query_params.get("encryption", ["none"])[0],
            "flow": query_params.get("flow", [""])[0],
            "security": query_params.get("security", [""])[0],
            "sni": query_params.get("sni", [""])[0],
            "network": query_params.get("type", ["tcp"])[0],
            "path": query_params.get("path", ["/"])[0],
            "host": query_params.get("host", [""])[0],
            "remarks": unquote(parsed_url.fragment) or "VLESS Node"
        }
    except Exception as e:
        log_message("error", f"解析 vless:// 失败: {e}")
        return None

def parse_trojan_url(url):
    """解析 trojan:// 链接"""
    if not url.startswith("trojan://"):
        return None
    try:
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        return {
            "protocol": "trojan",
            "password": parsed_url.username or "",
            "address": parsed_url.hostname or "",
            "port": parsed_url.port or 443,
            "sni": query_params.get("sni", [""])[0],
            "network": query_params.get("type", ["tcp"])[0],
            "path": query_params.get("path", ["/"])[0],
            "host": query_params.get("host", [""])[0],
            "remarks": unquote(parsed_url.fragment) or "Trojan Node"
        }
    except Exception as e:
        log_message("error", f"解析 trojan:// 失败: {e}")
        return None

def parse_ssr_url(url):
    """解析 ssr:// 链接"""
    if not url.startswith("ssr://"):
        return None
    try:
        encoded = url[len("ssr://"):]
        decoded = base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)).decode("utf-8")
        parts = decoded.split(':')
        if len(parts) < 6:
            return None
        server, port, protocol, method, obfs, password_encoded = parts[:6]
        # SSR的密码也需要单独解码
        password = base64.urlsafe_b64decode(password_encoded + '=' * (-len(password_encoded) % 4)).decode("utf-8")
        
        query = parse_qs(decoded.split('?')[-1]) if '?' in decoded else {}
        
        remarks_encoded = query.get("remarks", [""])[0]
        remarks = base64.urlsafe_b64decode(remarks_encoded + '=' * (-len(remarks_encoded) % 4)).decode("utf-8") if remarks_encoded else "SSR Node"

        return {
            "server": server,
            "port": int(port),
            "protocol": protocol,
            "method": method,
            "obfs": obfs,
            "password": password,
            "obfs_param": query.get("obfsparam", [""])[0],
            "protocol_param": query.get("protoparam", [""])[0],
            "remarks": remarks
        }
    except Exception as e:
        log_message("error", f"解析 ssr:// 失败: {e}")
        return None

def parse_ss_url(url):
    """解析 ss:// 链接"""
    if not url.startswith("ss://"):
        return None
    try:
        # SS URL的格式通常是 ss://base64(method:password)@server:port#remarks
        encoded_part = url[len("ss://"):url.index('@')]
        decoded_auth = base64.urlsafe_b64decode(encoded_part + '=' * (-len(encoded_part) % 4)).decode("utf-8")
        method, password = decoded_auth.split(':', 1) # 只按第一个冒号分割
        
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

def parse_hysteria2_url(url):
    """解析 hysteria2:// 链接"""
    if not url.startswith("hysteria2://"):
        return None
    try:
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        return {
            "password": parsed_url.username or "",
            "server": parsed_url.hostname or "",
            "port": parsed_url.port or 443,
            "sni": query_params.get("sni", [""])[0],
            "insecure": query_params.get("insecure", ["0"])[0] == "1",
            "remarks": unquote(parsed_url.fragment) or "Hysteria2 Node"
        }
    except Exception as e:
        log_message("error", f"解析 hysteria2:// 失败: {e}")
        return None

# --- 配置生成函数 ---
# 这些函数将解析后的节点数据转换为 Sing-Box 或 Xray 的JSON配置

def generate_singbox_config(node_url):
    """根据节点URL生成Sing-Box的JSON配置"""
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
                            "disable_sni": node_data["insecure"], # 如果insecure为True，则禁用SNI
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
                            "enabled": node_data["security"] in ["tls", "reality"], # vless有tls和reality两种加密
                            "server_name": node_data["sni"] or node_data["address"],
                            "insecure": node_data["security"] == "none" # 如果security为none，则认为不安全连接
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

def generate_xray_config(node_url):
    """根据节点URL生成Xray的JSON配置"""
    try:
        # Xray目前不支持Hysteria2和SSR，直接返回None
        if node_url.startswith("hysteria2://") or node_url.startswith("ssr://"):
            return None
        elif node_url.startswith("vmess://"):
            node_data = parse_vmess_url(node_url)
            if not node_data or not node_data.get("add") or not node_data.get("id"):
                return None
            # Xray配置中关于TLS和传输设置的映射可能与Sing-Box略有不同
            stream_settings = {
                "network": node_data.get("net", "tcp")
            }
            if node_data.get("tls") == "tls": # vmess的tls字段通常是"tls"或空
                stream_settings["security"] = "tls"
                stream_settings["tlsSettings"] = {"serverName": node_data.get("host", "")}
            
            # 根据传输类型添加特有设置
            if node_data.get("net") == "ws":
                stream_settings["wsSettings"] = {
                    "path": node_data.get("path", "/"),
                    "headers": {"Host": node_data.get("host", "")}
                }
            elif node_data.get("net") == "http":
                stream_settings["httpSettings"] = {
                    "path": node_data.get("path", "/"),
                    "host": node_data.get("host", "").split(',') # Xray的httpSettings host是列表
                }
            
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
                        "streamSettings": stream_settings
                    },
                    {"protocol": "freedom", "tag": "direct"},
                    {"protocol": "blackhole", "tag": "block"}
                ]
            }, indent=2)
        elif node_url.startswith("vless://"):
            node_data = parse_vless_url(node_url)
            if not node_data or not node_data["address"] or not node_data["id"]:
                return None
            
            stream_settings = {
                "network": node_data["network"]
            }
            if node_data["security"] in ["tls", "reality"]:
                stream_settings["security"] = node_data["security"]
                stream_settings["tlsSettings"] = {"serverName": node_data["sni"] or node_data["address"]}
            
            # 根据传输类型添加特有设置
            if node_data["network"] == "ws":
                stream_settings["wsSettings"] = {
                    "path": node_data["path"],
                    "headers": {"Host": node_data["host"]}
                }
            elif node_data["network"] == "http":
                stream_settings["httpSettings"] = {
                    "path": node_data["path"],
                    "host": node_data["host"].split(',')
                }

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
                                "users": [{"id": node_data["id"], "encryption": node_data["encryption"], "flow": node_data["flow"]}]
                            }]
                        },
                        "streamSettings": stream_settings
                    },
                    {"protocol": "freedom", "tag": "direct"},
                    {"protocol": "blackhole", "tag": "block"}
                ]
            }, indent=2)
        elif node_url.startswith("trojan://"):
            node_data = parse_trojan_url(node_url)
            if not node_data or not node_data["address"] or not node_data["password"]:
                return None

            stream_settings = {
                "network": node_data["network"],
                "security": "tls", # Trojan协议本身就强制TLS
                "tlsSettings": {"serverName": node_data["sni"] or node_data["address"]}
            }

            if node_data["network"] == "ws":
                stream_settings["wsSettings"] = {
                    "path": node_data["path"],
                    "headers": {"Host": node_data["host"]}
                }
            elif node_data["network"] == "http":
                stream_settings["httpSettings"] = {
                    "path": node_data["path"],
                    "host": node_data["host"].split(',')
                }

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
                        "streamSettings": stream_settings
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

# --- 测试函数 ---

def run_single_test(core_name, config_path):
    """
    运行单次代理核心测试，并返回延迟和结果。
    """
    process = None
    try:
        if core_name == "sing-box":
            process = subprocess.Popen(["sing-box", "run", "-c", config_path], 
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        elif core_name == "xray":
            process = subprocess.Popen(["xray", "-c", config_path], 
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            return None, "Unknown core"

        time.sleep(1) # 等待代理核心启动
        
        # 尝试访问多个测试URL，只要有一个成功就算成功
        total_latency = 0
        success_count = 0
        
        for test_url in TEST_URLS:
            try:
                start_time = time.time()
                response = requests.get(test_url, proxies={"http": f"socks5://127.0.0.1:{SOCKS_PORT}"}, timeout=TIMEOUT)
                latency = (time.time() - start_time) * 1000
                if response.status_code == 200 or response.status_code == 204: # 204是成功但无内容的响应码
                    total_latency += latency
                    success_count += 1
                    break # 只要有一个成功就跳出循环
            except requests.exceptions.RequestException:
                continue # 当前URL失败，尝试下一个

        if process:
            process.kill() # 终止代理核心进程
            process.wait(timeout=1) # 等待进程彻底终止，避免僵尸进程
            # 清理stdout和stderr缓冲区，避免死锁
            try:
                process.stdout.read()
                process.stderr.read()
            except ValueError: # 如果进程已关闭，读取可能会失败
                pass

        if success_count > 0:
            return total_latency / success_count, "Success" # 返回平均延迟
        else:
            return None, "All test URLs failed"

    except Exception as e:
        if process:
            process.kill()
            process.wait(timeout=1)
            try:
                process.stdout.read()
                process.stderr.read()
            except ValueError:
                pass
        return None, f"Test failed: {e}"

def run_test_with_retries(core_name, config_path):
    """
    对一个节点进行多次测试，返回最佳（最低）延迟。
    """
    latencies = []
    for i in range(TEST_COUNT):
        latency, result = run_single_test(core_name, config_path)
        if latency is not None:
            latencies.append(latency)
        else:
            log_message("debug", f"Core {core_name} test attempt {i+1} failed: {result}")
    
    if latencies:
        # 返回所有成功测试的平均延迟
        avg_latency = sum(latencies) / len(latencies)
        return avg_latency, "Success"
    else:
        return None, "All test attempts failed"


def process_node(node_url, index, total_nodes):
    """
    处理单个节点，包括生成配置、运行测试并返回结果。
    """
    log_message("info", f"处理节点 {index}/{total_nodes}: {node_url}")
    protocol = node_url.split("://")[0].lower()
    singbox_latency, singbox_result = None, "Skipped"
    xray_latency, xray_result = None, "Skipped"

    # 测试 Sing-Box
    if protocol in SINGBOX_PROTOCOLS:
        singbox_config = generate_singbox_config(node_url)
        if singbox_config:
            singbox_config_path = f"singbox_config_{index}.json"
            try:
                with open(singbox_config_path, "w") as f:
                    f.write(singbox_config)
                singbox_latency, singbox_result = run_test_with_retries("sing-box", singbox_config_path)
            finally: # 确保配置文件被删除
                if os.path.exists(singbox_config_path):
                    os.remove(singbox_config_path)
        else:
            singbox_latency, singbox_result = None, "Config generation failed"

    # 测试 Xray
    if protocol in XRAY_PROTOCOLS:
        xray_config = generate_xray_config(node_url)
        if xray_config:
            xray_config_path = f"xray_config_{index}.json"
            try:
                with open(xray_config_path, "w") as f:
                    f.write(xray_config)
                xray_latency, xray_result = run_test_with_retries("xray", xray_config_path)
            finally: # 确保配置文件被删除
                if os.path.exists(xray_config_path):
                    os.remove(xray_config_path)
        else:
            xray_latency, xray_result = None, "Config generation failed"

    log_message("info", f"节点 {index} 结果: Sing-Box 延迟={singbox_latency}ms, 结果={singbox_result}; Xray 延迟={xray_latency}ms, 结果={xray_result}")
    
    # 返回原始URL和两个测试核心的结果，方便后续排序和筛选
    return node_url, singbox_latency, singbox_result, xray_latency, xray_result

# --- 主逻辑函数 ---

def load_node_list(file_path="all_nodes.txt"):
    """
    从指定文件加载节点列表，并进行初步的格式验证。
    """
    if not os.path.exists(file_path):
        log_message("error", f"节点文件 {file_path} 不存在")
        return []
    try:
        log_message("info", f"从 {file_path} 加载节点列表...")
        with open(file_path, "r", encoding="utf-8") as f:
            nodes = [line.strip() for line in f.readlines() if line.strip()]
        
        # 严格匹配支持的协议
        pattern = re.compile(r"^(vmess|vless|trojan|ss|ssr|hysteria2)://[^\s]+$")
        nodes = [node for node in nodes if pattern.match(node)]
        
        if not nodes:
            log_message("error", "节点列表为空或无有效节点")
            return []
        
        log_message("info", f"成功加载 {len(nodes)} 个节点")
        return nodes[:MAX_NODES] # 限制最大处理节点数
    except Exception as e:
        log_message("error", f"加载节点列表失败: {e}")
        return []

def main():
    """
    主函数，执行节点测试、筛选和结果保存。
    """
    start_time = time.time()
    os.makedirs(OUTPUT_DIR, exist_ok=True) # 确保输出目录存在

    nodes = load_node_list()
    if not nodes:
        log_message("error", "无节点可测试，退出")
        return

    # 存储所有通过测试的节点及其最佳延迟
    # 格式: (node_url, best_latency)
    qualified_nodes_info = [] 

    with ThreadPoolExecutor(max_workers=MAX_CONCURRENT) as executor:
        # 提交所有节点的处理任务
        future_to_node = {executor.submit(process_node, node_url, i + 1, len(nodes)): node_url 
                          for i, node_url in enumerate(nodes)}
        
        # 遍历已完成的任务
        for future in as_completed(future_to_node):
            node_url_original = future_to_node[future] # 获取原始节点URL
            try:
                # result 是 (node_url, singbox_latency, singbox_result, xray_latency, xray_result)
                node_url_returned, singbox_latency, singbox_result, xray_latency, xray_result = future.result()
                
                best_latency = float('inf')
                
                # 判断Sing-Box测试结果
                if singbox_latency is not None and singbox_latency < LATENCY_THRESHOLD:
                    best_latency = min(best_latency, singbox_latency)
                
                # 判断Xray测试结果
                if xray_latency is not None and xray_latency < LATENCY_THRESHOLD:
                    best_latency = min(best_latency, xray_latency)
                
                # 如果有任何一个核心测试成功且延迟在阈值内，则认为该节点合格
                if best_latency != float('inf'):
                    qualified_nodes_info.append((node_url_returned, best_latency))

            except Exception as e:
                log_message("error", f"处理节点 {node_url_original} 时发生异常: {e}")

    # 根据最佳延迟进行排序（升序）
    qualified_nodes_info.sort(key=lambda x: x[1])

    # 提取合格节点的URL列表，并使用集合进行最终去重，同时保留顺序
    final_sorted_unique_nodes = []
    seen_urls = set()
    for url, latency in qualified_nodes_info:
        if url not in seen_urls:
            final_sorted_unique_nodes.append(url)
            seen_urls.add(url)
    
    # 保存结果到 data/sub.txt
    # 注意：使用 "w" 模式，确保每次运行都覆盖旧文件，而不是追加
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        f.write(f"# Updated at {timestamp}\n")
        
        for node_url in final_sorted_unique_nodes:
            f.write(f"{node_url}\n")

    log_message("info", f"保存了 {len(final_sorted_unique_nodes)} 个有效节点到 {OUTPUT_FILE}")
    log_message("info", f"总运行时间: {time.time() - start_time:.2f} 秒")

if __name__ == "__main__":
    main()
