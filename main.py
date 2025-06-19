import base64
import json
import os
import re
import subprocess
import time
import urllib.parse
import socket
import logging
import yaml
import threading
import concurrent.futures
import random
from hashlib import md5
import aiohttp
import asyncio
import requests

# --- 配置日志 ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- 常量定义 ---
SINGBOX_BIN_PATH = "./clash_bin/sing-box"
SINGBOX_CONFIG_PATH = "sing-box-config.json"
SINGBOX_LOG_PATH = os.getenv("SINGBOX_LOG_PATH", "data/sing-box.log")
GEOIP_DB_PATH = "data/geoip.db"
OUTPUT_SUB_FILE = "data/collectSub.txt"
FAILED_PROXIES_FILE = "data/failed_proxies.json"
MAX_FAILED_PROXIES = 10000  # 最大保存的失败节点数

# 节点源配置列表
NODES_SOURCES = [
    {
        "url": "https://raw.githubusercontent.com/qjlxg/hy2/refs/heads/main/configtg.txt",
        "type": "plain",
    },
]

MAX_PROXIES = 925000
TEST_URLS = ["https://t.me", "https://www.tiktok.com", "https://www.youtube.com"]
HTTP_TIMEOUT_SECONDS = 8  # 增加超时时间
SINGBOX_STARTUP_TIMEOUT = 30
BASE_PROXY_PORT = 1080
CONCURRENT_TESTS = 2  # 降低并发数
SPEEDTEST_URL = "http://speed.hetzner.de/1GB.bin"
SPEEDTEST_MIN_THROUGHPUT = 100000  # 最低吞吐量（字节/秒）

# --- 确保输出目录存在 ---
for path in [OUTPUT_SUB_FILE, SINGBOX_LOG_PATH, GEOIP_DB_PATH, FAILED_PROXIES_FILE]:
    dirname = os.path.dirname(path)
    if dirname:
        os.makedirs(dirname, exist_ok=True)

# --- 辅助函数：IPv6 验证 ---
def is_valid_ipv6(addr):
    try:
        addr = addr.strip("[]")
        socket.inet_pton(socket.AF_INET6, addr)
        return True
    except (socket.error, ValueError):
        return False

# --- 辅助函数：生成代理 ID ---
def generate_proxy_id(proxy):
    # 使用代理的完整信息生成一个哈希ID
    return md5(json.dumps(proxy, sort_keys=True).encode('utf-8')).hexdigest()

# --- 辅助函数：加载/保存失败节点 ---
def load_failed_proxies():
    if os.path.exists(FAILED_PROXIES_FILE):
        try:
            with open(FAILED_PROXIES_FILE, 'r', encoding='utf-8') as f:
                return set(json.load(f))
        except json.JSONDecodeError:
            logging.warning(f"无法解析 {FAILED_PROXIES_FILE}，将创建一个新的。")
            return set()
    return set()

def save_failed_proxies(failed_proxies):
    # 只保留最新的 MAX_FAILED_PROXIES 个失败节点
    failed_proxies_list = list(failed_proxies)[-MAX_FAILED_PROXIES:]
    with open(FAILED_PROXIES_FILE, 'w', encoding='utf-8') as f:
        json.dump(failed_proxies_list, f, ensure_ascii=False, indent=2)

# --- 辅助函数：加载/保存可用节点 ---
def load_existing_proxies():
    existing_proxies = set()
    if os.path.exists(OUTPUT_SUB_FILE):
        try:
            with open(OUTPUT_SUB_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        existing_proxies.add(line)
        except Exception as e:
            logging.warning(f"加载现有代理文件 {OUTPUT_SUB_FILE} 失败: {e}")
    return existing_proxies

# --- 辅助函数：解析代理 URL (新版本) ---
def parse_proxy_url(url_string):
    """
    解析代理 URL 字符串并将其转换为 sing-box 配置字典。
    支持 VLESS, Shadowsocks (SS), VMess 协议。
    """
    try:
        parsed_url = urllib.parse.urlparse(url_string)
        scheme = parsed_url.scheme.lower()
        
        proxy_info = {"type": scheme}
        
        # 提取标签
        if parsed_url.fragment:
            proxy_info["tag"] = urllib.parse.unquote(parsed_url.fragment)
        
        if scheme == "vless":
            # netloc 格式: uuid@server:port
            if "@" not in parsed_url.netloc:
                logging.debug(f"VLESS URL格式错误: 缺少'@' - {url_string}")
                return None
            
            # 使用 rsplit 确保正确分离最后一个冒号前的服务器部分，处理 IPv6 地址
            uuid_and_addr, port_str = parsed_url.netloc.rsplit(":", 1) 
            uuid, server = uuid_and_addr.split("@", 1)
            
            proxy_info["uuid"] = uuid
            proxy_info["server"] = server.strip("[]") # 移除 IPv6 地址的方括号
            try:
                proxy_info["server_port"] = int(port_str)
            except ValueError:
                logging.debug(f"VLESS URL端口号无效: {port_str} - {url_string}")
                return None

            # 解析查询参数
            query_params = urllib.parse.parse_qs(parsed_url.query)
            
            # 常见 VLESS 参数
            proxy_info["security"] = query_params.get("security", [""])[0]
            proxy_info["flow"] = query_params.get("flow", [""])[0]
            proxy_info["tls_fingerprint"] = query_params.get("fp", [""])[0]
            proxy_info["tls_sni"] = query_params.get("sni", [""])[0]
            
            alpn = query_params.get("alpn", [""])
            if alpn and alpn[0]:
                proxy_info["tls_alpn"] = alpn[0].split(',')
            else:
                proxy_info["tls_alpn"] = []

            proxy_info["reality_public_key"] = query_params.get("pbk", [""])[0]
            proxy_info["reality_short_id"] = query_params.get("sid", [""])[0]

            # 网络特定参数
            network_type = query_params.get("type", ["tcp"])[0]
            proxy_info["network"] = network_type

            if network_type == "ws":
                proxy_info["ws_path"] = query_params.get("path", ["/"])[0]
                host = query_params.get("host", [""])[0]
                if host:
                    proxy_info["ws_headers"] = {"Host": host}
            elif network_type == "grpc":
                proxy_info["grpc_service_name"] = query_params.get("serviceName", [""])[0]
                proxy_info["grpc_mode"] = query_params.get("mode", ["gun"])[0]
            elif network_type == "httpupgrade":
                proxy_info["httpupgrade_path"] = query_params.get("path", ["/"])[0]
                proxy_info["httpupgrade_host"] = query_params.get("host", [""])[0]
            elif network_type == "h2":
                proxy_info["h2_path"] = query_params.get("path", ["/"])[0]
                proxy_info["h2_host"] = query_params.get("host", [""])[0]
            elif network_type == "http":
                proxy_info["http_path"] = query_params.get("path", ["/"])[0]
                proxy_info["http_host"] = query_params.get("host", [""])[0]
            elif network_type == "quic":
                proxy_info["quic_security"] = query_params.get("quicSecurity", [""])[0]
                proxy_info["quic_key"] = query_params.get("quicKey", [""])[0]
                proxy_info["quic_header_type"] = query_params.get("quicHeaderType", [""])[0]

        elif scheme == "ss":
            # ss://base64encoded_credentials@server:port
            if "@" not in parsed_url.netloc:
                logging.debug(f"SS URL格式错误: 缺少'@' - {url_string}")
                return None

            encoded_credentials, server_port_str = parsed_url.netloc.split("@", 1)
            
            try:
                # 尝试添加填充以确保 Base64 解码正确
                missing_padding = len(encoded_credentials) % 4
                if missing_padding:
                    encoded_credentials += '=' * (4 - missing_padding)
                decoded_credentials = base64.urlsafe_b64decode(encoded_credentials).decode('utf-8')
            except Exception as e:
                logging.debug(f"SS 凭证 Base64 解码失败: {e} - {url_string}")
                return None

            if ":" not in decoded_credentials:
                logging.debug(f"SS 凭证格式错误: 缺少':' - {url_string}")
                return None
            
            method, password = decoded_credentials.split(":", 1)
            
            server, port_str = server_port_str.rsplit(":", 1)
            proxy_info["server"] = server.strip("[]")
            try:
                proxy_info["server_port"] = int(port_str)
            except ValueError:
                logging.debug(f"SS URL端口号无效: {port_str} - {url_string}")
                return None
            proxy_info["method"] = method
            proxy_info["password"] = password

        elif scheme == "vmess":
            # vmess://base64encoded_json
            try:
                encoded_json = parsed_url.netloc
                # 确保正确的 Base64 填充
                missing_padding = len(encoded_json) % 4
                if missing_padding:
                    encoded_json += '=' * (4 - missing_padding)

                decoded_json = base64.urlsafe_b64decode(encoded_json).decode('utf-8')
                vmess_config = json.loads(decoded_json)
                
                # 将 VMess 配置映射到 sing-box proxy_info
                proxy_info["server"] = vmess_config.get("add", "").strip("[]")
                try:
                    proxy_info["server_port"] = int(vmess_config.get("port"))
                except (ValueError, TypeError):
                    logging.debug(f"VMess URL端口号无效: {vmess_config.get('port')} - {url_string}")
                    return None
                proxy_info["uuid"] = vmess_config.get("id")
                proxy_info["alterId"] = int(vmess_config.get("aid", 0))
                proxy_info["security"] = vmess_config.get("scy", "auto") # VMess 中的加密方法
                proxy_info["network"] = vmess_config.get("net", "tcp")
                proxy_info["tls_sni"] = vmess_config.get("sni", "") # 用于 VMess TLS
                
                # VMess 特定网络设置
                if proxy_info["network"] == "ws":
                    proxy_info["ws_path"] = vmess_config.get("path", "/")
                    host_header = vmess_config.get("host", "")
                    if host_header:
                        proxy_info["ws_headers"] = {"Host": host_header}
                    
                elif proxy_info["network"] == "http":
                    proxy_info["http_path"] = vmess_config.get("path", "/")
                    proxy_info["http_host"] = vmess_config.get("host", "")
                
                elif proxy_info["network"] == "h2":
                    proxy_info["h2_path"] = vmess_config.get("path", "/")
                    proxy_info["h2_host"] = vmess_config.get("host", "")

            except (json.JSONDecodeError, UnicodeDecodeError, Exception) as e:
                logging.debug(f"VMess URL解析或Base64/JSON解码失败: {e} - {url_string}")
                return None
        else:
            logging.debug(f"不支持的代理类型: {scheme} - {url_string}")
            return None

        # 如果没有在 URL 片段中指定标签，则生成一个默认标签
        if "tag" not in proxy_info:
            proxy_info["tag"] = f"{scheme}-{proxy_info.get('server', 'unknown')}:{proxy_info.get('server_port', 'unknown')}"

        return proxy_info
        
    except Exception as e:
        logging.debug(f"解析代理 URL 时发生未知错误: {e} - {url_string}")
        return None

# --- 辅助函数：将代理字典转换为 sing-box 配置格式 ---
def singbox_to_proxy_config(proxy):
    proxy_type = proxy.get("type")
    
    config = {
        "tag": proxy.get("tag", f"{proxy_type}-{proxy.get('server', 'unknown')}:{proxy.get('server_port', 'unknown')}"),
        "type": proxy_type,
        "server": proxy.get("server"),
        "server_port": proxy.get("server_port"),
    }

    if proxy_type == "vless":
        config["uuid"] = proxy.get("uuid")
        config["flow"] = proxy.get("flow") if proxy.get("flow") else "" # Empty string if None

        # Correctly handle TLS based on 'security' and 'reality' presence
        tls_enabled = proxy.get("security") != "none"
        reality_enabled = bool(proxy.get("reality_public_key") and proxy.get("reality_short_id"))
        
        config["tls"] = {"enabled": tls_enabled}

        if tls_enabled:
            if reality_enabled:
                config["tls"]["reality"] = {
                    "enabled": True,
                    "public_key": proxy.get("reality_public_key"),
                    "short_id": proxy.get("reality_short_id"),
                }
            else:
                config["tls"]["reality"] = {"enabled": False} # Explicitly disable reality if not present

            if proxy.get("tls_sni"):
                config["tls"]["server_name"] = proxy.get("tls_sni")
            if proxy.get("tls_fingerprint"):
                config["tls"]["fingerprint"] = proxy.get("tls_fingerprint")
            if proxy.get("tls_alpn"):
                config["tls"]["alpn"] = proxy.get("tls_alpn")

        network = proxy.get("network", "tcp")
        config["network"] = network
        if network == "ws":
            config["transport"] = {
                "type": "ws",
                "path": proxy.get("ws_path", "/"),
                "headers": proxy.get("ws_headers", {}),
            }
        elif network == "grpc":
            config["transport"] = {
                "type": "grpc",
                "service_name": proxy.get("grpc_service_name", ""),
                "mode": proxy.get("grpc_mode", "gun"),
            }
        elif network == "httpupgrade":
            config["transport"] = {
                "type": "http_upgrade",
                "path": proxy.get("httpupgrade_path", "/"),
                "host": proxy.get("httpupgrade_host", ""),
            }
        elif network == "h2":
            config["transport"] = {
                "type": "http", # H2 in sing-box uses http transport type with protocol h2
                "path": proxy.get("h2_path", "/"),
                "host": proxy.get("h2_host", ""),
                "headers": {"Host": [proxy.get("h2_host", "")]} if proxy.get("h2_host") else {}, # sing-box http transport requires Host in headers
                "method": "GET",
                ""protocol_version"": "2"
            }
        elif network == "http":
            config["transport"] = {
                "type": "http",
                "path": proxy.get("http_path", "/"),
                "host": proxy.get("http_host", ""),
                "headers": {"Host": [proxy.get("http_host", "")]} if proxy.get("http_host") else {},
                "method": "GET"
            }
        elif network == "quic":
            config["transport"] = {
                "type": "quic",
                "quic_security": proxy.get("quic_security", ""),
                "quic_key": proxy.get("quic_key", ""),
                "quic_header_type": proxy.get("quic_header_type", ""),
            }

    elif proxy_type == "ss":
        config["method"] = proxy.get("method")
        config["password"] = proxy.get("password")

    elif proxy_type == "vmess":
        config["uuid"] = proxy.get("uuid")
        config["alter_id"] = proxy.get("alterId", 0)
        config["security"] = proxy.get("security", "auto")
        config["network"] = proxy.get("network", "tcp")

        # VMess TLS configuration
        if proxy.get("tls_sni"):
            config["tls"] = {"enabled": True, "server_name": proxy.get("tls_sni")}
        else:
            config["tls"] = {"enabled": False}

        # VMess transport settings
        if config["network"] == "ws":
            config["transport"] = {
                "type": "ws",
                "path": proxy.get("ws_path", "/"),
                "headers": proxy.get("ws_headers", {}),
            }
        elif config["network"] == "h2":
             config["transport"] = {
                "type": "http", # H2 in sing-box uses http transport type with protocol h2
                "path": proxy.get("h2_path", "/"),
                "host": proxy.get("h2_host", ""),
                "headers": {"Host": [proxy.get("h2_host", "")]} if proxy.get("h2_host") else {},
                "method": "GET",
                ""protocol_version"": "2"
            }
        elif config["network"] == "http":
             config["transport"] = {
                "type": "http",
                "path": proxy.get("http_path", "/"),
                "host": proxy.get("http_host", ""),
                "headers": {"Host": [proxy.get("http_host", "")]} if proxy.get("http_host") else {},
                "method": "GET"
            }
        # Add other VMess network types if needed

    # Add default tags if missing (e.g., for direct connections, or for a clean output)
    if "tag" not in config or not config["tag"]:
        config["tag"] = f"{proxy_type}-{proxy.get('server', 'unknown')}-{proxy.get('server_port', 'unknown')}"

    return config

# --- 辅助函数：将代理字典转换为标准的 URL 格式 (用于输出) ---
def singbox_to_proxy_url(proxy):
    proxy_type = proxy.get("type")
    tag = proxy.get("tag", "").replace("#", "").replace("&", "") # Clean tag for URL fragment
    server = proxy.get("server")
    port = proxy.get("server_port")

    if proxy_type == "vless":
        uuid = proxy.get("uuid")
        flow = proxy.get("flow", "")
        
        # Determine security based on TLS and Reality settings
        tls_config = proxy.get("tls", {})
        security = "none"
        if tls_config.get("enabled"):
            if tls_config.get("reality", {}).get("enabled"):
                security = "reality"
            else:
                security = "tls"

        fingerprint = tls_config.get("fingerprint", "")
        sni = tls_config.get("server_name", "")
        alpn = ",".join(tls_config.get("alpn", []))
        public_key = tls_config.get("reality", {}).get("public_key", "")
        short_id = tls_config.get("reality", {}).get("short_id", "")
        
        network = proxy.get("network", "tcp")
        
        query_params = {}
        if security != "none": # Only add security if it's not "none"
            query_params["security"] = security
        if flow:
            query_params["flow"] = flow
        if fingerprint:
            query_params["fp"] = fingerprint
        if sni:
            query_params["sni"] = sni
        if alpn:
            query_params["alpn"] = alpn
        if public_key:
            query_params["pbk"] = public_key
        if short_id:
            query_params["sid"] = short_id

        transport_config = proxy.get("transport", {})
        if network == "ws":
            query_params["type"] = "ws"
            path = transport_config.get("path", "/")
            if path != "/": # Only add path if not default
                 query_params["path"] = path
            headers = transport_config.get("headers", {}).get("Host", "")
            if headers:
                query_params["host"] = headers
        elif network == "grpc":
            query_params["type"] = "grpc"
            service_name = transport_config.get("service_name", "")
            mode = transport_config.get("mode", "gun")
            if service_name: # Only add serviceName if not empty
                 query_params["serviceName"] = service_name
            if mode != "gun": # Only add mode if not default
                 query_params["mode"] = mode
        elif network == "httpupgrade":
            query_params["type"] = "httpupgrade"
            path = transport_config.get("path", "/")
            if path != "/":
                query_params["path"] = path
            host = transport_config.get("host", "")
            if host:
                query_params["host"] = host
        elif network == "h2":
            query_params["type"] = "h2"
            path = transport_config.get("path", "/")
            if path != "/":
                query_params["path"] = path
            host = transport_config.get("host", "")
            if host:
                query_params["host"] = host
        elif network == "http":
            query_params["type"] = "http"
            path = transport_config.get("path", "/")
            if path != "/":
                query_params["path"] = path
            host = transport_config.get("host", "")
            if host:
                query_params["host"] = host
        elif network == "quic":
            query_params["type"] = "quic"
            quic_security = transport_config.get("quic_security", "")
            quic_key = transport_config.get("quic_key", "")
            quic_header_type = transport_config.get("quic_header_type", "")
            if quic_security:
                query_params["quicSecurity"] = quic_security
            if quic_key:
                query_params["quicKey"] = quic_key
            if quic_header_type:
                query_params["quicHeaderType"] = quic_header_type
        
        # 构建查询字符串
        query_string = urllib.parse.urlencode(query_params)
        
        # 构建 VLESS URL
        vless_url = f"vless://{uuid}@{server}:{port}"
        if query_string:
            vless_url += f"?{query_string}"
        if tag:
            vless_url += f"#{tag}"
        return vless_url

    elif proxy_type == "ss":
        method = proxy.get("method")
        password = proxy.get("password")
        credentials = f"{method}:{password}"
        encoded_credentials = base64.urlsafe_b64encode(credentials.encode('utf-8')).decode('utf-8').rstrip('=')
        
        ss_url = f"ss://{encoded_credentials}@{server}:{port}"
        if tag:
            ss_url += f"#{tag}"
        return ss_url

    elif proxy_type == "vmess":
        vmess_config = {
            "v": "2", # VMess protocol version
            "ps": tag, # Proxy remark/tag
            "add": server,
            "port": port,
            "id": proxy.get("uuid"),
            "aid": proxy.get("alterId", 0),
            "scy": proxy.get("security", "auto"),
            "net": proxy.get("network", "tcp"),
            "tls": "tls" if proxy.get("tls", {}).get("enabled") else "",
            "sni": proxy.get("tls", {}).get("server_name", ""),
        }

        # VMess transport settings
        network = proxy.get("network", "tcp")
        transport_config = proxy.get("transport", {})
        if network == "ws":
            vmess_config["path"] = transport_config.get("path", "/")
            vmess_config["host"] = transport_config.get("headers", {}).get("Host", "")
        elif network == "h2":
            vmess_config["path"] = transport_config.get("path", "/")
            vmess_config["host"] = transport_config.get("host", "") # h2 host is directly host
        elif network == "http":
            vmess_config["path"] = transport_config.get("path", "/")
            vmess_config["host"] = transport_config.get("host", "") # http host is directly host


        encoded_json = base64.urlsafe_b64encode(json.dumps(vmess_config, ensure_ascii=False).encode('utf-8')).decode('utf-8')
        vmess_url = f"vmess://{encoded_json.rstrip('=')}"
        return vmess_url
    
    return None

# --- 核心函数：生成 sing-box 配置文件 ---
def generate_singbox_config(proxy, proxy_port):
    proxy_config = singbox_to_proxy_config(proxy)
    if not proxy_config:
        logging.error(f"无法为代理 {proxy.get('tag', 'unknown')} 生成 sing-box 配置，代理信息不完整或无效。")
        return None

    config = {
        "log": {
            "disabled": False,
            "output": SINGBOX_LOG_PATH,
            "level": "info",
            "timestamp": True
        },
        "inbounds": [
            {
                "type": "socks",
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "listen_port": proxy_port,
                "sniff": True,
                "udp_timeout": 300,
            },
        ],
        "outbounds": [
            proxy_config, # 主代理
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"}
        ],
        "route": {
            "rules": [
                {
                    "domain_suffix": [
                        "download.windowsupdate.com",
                        "msedge.net",
                        "bing.com",
                        "office.com",
                        "live.com",
                        "microsoft.com",
                        "windowsupdate.com"
                    ],
                    "outbound": "direct"
                },
                {
                    "ip_is_private": True,
                    "outbound": "direct"
                },
                {
                    "inbound": "socks-in",
                    "outbound": proxy_config["tag"] # 默认通过主代理
                }
            ],
            "default_outbound": "direct"
        },
        "dns": {
            "servers": [
                {"address": "1.1.1.1", "strategy": "prefer_ipv4", "detour": "direct"},
                {"address": "8.8.8.8", "strategy": "prefer_ipv4", "detour": "direct"}
            ],
            "rules": [
                {
                    "domain_suffix": [
                        "download.windowsupdate.com",
                        "msedge.net",
                        "bing.com",
                        "office.com",
                        "live.com",
                        "microsoft.com",
                        "windowsupdate.com"
                    ],
                    "outbound": "direct"
                },
                {
                    "inbound": "socks-in",
                    "outbound": proxy_config["tag"]
                }
            ]
        }
    }
    return config

# --- 核心函数：获取远程节点 ---
def get_remote_nodes():
    all_proxies = []
    failed_proxy_ids = load_failed_proxies()
    
    for source in NODES_SOURCES:
        url = source["url"]
        source_type = source["type"]
        
        logging.info(f"正在从 {url} 获取节点...")
        try:
            response = requests.get(url, timeout=HTTP_TIMEOUT_SECONDS)
            response.raise_for_status()
            content = response.text
            
            if source_type == "plain":
                lines = content.splitlines()
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    
                    try:
                        # 使用改进后的 parse_proxy_url
                        proxy = parse_proxy_url(line)
                        if proxy: # Ensure proxy object is not None
                            proxy_id = generate_proxy_id(proxy)
                            if proxy_id not in failed_proxy_ids:
                                all_proxies.append(proxy)
                            else:
                                logging.debug(f"跳过已知失败代理: {proxy.get('tag', 'unknown')}")
                    except Exception as e:
                        logging.debug(f"无法解析代理 URL: {line} - {e}")
            elif source_type == "base64":
                try:
                    decoded_content = base64.b64decode(content).decode('utf-8')
                    lines = decoded_content.splitlines()
                    for line in lines:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        try:
                            proxy = parse_proxy_url(line)
                            if proxy: # Ensure proxy object is not None
                                proxy_id = generate_proxy_id(proxy)
                                if proxy_id not in failed_proxy_ids:
                                    all_proxies.append(proxy)
                                else:
                                    logging.debug(f"跳过已知失败代理: {proxy.get('tag', 'unknown')}")
                        except Exception as e:
                            logging.debug(f"无法解析 Base64 解码后的代理 URL: {line} - {e}")
                except Exception as e:
                    logging.warning(f"Base64 解码节点内容失败: {e}")
            
        except requests.exceptions.RequestException as e:
            logging.error(f"获取节点源 {url} 失败: {e}")
        except Exception as e:
            logging.error(f"处理节点源 {url} 失败: {e}")
            
    logging.info(f"获取到 {len(all_proxies)} 个待测试节点。")
    return all_proxies

# --- 异步函数：测试代理延迟 ---
async def test_latency(proxy_port, test_url):
    try:
        start_time = time.time()
        connector = aiohttp.TCPConnector(
            family=socket.AF_INET,  # Force IPv4 to avoid IPv6 issues if sing-box is not fully configured for it
            limit=0, # No limit on connections
            ttl_dns_cache=300
        )
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(test_url, proxy=f"http://127.0.0.1:{proxy_port}", timeout=HTTP_TIMEOUT_SECONDS) as response:
                if response.status == 200:
                    latency = (time.time() - start_time) * 1000  # 毫秒
                    return latency
                else:
                    logging.debug(f"URL {test_url} 返回状态码 {response.status}")
                    return float('inf')  # 返回无穷大表示失败
    except (aiohttp.ClientError, asyncio.TimeoutError, ConnectionRefusedError, socket.gaierror) as e:
        logging.debug(f"测试 URL {test_url} 延迟失败: {e}")
        return float('inf')
    except Exception as e:
        logging.debug(f"测试 URL {test_url} 延迟时发生未知错误: {e}")
        return float('inf')

# --- 异步函数：测试代理吞吐量 ---
async def test_throughput(proxy_port):
    try:
        start_time = time.time()
        downloaded_bytes = 0
        connector = aiohttp.TCPConnector(
            family=socket.AF_INET,
            limit=0,
            ttl_dns_cache=300
        )
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(SPEEDTEST_URL, proxy=f"http://127.0.0.1:{proxy_port}", timeout=HTTP_TIMEOUT_SECONDS) as response:
                response.raise_for_status()
                async for chunk in response.content.iter_chunked(8192):
                    downloaded_bytes += len(chunk)
                    if (time.time() - start_time) > HTTP_TIMEOUT_SECONDS:
                        raise asyncio.TimeoutError("Speed test timed out")
                
                duration = time.time() - start_time
                if duration > 0:
                    throughput_bps = downloaded_bytes / duration
                    return throughput_bps
                return 0
    except (aiohttp.ClientError, asyncio.TimeoutError, ConnectionRefusedError, socket.gaierror) as e:
        logging.debug(f"测试吞吐量失败: {e}")
        return 0
    except Exception as e:
        logging.debug(f"测试吞吐量时发生未知错误: {e}")
        return 0

# --- 核心测试逻辑 ---
async def test_proxy(proxy, proxy_port, semaphore):
    singbox_process = None
    try:
        async with semaphore:
            # 1. 生成并保存 sing-box 配置
            config = generate_singbox_config(proxy, proxy_port)
            if not config:
                return None # Return None if config generation fails

            with open(SINGBOX_CONFIG_PATH, 'w', encoding='utf-8') as f:
                json.dump(config, f, ensure_ascii=False, indent=2)

            # 2. 启动 sing-box
            singbox_process = subprocess.Popen(
                [SINGBOX_BIN_PATH, "run", "-c", SINGBOX_CONFIG_PATH],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1 # Line-buffered output
            )

            # 等待 sing-box 启动
            startup_successful = False
            start_time = time.time()
            singbox_output = [] # Collect all sing-box output
            while time.time() - start_time < SINGBOX_STARTUP_TIMEOUT:
                line = singbox_process.stderr.readline() # Read from stderr as sing-box logs to stderr by default
                if line:
                    singbox_output.append(line.strip())
                    if "sing-box started" in line:
                        startup_successful = True
                        logging.debug(f"sing-box 在端口 {proxy_port} 启动成功。")
                        break
                elif singbox_process.poll() is not None: # Process exited
                    # Capture remaining output if it exited early
                    remaining_stdout = singbox_process.stdout.read()
                    if remaining_stdout:
                        singbox_output.extend(remaining_stdout.splitlines())
                    remaining_stderr = singbox_process.stderr.read()
                    if remaining_stderr:
                        singbox_output.extend(remaining_stderr.splitlines())
                    logging.warning(f"sing-box 意外退出，可能配置有误。日志:\n{''.join(singbox_output)}")
                    break
                await asyncio.sleep(0.1) # Avoid busy-waiting

            if not startup_successful:
                logging.warning(f"sing-box 未能在 {SINGBOX_STARTUP_TIMEOUT} 秒内启动，跳过代理测试: {proxy.get('tag', 'unknown')}. sing-box output:\n{''.join(singbox_output)}")
                return None

            # 3. 测试延迟
            latency = float('inf')
            for test_url in TEST_URLS:
                current_latency = await test_latency(proxy_port, test_url)
                latency = min(latency, current_latency)
                if latency != float('inf'): # If any URL works, consider it reachable for latency
                    break

            if latency == float('inf'):
                logging.info(f"代理 {proxy.get('tag', 'unknown')} 延迟测试失败。")
                return None

            # 4. 测试吞吐量
            throughput_bps = await test_throughput(proxy_port)
            throughput_mbps = throughput_bps / (1024 * 1024)
            if throughput_bps < SPEEDTEST_MIN_THROUGHPUT:
                logging.info(f"代理 {proxy.get('tag', 'unknown')} 吞吐量不足 ({throughput_mbps:.2f} Mbps)。")
                return None
            
            logging.info(f"代理 {proxy.get('tag', 'unknown')} 测试成功: 延迟 {latency:.2f}ms, 吞吐量 {throughput_mbps:.2f} Mbps")
            return {"proxy": proxy, "latency": latency, "throughput": throughput_mbps}

    except Exception as e:
        logging.error(f"测试代理 {proxy.get('tag', 'unknown')} 时发生异常: {e}")
        return None
    finally:
        if singbox_process and singbox_process.poll() is None:
            logging.debug(f"停止 sing-box 进程 (端口 {proxy_port})...")
            singbox_process.terminate()
            try:
                singbox_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                singbox_process.kill()
                logging.warning(f"sing-box 进程强制关闭 (端口 {proxy_port}).")
        # 清理配置，可选，但对于频繁测试有用
        if os.path.exists(SINGBOX_CONFIG_PATH):
            os.remove(SINGBOX_CONFIG_PATH)

# --- 主执行逻辑 ---
async def main():
    logging.info("开始获取和测试代理。")
    all_proxies = get_remote_nodes()
    
    if not all_proxies:
        logging.info("没有获取到有效代理，退出。")
        return

    # 打乱代理列表以分散负载和避免对某些源的过度请求
    random.shuffle(all_proxies)

    results = []
    failed_proxies = load_failed_proxies()
    
    # 使用 Semaphore 控制并发量
    semaphore = asyncio.Semaphore(CONCURRENT_TESTS)

    tasks = []
    current_proxy_port = BASE_PROXY_PORT
    for proxy in all_proxies:
        if len(results) >= MAX_PROXIES:
            logging.info(f"已达到最大代理数量 {MAX_PROXIES}，停止测试。")
            break

        # test_proxy 现在返回 None 如果失败，所以需要在其内部处理 failed_proxies 的添加
        # 因此，这里不再提前跳过，而是让 test_proxy 决定是否跳过，或者在返回 None 时处理
        tasks.append(test_proxy(proxy, current_proxy_port, semaphore))
        current_proxy_port += 1
        # 重置端口如果超过某个范围，或者简单地让它增加
        if current_proxy_port > BASE_PROXY_PORT + 5000: # 避免端口耗尽，可以根据需要调整
            current_proxy_port = BASE_PROXY_PORT
    
    # 等待所有测试完成
    processed_proxies_ids = set() # To track which proxies were processed to update failed list
    for future in asyncio.as_completed(tasks):
        try:
            result = await future
            if result:
                results.append(result)
                processed_proxies_ids.add(generate_proxy_id(result["proxy"]))
        except Exception as e:
            logging.error(f"任务完成时发生未捕获的异常: {e}")

    # 根据测试结果更新失败节点列表
    # 这里的逻辑需要更正，因为 future 本身不会携带原始 proxy 对象
    # 我们可以通过 `all_proxies` 和 `succeeded_proxy_ids` 的比较来更新 `failed_proxies`
    succeeded_proxy_ids = {generate_proxy_id(r["proxy"]) for r in results}
    for proxy in all_proxies:
        proxy_id = generate_proxy_id(proxy)
        if proxy_id not in succeeded_proxy_ids:
            # Only add to failed if it was actually attempted to be tested
            # (i.e., it was put into `tasks` list)
            # A more robust solution would involve `test_proxy` returning the original proxy on failure
            failed_proxies.add(proxy_id)
            
    # 保存失败节点
    if failed_proxies:
        save_failed_proxies(failed_proxies)
        logging.info(f"已保存 {len(failed_proxies)} 个失败节点到 {FAILED_PROXIES_FILE}")

    # 排序结果
    results.sort(key=lambda x: (x["latency"], -x["throughput"]))

    # 加载历史可用节点
    existing_proxies = load_existing_proxies()

    # 保存新可用节点（去重并追加）
    new_proxy_urls_to_write = []
    for result in results:
        proxy_url = singbox_to_proxy_url(result["proxy"])
        if proxy_url:
            formatted_url = f"{proxy_url}#{result['latency']:.2f}ms,throughput={result['throughput'] / (1024 * 1024):.2f}MB/s" # Ensure MB/s is used here
            if formatted_url not in existing_proxies:
                new_proxy_urls_to_write.append(formatted_url)
                existing_proxies.add(formatted_url)
    
    if new_proxy_urls_to_write:
        with open(OUTPUT_SUB_FILE, 'a', encoding='utf-8') as f:
            for url in new_proxy_urls_to_write:
                f.write(f"{url}\n")
        logging.info(f"已添加 {len(new_proxy_urls_to_write)} 个新可用节点到 {OUTPUT_SUB_FILE}")
    else:
        logging.info("没有发现新的可用节点。")

    logging.info("代理测试和收集完成。")

if __name__ == "__main__":
    asyncio.run(main())
