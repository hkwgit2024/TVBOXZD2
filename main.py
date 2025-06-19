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
TEST_URLS = ["https://t.me", "https://www.tiktok.com", "https://www.google.com/generate_204"]
TEST_TIMEOUT = 10  # 测试超时时间（秒）
DOWNLOAD_TEST_SIZE = 1 * 1024 * 1024  # 下载测试文件大小，1MB
MIN_THROUGHPUT = 0.5 * 1024 * 1024 # 最小吞吐量，0.5MB/s


# --- 辅助函数 ---
def load_failed_proxies():
    """加载之前保存的失败代理ID"""
    if os.path.exists(FAILED_PROXIES_FILE):
        with open(FAILED_PROXIES_FILE, 'r') as f:
            return set(json.load(f))
    return set()

def save_failed_proxies(failed_proxies):
    """保存失败代理ID，限制最大数量"""
    with open(FAILED_PROXIES_FILE, 'w') as f:
        # 只保留最新的 MAX_FAILED_PROXIES 条记录
        json.dump(list(failed_proxies)[-MAX_FAILED_PROXIES:], f)

def generate_proxy_id(proxy):
    """生成代理的唯一ID"""
    # 使用代理的完整信息进行哈希，确保唯一性
    return md5(json.dumps(proxy, sort_keys=True).encode('utf-8')).hexdigest()

def singbox_to_proxy_url(proxy_data):
    """将sing-box代理数据转换为URL格式"""
    proxy_type = proxy_data.get("type")
    if proxy_type == "hysteria2":
        server = proxy_data["server"]
        port = proxy_data["server_port"]
        password = proxy_data["password"]
        obfs = proxy_data.get("obfs")
        obfs_password = proxy_data.get("obfs_password")
        
        url = f"hysteria2://{urllib.parse.quote_plus(password)}@{server}:{port}"
        params = []
        if obfs == "tls":
            params.append("obfs=tls")
            if obfs_password:
                params.append(f"obfs-password={urllib.parse.quote_plus(obfs_password)}")
        if params:
            url += "?" + "&".join(params)
        
        # 添加别名
        # 尝试从 tag 或 server 获取别名，或使用默认
        alias = proxy_data.get("tag") or server
        url += f"#{urllib.parse.quote_plus(alias)}"
        return url
    elif proxy_type == "tuic":
        server = proxy_data["server"]
        port = proxy_data["server_port"]
        uuid = proxy_data["uuid"]
        password = proxy_data["password"]
        congestion_controller = proxy_data.get("congestion_controller", "bbr")
        zero_rtt_handshake = str(proxy_data.get("zero_rtt_handshake", "true")).lower()
        
        # TUIC URL 格式通常不包含所有参数在 URL 中，可能需要特别处理
        # 这是一个简化的示例，可能需要根据实际客户端支持的TUIC URL格式进行调整
        url = f"tuic://{urllib.parse.quote_plus(uuid)}:{urllib.parse.quote_plus(password)}@{server}:{port}?" \
              f"congestion_controller={congestion_controller}&" \
              f"zero_rtt_handshake={zero_rtt_handshake}"
        
        # 添加别名
        alias = proxy_data.get("tag") or server
        url += f"#{urllib.parse.quote_plus(alias)}"
        return url
    elif proxy_type == "vless":
        server = proxy_data["server"]
        port = proxy_data["server_port"]
        uuid = proxy_data["uuid"]
        flow = proxy_data.get("flow", "")
        # VLESS XTLS flow support
        if flow:
            flow_param = f"&flow={flow}"
        else:
            flow_param = ""

        # TLS settings
        tls_settings = proxy_data.get("tls", {})
        tls_query_params = []
        if tls_settings.get("enabled"):
            tls_query_params.append("security=tls")
            sni = tls_settings.get("server_name")
            if sni:
                tls_query_params.append(f"sni={sni}")
            alpn = tls_settings.get("alpn")
            if alpn and isinstance(alpn, list):
                tls_query_params.append(f"alpn={','.join(alpn)}")
            fingerprint = tls_settings.get("reality_fingerprint")
            if fingerprint:
                tls_query_params.append(f"fp={fingerprint}")
            pbk = tls_settings.get("reality_public_key")
            if pbk:
                tls_query_params.append(f"pbk={pbk}")
            sid = tls_settings.get("reality_short_id")
            if sid:
                tls_query_params.append(f"sid={sid}")

            # Xver for VLESS Reality
            if "xver" in tls_settings:
                tls_query_params.append(f"xver={tls_settings['xver']}")

        # Transport settings (ws, grpc, etc.)
        transport_settings = proxy_data.get("transport", {})
        transport_type = transport_settings.get("type")
        transport_query_params = []
        if transport_type == "ws":
            transport_query_params.append("type=ws")
            path = transport_settings.get("path", "/")
            transport_query_params.append(f"path={urllib.parse.quote_plus(path)}")
            headers = transport_settings.get("headers", {})
            if "Host" in headers:
                transport_query_params.append(f"host={urllib.parse.quote_plus(headers['Host'])}")
        elif transport_type == "grpc":
            transport_query_params.append("type=grpc")
            service_name = transport_settings.get("service_name")
            if service_name:
                transport_query_params.append(f"serviceName={urllib.parse.quote_plus(service_name)}")
            # 这里可以添加更多 gRPC 参数，例如 `blocking`

        all_params = tls_query_params + transport_query_params
        query_string = f"?{'&'.join(all_params)}{flow_param}" if all_params or flow_param else ""

        # 添加别名
        alias = proxy_data.get("tag") or server
        return f"vless://{uuid}@{server}:{port}{query_string}#{urllib.parse.quote_plus(alias)}"
    elif proxy_type == "vmess":
        # VMess 编码与 VLESS 不同，需要转换为 base64
        server = proxy_data["server"]
        port = proxy_data["server_port"]
        uuid = proxy_data["uuid"]
        alter_id = proxy_data.get("alter_id", 0)
        cipher = proxy_data.get("security", "auto")

        # TLS settings
        tls_settings = proxy_data.get("tls", {})
        tls_enabled = tls_settings.get("enabled", False)
        sni = tls_settings.get("server_name", "")
        fingerprint = tls_settings.get("reality_fingerprint", "") # For Reality in VMess
        pbk = tls_settings.get("reality_public_key", "")
        sid = tls_settings.get("reality_short_id", "")
        
        # Transport settings
        transport_settings = proxy_data.get("transport", {})
        transport_type = transport_settings.get("type", "tcp")
        path = transport_settings.get("path", "")
        host = transport_settings.get("headers", {}).get("Host", "")
        service_name = transport_settings.get("service_name", "") # For gRPC

        vmess_json = {
            "v": "2",
            "ps": proxy_data.get("tag") or server, # 别名
            "add": server,
            "port": port,
            "id": uuid,
            "aid": alter_id,
            "net": transport_type,
            "type": "none", # 早期版本兼容，或根据实际协议
            "host": host,
            "path": path,
            "tls": "tls" if tls_enabled else "",
            "sni": sni, # 虽然不是标准字段，但一些客户端会解析
            "fp": fingerprint, # Reality
            "pbk": pbk, # Reality
            "sid": sid # Reality
        }
        
        # gRPC special handling for VMess
        if transport_type == "grpc":
            vmess_json["type"] = "grpc" # 设置type为grpc
            vmess_json["serviceName"] = service_name

        # 对于 ws 协议，"type" 字段在一些客户端中会设置为 "ws"
        if transport_type == "ws":
            vmess_json["type"] = "ws"


        # Base64 编码
        vmess_encoded = base64.b64encode(json.dumps(vmess_json).encode('utf-8')).decode('utf-8')
        return f"vmess://{vmess_encoded}"

    logging.warning(f"不支持的代理类型: {proxy_type}")
    return None

def extract_proxies_from_url(url_list, existing_proxies_ids, max_proxies_to_fetch, failed_proxies_ids):
    """从URL列表获取代理信息，跳过已存在或失败的代理"""
    proxies = []
    fetched_count = 0
    for url_info in url_list:
        if fetched_count >= max_proxies_to_fetch:
            break

        url = url_info["url"]
        proxy_type = url_info.get("type", "plain")
        logging.info(f"开始从 {url} 获取代理，类型：{proxy_type}")
        
        try:
            response = requests.get(url, timeout=15)
            response.raise_for_status()
            content = response.text

            if proxy_type == "plain":
                # 每行一个代理URL
                lines = content.splitlines()
                random.shuffle(lines) # 打乱顺序
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        # 尝试转换为sing-box格式
                        singbox_proxy = proxy_url_to_singbox(line)
                        if singbox_proxy:
                            proxy_id = generate_proxy_id(singbox_proxy)
                            if proxy_id not in existing_proxies_ids and proxy_id not in failed_proxies_ids:
                                proxies.append(singbox_proxy)
                                fetched_count += 1
                                if fetched_count >= max_proxies_to_fetch:
                                    break
                            else:
                                logging.debug(f"跳过已存在或失败的代理: {singbox_proxy.get('tag', 'unknown')}")
                        else:
                            logging.warning(f"无法解析的代理URL: {line[:50]}...")
                    except Exception as e:
                        logging.warning(f"处理代理URL失败 {line[:50]}...: {e}")
            elif proxy_type == "base64":
                decoded_content = base64.b64decode(content).decode('utf-8')
                lines = decoded_content.splitlines()
                random.shuffle(lines) # 打乱顺序
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        singbox_proxy = proxy_url_to_singbox(line)
                        if singbox_proxy:
                            proxy_id = generate_proxy_id(singbox_proxy)
                            if proxy_id not in existing_proxies_ids and proxy_id not in failed_proxies_ids:
                                proxies.append(singbox_proxy)
                                fetched_count += 1
                                if fetched_count >= max_proxies_to_fetch:
                                    break
                            else:
                                logging.debug(f"跳过已存在或失败的代理: {singbox_proxy.get('tag', 'unknown')}")
                        else:
                            logging.warning(f"无法解析的代理URL: {line[:50]}...")
                    except Exception as e:
                        logging.warning(f"处理代理URL失败 {line[:50]}...: {e}")
            else:
                logging.warning(f"不支持的代理源类型: {proxy_type}")

        except requests.exceptions.RequestException as e:
            logging.error(f"从 {url} 获取代理失败: {e}")
    logging.info(f"从所有源共获取到 {len(proxies)} 个新代理")
    return proxies


def proxy_url_to_singbox(proxy_url):
    """将代理URL转换为sing-box配置格式"""
    if proxy_url.startswith("hysteria2://"):
        try:
            # hysteria2://password@server:port?obfs=obfs_type&obfs-password=obfs_password#tag
            parsed = urllib.parse.urlparse(proxy_url)
            password = urllib.parse.unquote_plus(parsed.username or parsed.password or "") # 兼容旧格式
            
            server_parts = parsed.netloc.split('@')
            if len(server_parts) > 1:
                server_info = server_parts[1]
            else:
                server_info = server_parts[0] # 没有@，直接是server:port

            server, port = server_info.split(':')
            port = int(port)

            query_params = urllib.parse.parse_qs(parsed.query)
            obfs = query_params.get("obfs", [None])[0]
            obfs_password = query_params.get("obfs-password", [None])[0]
            
            tag = urllib.parse.unquote_plus(parsed.fragment) if parsed.fragment else f"hysteria2-{server}"

            singbox_config = {
                "tag": tag,
                "type": "hysteria2",
                "server": server,
                "server_port": port,
                "password": password,
                "tls": {
                    "enabled": True,
                    "insecure": True, # 默认设为true，实际使用中可能需要更严格的校验
                    "server_name": server # 默认SNI与服务器地址相同
                }
            }
            if obfs == "tls":
                singbox_config["obfs"] = "tls"
                if obfs_password:
                    singbox_config["obfs_password"] = obfs_password
            
            return singbox_config
        except Exception as e:
            logging.error(f"解析Hysteria2 URL失败 {proxy_url}: {e}")
            return None
    elif proxy_url.startswith("tuic://"):
        try:
            # tuic://uuid:password@server:port?参数#tag
            parsed = urllib.parse.urlparse(proxy_url)
            
            user_info = parsed.netloc.split('@')[0]
            uuid, password = user_info.split(':')
            
            server_info = parsed.netloc.split('@')[1]
            server, port = server_info.split(':')
            port = int(port)

            query_params = urllib.parse.parse_qs(parsed.query)
            congestion_controller = query_params.get("congestion_controller", ["bbr"])[0]
            zero_rtt_handshake = query_params.get("zero_rtt_handshake", ["true"])[0].lower() == "true"
            
            tag = urllib.parse.unquote_plus(parsed.fragment) if parsed.fragment else f"tuic-{server}"

            singbox_config = {
                "tag": tag,
                "type": "tuic",
                "server": server,
                "server_port": port,
                "uuid": uuid,
                "password": password,
                "congestion_controller": congestion_controller,
                "zero_rtt_handshake": zero_rtt_handshake,
                "tls": {
                    "enabled": True,
                    "insecure": True,
                    "server_name": server
                }
            }
            return singbox_config
        except Exception as e:
            logging.error(f"解析TUIC URL失败 {proxy_url}: {e}")
            return None
    elif proxy_url.startswith("vless://"):
        try:
            # vless://uuid@server:port?params#tag
            parsed = urllib.parse.urlparse(proxy_url)
            user_info, server_port = parsed.netloc.split('@')
            uuid = user_info
            server, port = server_port.split(':')
            port = int(port)
            
            tag = urllib.parse.unquote_plus(parsed.fragment) if parsed.fragment else f"vless-{server}"

            query_params = urllib.parse.parse_qs(parsed.query)

            singbox_config = {
                "tag": tag,
                "type": "vless",
                "server": server,
                "server_port": port,
                "uuid": uuid,
                "tls": {"enabled": False, "insecure": True},
                "transport": {"type": "tcp"}
            }

            # TLS settings
            if query_params.get("security", [""])[0] == "tls":
                singbox_config["tls"]["enabled"] = True
                if "sni" in query_params:
                    singbox_config["tls"]["server_name"] = query_params["sni"][0]
                elif "host" in query_params: # Some clients might use host for SNI
                    singbox_config["tls"]["server_name"] = query_params["host"][0]
                if "alpn" in query_params:
                    singbox_config["tls"]["alpn"] = query_params["alpn"][0].split(',')
                if "fp" in query_params: # Reality fingerprint
                    singbox_config["tls"]["reality_fingerprint"] = query_params["fp"][0]
                if "pbk" in query_params: # Reality public key
                    singbox_config["tls"]["reality_public_key"] = query_params["pbk"][0]
                if "sid" in query_params: # Reality short ID
                    singbox_config["tls"]["reality_short_id"] = query_params["sid"][0]
                if "xver" in query_params: # VLESS Xver
                    singbox_config["tls"]["xver"] = int(query_params["xver"][0])

            # Flow
            if "flow" in query_params:
                singbox_config["flow"] = query_params["flow"][0]

            # Transport settings
            transport_type = query_params.get("type", ["tcp"])[0]
            singbox_config["transport"]["type"] = transport_type
            if transport_type == "ws":
                singbox_config["transport"]["path"] = query_params.get("path", ["/"])[0]
                host_header = query_params.get("host", [""])[0]
                if host_header:
                    singbox_config["transport"]["headers"] = {"Host": host_header}
            elif transport_type == "grpc":
                singbox_config["transport"]["service_name"] = query_params.get("serviceName", [""])[0]
                # 更多 gRPC 参数可以根据需要添加

            return singbox_config
        except Exception as e:
            logging.error(f"解析VLESS URL失败 {proxy_url}: {e}")
            return None
    elif proxy_url.startswith("vmess://"):
        try:
            # VMess URL 是 base64 编码的 JSON
            encoded_str = proxy_url[len("vmess://"):]
            decoded_json_str = base64.b64decode(encoded_str).decode('utf-8')
            vmess_data = json.loads(decoded_json_str)

            tag = vmess_data.get("ps", f"vmess-{vmess_data['add']}")
            server = vmess_data["add"]
            port = int(vmess_data["port"])
            uuid = vmess_data["id"]
            alter_id = int(vmess_data.get("aid", 0))
            security = vmess_data.get("scy", vmess_data.get("s", "auto")) # scy for sing-box, s for v2rayN

            singbox_config = {
                "tag": tag,
                "type": "vmess",
                "server": server,
                "server_port": port,
                "uuid": uuid,
                "alter_id": alter_id,
                "security": security,
                "tls": {"enabled": False, "insecure": True},
                "transport": {"type": "tcp"}
            }

            # TLS
            if vmess_data.get("tls") == "tls":
                singbox_config["tls"]["enabled"] = True
                if "sni" in vmess_data:
                    singbox_config["tls"]["server_name"] = vmess_data["sni"]
                elif "host" in vmess_data: # Fallback for SNI from host in some clients
                    singbox_config["tls"]["server_name"] = vmess_data["host"]
                # Reality in VMess (non-standard but some clients support)
                if "fp" in vmess_data:
                    singbox_config["tls"]["reality_fingerprint"] = vmess_data["fp"]
                if "pbk" in vmess_data:
                    singbox_config["tls"]["reality_public_key"] = vmess_data["pbk"]
                if "sid" in vmess_data:
                    singbox_config["tls"]["reality_short_id"] = vmess_data["sid"]

            # Transport
            transport_type = vmess_data.get("net", "tcp")
            singbox_config["transport"]["type"] = transport_type
            if transport_type == "ws":
                singbox_config["transport"]["path"] = vmess_data.get("path", "/")
                host_header = vmess_data.get("host", "")
                if host_header:
                    singbox_config["transport"]["headers"] = {"Host": host_header}
            elif transport_type == "grpc":
                singbox_config["transport"]["service_name"] = vmess_data.get("serviceName", "")
                # 更多 gRPC 参数可以根据需要添加

            return singbox_config
        except Exception as e:
            logging.error(f"解析VMess URL失败 {proxy_url}: {e}")
            return None
    return None

def write_singbox_config(proxy, listen_port, dns_servers=None):
    """生成并写入sing-box配置文件"""
    # 构建 sing-box 配置
    singbox_config = {
        "log": {
            "disabled": False,
            "output": SINGBOX_LOG_PATH,
            "level": "info",
        },
        "dns": {
            "servers": [],
            "rules": [],
            "disable_cache": True,
            "disable_expire": True,
        },
        "inbounds": [
            {
                "type": "socks",
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "listen_port": listen_port,
                "sniff": True,
                "udp_timeout": 300,
            }
        ],
        "outbounds": [
            proxy,  # 动态传入的代理配置
            {
                "type": "direct",
                "tag": "direct",
            },
            {
                "type": "block",
                "tag": "block",
            },
        ],
        "route": {
            "rules": [
                {"protocol": "dns", "outbound": "dns-out"},
                {"ip_is_private": True, "outbound": "direct"},
                {"domain_suffix": ["t.me", "tiktok.com"], "outbound": proxy["tag"]}, # 特定域名走代理
                {"outbound": proxy["tag"]},  # 所有流量通过代理
            ],
            "final": "direct", # 默认直连
        },
    }

    # 根据传入的 DNS 服务器设置
    if dns_servers:
        for i, dns_ip in enumerate(dns_servers):
            singbox_config["dns"]["servers"].append({"address": dns_ip, "strategy": "prefer_ipv4", "tag": f"dns-server-{i}"})
        # 将 DNS 出站规则添加到路由中
        singbox_config["outbounds"].append({
            "type": "dns",
            "tag": "dns-out"
        })
        # 确保 DNS 流量走直连或指定的 DNS
        singbox_config["route"]["rules"].insert(0, {"rule_set": "geosite-category-ads-lh", "outbound": "block"})
        singbox_config["route"]["rules"].insert(0, {"domain_suffix": ["t.me", "tiktok.com"], "outbound": proxy["tag"]}) # 确保这些也走代理的DNS
        singbox_config["route"]["rules"].insert(0, {"outbound": "dns-out", "port": 53, "network": "udp"}) # 确保 DNS 请求走 dns-out
        
    else: # 如果没有指定，sing-box会使用系统DNS
        # 确保 DNS 流量走直连
        singbox_config["outbounds"].append({
            "type": "dns",
            "tag": "dns-out"
        })
        singbox_config["route"]["rules"].insert(0, {"rule_set": "geosite-category-ads-lh", "outbound": "block"})
        singbox_config["route"]["rules"].insert(0, {"domain_suffix": ["t.me", "tiktok.com"], "outbound": proxy["tag"]})
        singbox_config["route"]["rules"].insert(0, {"outbound": "dns-out", "port": 53, "network": "udp"})


    with open(SINGBOX_CONFIG_PATH, 'w') as f:
        json.dump(singbox_config, f, indent=2)

def get_free_port():
    """获取一个空闲端口"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def run_singbox(listen_port):
    """启动sing-box进程"""
    # 确保日志文件和目录存在
    os.makedirs(os.path.dirname(SINGBOX_LOG_PATH), exist_ok=True)

    command = [
        SINGBOX_BIN_PATH,
        "-C", SINGBOX_CONFIG_PATH,
        "run"
    ]
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding='utf-8'
    )
    # 等待 sing-box 启动
    time.sleep(1) # 简单等待，可以根据日志判断是否启动成功
    return process

async def test_proxy_connectivity(proxy, dns_servers=None):
    """
    测试代理的连接和吞吐量。
    返回 (延迟, 吞吐量) 或 (None, None)
    """
    listen_port = get_free_port()
    write_singbox_config(proxy, listen_port, dns_servers)
    singbox_process = run_singbox(listen_port)
    
    # 检查sing-box是否成功启动
    time.sleep(1) # 稍微延长等待时间
    if singbox_process.poll() is not None:
        stderr_output = singbox_process.stderr.read()
        logging.error(f"Sing-box 启动失败，代理: {proxy.get('tag', 'unknown')}, 错误: {stderr_output}")
        return None, None

    proxy_url = f"socks5://127.0.0.1:{listen_port}"

    latency = float('inf')
    throughput = 0

    try:
        # 测试延迟
        start_time = time.time()
        async with aiohttp.ClientSession(trust_env=True) as session:
            try:
                # 使用代理访问一个公共的、轻量级的网站，例如 Google 的 204 页面
                async with session.get("https://www.google.com/generate_204", 
                                       proxy=proxy_url, 
                                       timeout=TEST_TIMEOUT) as response:
                    response.raise_for_status()
                    latency = (time.time() - start_time) * 1000 # 毫秒
                    logging.info(f"代理 {proxy.get('tag', 'unknown')} 延迟: {latency:.2f}ms")
            except Exception as e:
                logging.warning(f"代理 {proxy.get('tag', 'unknown')} 延迟测试失败: {e}")
                return None, None # 延迟测试失败直接返回

        # 测试吞吐量
        try:
            download_url = "https://cachefly.cachefly.net/100mb.test" # 使用一个大文件进行下载测试
            start_time = time.time()
            async with aiohttp.ClientSession(trust_env=True) as session:
                async with session.get(download_url, proxy=proxy_url, timeout=TEST_TIMEOUT) as response:
                    response.raise_for_status()
                    total_downloaded = 0
                    async for chunk in response.content.iter_chunked(8192):
                        total_downloaded += len(chunk)
                        if total_downloaded >= DOWNLOAD_TEST_SIZE: # 下载达到指定大小即停止
                            break
            
            end_time = time.time()
            duration = end_time - start_time
            if duration > 0:
                throughput = (total_downloaded / duration) / (1024 * 1024) # MB/s
                logging.info(f"代理 {proxy.get('tag', 'unknown')} 吞吐量: {throughput:.2f}MB/s")
            else:
                logging.warning(f"代理 {proxy.get('tag', 'unknown')} 吞吐量测试时间过短或下载量为0。")
                throughput = 0

            # 检查吞吐量是否达到最低要求
            if throughput < MIN_THROUGHPUT:
                logging.warning(f"代理 {proxy.get('tag', 'unknown')} 吞吐量 {throughput:.2f}MB/s 低于最低要求 {MIN_THROUGHPUT:.2f}MB/s。")
                return None, None # 吞吐量不达标也返回 None, None

        except asyncio.TimeoutError:
            logging.warning(f"代理 {proxy.get('tag', 'unknown')} 吞吐量测试超时。")
            return None, None
        except Exception as e:
            logging.warning(f"代理 {proxy.get('tag', 'unknown')} 吞吐量测试失败: {e}")
            return None, None

    except asyncio.TimeoutError:
        logging.warning(f"代理 {proxy.get('tag', 'unknown')} 连接超时。")
        return None, None
    except Exception as e:
        logging.warning(f"代理 {proxy.get('tag', 'unknown')} 连接或测试失败: {e}")
        return None, None
    finally:
        if singbox_process:
            singbox_process.terminate()
            singbox_process.wait(timeout=5)
            if singbox_process.poll() is None:
                singbox_process.kill()
        # 清理配置文件，但通常这不是必须的，因为每次都会覆盖
        # if os.path.exists(SINGBOX_CONFIG_PATH):
        #     os.remove(SINGBOX_CONFIG_PATH)

    return latency, throughput

def load_existing_proxies():
    """加载已有的可用节点"""
    if os.path.exists(OUTPUT_SUB_FILE):
        with open(OUTPUT_SUB_FILE, 'r') as f:
            return set(f.read().splitlines())
    return set()

def run_tests_and_save_results(proxies):
    """
    运行代理测试并保存结果。
    """
    results = []
    failed_proxies = load_failed_proxies()
    
    # 定义中国联通的 DNS
    union_dns_servers = ["202.106.0.20", "202.106.196.115"]

    with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count() * 2) as executor:
        future_to_proxy = {executor.submit(asyncio.run, test_proxy_connectivity(proxy, dns_servers=union_dns_servers)): proxy for proxy in proxies}
        for future in concurrent.futures.as_completed(future_to_proxy):
            proxy = future_to_proxy[future]
            try:
                latency, throughput = future.result()
                if latency is not None and throughput is not None:
                    results.append({"proxy": proxy, "latency": latency, "throughput": throughput})
                    proxy_id = generate_proxy_id(proxy)
                    if proxy_id in failed_proxies:
                        failed_proxies.remove(proxy_id) # 成功则从失败列表中移除
                else:
                    failed_proxies.add(generate_proxy_id(proxy))
            except Exception as exc:
                logging.error(f"代理 {proxy.get('tag', 'unknown')} 生成异常: {exc}")
                failed_proxies.add(generate_proxy_id(proxy))

    # 保存失败节点
    if failed_proxies:
        save_failed_proxies(failed_proxies)
        logging.info(f"已保存 {len(failed_proxies)} 个失败节点到 {FAILED_PROXIES_FILE}")

    # 排序结果
    results.sort(key=lambda x: (x["latency"], -x["throughput"]))

    # 加载历史可用节点
    existing_proxies = load_existing_proxies()

    # 保存新可用节点（去重并追加）
    new_proxy_urls = []
    for result in results:
        proxy_url = singbox_to_proxy_url(result["proxy"])
        if proxy_url:
            formatted_url = f"{proxy_url}#{result['latency']:.2f}ms,throughput={result['throughput']:.2f}MB/s"
            if formatted_url not in existing_proxies:
                new_proxy_urls.append(formatted_url)
                existing_proxies.add(formatted_url)

    if new_proxy_urls:
        content = "\n".join(new_proxy_urls)
        content_b64 = base64.b64encode(content.encode('utf-8')).decode('utf-8')

        with open(OUTPUT_SUB_FILE, 'a') as f: # 使用追加模式
            for url in new_proxy_urls:
                f.write(url + "\n")
        logging.info(f"已将 {len(new_proxy_urls)} 个新可用节点追加到 {OUTPUT_SUB_FILE}")
    else:
        logging.info("没有新的可用节点需要保存。")


async def main():
    """主函数"""
    logging.info("开始更新代理...")
    
    existing_proxies_ids = {generate_proxy_id(proxy_url_to_singbox(url.split('#')[0])) 
                            for url in load_existing_proxies() if proxy_url_to_singbox(url.split('#')[0])}
    failed_proxies_ids = load_failed_proxies()

    # 计算需要获取的新代理数量
    current_proxies_count = len(existing_proxies_ids)
    proxies_to_fetch = MAX_PROXIES - current_proxies_count
    if proxies_to_fetch <= 0:
        logging.info(f"已达到最大代理数量 {MAX_PROXIES}，无需获取新代理。")
        return

    proxies_to_test = extract_proxies_from_url(NODES_SOURCES, existing_proxies_ids, proxies_to_fetch, failed_proxies_ids)

    if proxies_to_test:
        logging.info(f"将测试 {len(proxies_to_test)} 个新代理...")
        run_tests_and_save_results(proxies_to_test)
    else:
        logging.info("没有新代理需要测试。")

    logging.info("代理更新完成。")

if __name__ == "__main__":
    asyncio.run(main())
