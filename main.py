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
import random
from hashlib import md5
import aiohttp
import asyncio


# --- 配置日志 ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- 常量定义 ---
SINGBOX_BIN_PATH = "./clash_bin/sing-box"
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
TEST_URLS = ["https://www.google.com", "https://t.me", "https://www.tiktok.com"] # 优先测试Google，因为通常更稳定
TEST_TIMEOUT = 10 # 代理测试超时时间（秒）
MAX_WORKERS = 50 # 并发测试的代理数量，对于异步I/O可以设置得更高，但也要考虑系统资源


# --- 辅助函数 ---

def find_available_port():
    """找到一个可用的本地端口"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def cleanup_singbox(port):
    """根据端口号终止对应的sing-box进程"""
    try:
        # 使用 pgrep 查找进程，更精确
        # 注意：这里假设sing-box的进程命令行会包含其配置文件路径，且配置文件名包含端口
        # 例如：sing-box -C data/sing-box-config-12345.json
        pids_output = subprocess.check_output(f"pgrep -f 'sing-box -C .*-config-{port}\\.json'", shell=True).decode().strip()
        if pids_output:
            pids = pids_output.split('\n')
            for pid in pids:
                logging.info(f"正在终止 sing-box 进程 (PID: {pid}) 监听端口 {port}...")
                subprocess.run(f"kill -9 {pid}", shell=True, check=True)
        # else:
        #    logging.debug(f"端口 {port} 上没有找到 sing-box 进程在监听。")
    except subprocess.CalledProcessError:
        # pgrep 没有找到匹配的进程，这是正常情况
        # logging.debug(f"端口 {port} 上没有找到 sing-box 进程在监听。")
        pass
    except Exception as e:
        logging.error(f"清理 sing-box 进程时发生错误: {e}")

def parse_proxy_url(proxy_url):
    """
    解析 VLESS, Trojan, VMess, SS, Hysteria2 等协议的 URL
    提取所需信息
    """
    # 尝试解析 URL
    parsed = urllib.parse.urlparse(proxy_url)
    scheme = parsed.scheme.lower()
    
    # 提取用户信息和主机信息
    userinfo = parsed.username
    if userinfo: # For VLESS/VMess/SS/Trojan password
        try:
            # 用户信息部分通常是 Base64 编码的 JSON 或纯文本
            decoded_userinfo = base64.b64decode(userinfo + '=' * (-len(userinfo) % 4)).decode('utf-8')
            # 尝试解析为 JSON (VMess)
            user_data = json.loads(decoded_userinfo)
            uuid = user_data.get('id')
            alter_id = user_data.get('aid', 0)
            security_param = user_data.get('scy') # 'scy' for security in VMess
            method = user_data.get('method') # For SS
            password = user_data.get('password') # For Trojan/SS
        except (json.JSONDecodeError, UnicodeDecodeError):
            # 如果不是 JSON，就作为纯文本处理 (VLESS, Trojan, SS)
            uuid = userinfo # For VLESS
            password = userinfo # For Trojan, SS
            alter_id = 0
            security_param = None
            method = None
    else:
        uuid = None
        password = None
        alter_id = 0
        security_param = None
        method = None

    address = parsed.hostname
    port = parsed.port
    # 解码 fragment 作为 tag
    tag = urllib.parse.unquote(parsed.fragment) if parsed.fragment else f"{scheme}-{address}:{port}"

    # 解析查询参数
    query_params = urllib.parse.parse_qs(parsed.query)

    proxy_info = {
        "tag": tag,
        "scheme": scheme,
        "address": address,
        "port": port,
        "uuid": uuid,
        "password": password,
        "alter_id": alter_id,
        "security": security_param, # Use security_param from userinfo for vmess
        "method": method, # SS method

        # TLS/Reality/uTLS 参数 (从query_params获取)
        "sni": query_params.get('sni', [None])[0],
        "alpn": query_params.get('alpn', [None])[0],
        "fp": query_params.get('fp', [None])[0], # uTLS fingerprint
        "publicKey": query_params.get('pbk', [None])[0], # Reality public key
        "shortId": query_params.get('sid', [None])[0], # Reality short ID
        "spiderX": query_params.get('spx', [None])[0], # Reality spider X
        "flow": query_params.get('flow', [None])[0], # VLESS flow (e.g., "xtls-rprx-vision")

        # 传输协议参数 (VMess, VLESS)
        "type": query_params.get('type', [None])[0], # transport type (e.g., ws, grpc, h2)
        "path": query_params.get('path', ['/'])[0], # ws/grpc path
        "host": query_params.get('host', [None])[0], # ws/h2 host header
        "serviceName": query_params.get('serviceName', [None])[0], # grpc serviceName
        "mode": query_params.get('mode', [None])[0], # grpc mode
        "encryption": query_params.get('encryption', [None])[0], # Hysteria2 encryption
        "obfs": query_params.get('obfs', [None])[0], # Hysteria2 obfs
        "obfs_password": query_params.get('obfsParam', [None])[0], # Hysteria2 obfs password
        "up_mbps": query_params.get('up_mbps', [None])[0], # Hysteria2 up_mbps
        "down_mbps": query_params.get('down_mbps', [None])[0], # Hysteria2 down_mbps
    }
    
    # Clean up empty values (None values)
    proxy_info = {k: v for k, v in proxy_info.items() if v is not None}
    
    return proxy_info


def create_singbox_config(proxy, local_port):
    """根据代理信息生成 sing-box 配置"""
    
    outbound = {
        "tag": "proxy",
        "type": "direct" # Default, will be overridden
    }

    scheme = proxy.get('scheme', '').lower()
    address = proxy.get('address')
    port = proxy.get('port')
    uuid = proxy.get('uuid')
    flow = proxy.get('flow')
    security = proxy.get('security') # From parse_proxy_url's 'scy' or general security param
    password = proxy.get('password')
    
    # TLS/Reality/uTLS 参数
    sni = proxy.get('sni')
    alpn = proxy.get('alpn')
    fp = proxy.get('fp')
    publicKey = proxy.get('publicKey')
    shortId = proxy.get('shortId')
    spiderX = proxy.get('spiderX')

    # 传输协议参数
    transport_type = proxy.get('type')
    path = proxy.get('path')
    host = proxy.get('host')
    serviceName = proxy.get('serviceName')
    mode = proxy.get('mode')
    
    # Hysteria2
    encryption = proxy.get('encryption')
    obfs = proxy.get('obfs')
    obfs_password = proxy.get('obfs_password')
    up_mbps = proxy.get('up_mbps')
    down_mbps = proxy.get('down_mbps')

    # Base TLS config for common use
    tls_config = {
        "enabled": True,
        "server_name": sni if sni else address,
        "insecure": True, # For testing, set to False in production
    }
    if alpn:
        tls_config["alpn"] = alpn.split(',')
    if fp:
        tls_config["utls"] = {
            "enabled": True,
            "fingerprint": fp
        }
    
    # Reality specific for VLESS/VMess
    if publicKey:
        tls_config["reality"] = {
            "enabled": True,
            "public_key": publicKey,
            "short_id": shortId,
            "spider_x": spiderX if spiderX else None,
        }

    if scheme == "vless":
        outbound = {
            "tag": "proxy",
            "type": "vless",
            "server": address,
            "server_port": port,
            "uuid": uuid,
            "flow": flow,
            "tls": tls_config,
        }
    elif scheme == "trojan":
        outbound = {
            "tag": "proxy",
            "type": "trojan",
            "server": address,
            "server_port": port,
            "password": password,
            "tls": tls_config,
        }
    elif scheme == "vmess":
        outbound = {
            "tag": "proxy",
            "type": "vmess",
            "server": address,
            "server_port": port,
            "uuid": uuid,
            "security": security if security else "auto", # 'auto' is sing-box default for vmess security
            "alter_id": proxy.get('alter_id', 0),
            "tls": tls_config if proxy.get('security') == 'tls' else {"enabled": False}, # Only enable TLS if 'security' param is 'tls'
        }
        # Add transport settings (ws, grpc)
        if transport_type == "ws":
            outbound["transport"] = {
                "type": "ws",
                "path": path,
                "headers": {
                    "Host": host if host else (sni if sni else address)
                }
            }
        elif transport_type == "grpc":
            outbound["transport"] = {
                "type": "grpc",
                "service_name": serviceName,
                "mode": mode if mode else "gun" # Default grpc mode is 'gun'
            }
    elif scheme == "ss": # Shadowsocks
        outbound = {
            "tag": "proxy",
            "type": "shadowsocks",
            "server": address,
            "server_port": port,
            "method": proxy.get('method', 'chacha20-poly1305'), # Default method
            "password": password,
            "tls": tls_config if proxy.get('security') == 'tls' else {"enabled": False}, # SS with TLS is uncommon but possible
        }
    elif scheme == "hy2": # Hysteria2
        outbound = {
            "tag": "proxy",
            "type": "hysteria2",
            "server": address,
            "server_port": port,
            "password": password,
            "tls": tls_config,
        }
        if encryption:
            outbound["encryption"] = encryption
        if obfs:
            outbound["obfs"] = obfs
            if obfs_password:
                outbound["obfs_password"] = obfs_password
        # Add bandwidth limits if provided in URL (optional, can be fixed)
        outbound["up_mbps"] = int(up_mbps) if up_mbps else 100 # Default to 100 Mbps
        outbound["down_mbps"] = int(down_mbps) if down_mbps else 100 # Default to 100 Mbps

    else:
        # 对于不支持的协议，或者解析失败，将其视为直连或直接跳过 (这里设为直连)
        logging.warning(f"不支持或无法解析的代理协议: {scheme}. 将使用直连。Proxy: {proxy.get('tag', 'unknown')}")
        outbound = {
            "tag": "proxy",
            "type": "direct"
        }

    config = {
        "log": {
            "level": "info", # Keep info for sing-box internal logs
            "output": SINGBOX_LOG_PATH,
        },
        "dns": {
            "servers": [
                {"tag": "local-dns", "address": "202.96.128.86", "port": 53},
                {"tag": "backup-dns", "address": "120.196.165.24", "port": 53}
            ],
            "rules": [
                {"outbound": "dns-out"} # All DNS queries go to dns-out
            ],
            "final": "dns-out" # Final fallback for DNS
        },
        "inbounds": [
            {
                "type": "socks",
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "listen_port": local_port,
                "sniff": True # Enable sniffing to identify DNS requests
            }
        ],
        "outbounds": [
            outbound,
            {"tag": "direct", "type": "direct"},
            {"tag": "block", "type": "block"}
        ],
        "route": {
            "rules": [
                {"protocol": ["dns"], "outbound": "dns-out"}, # Explicitly route DNS protocol traffic
                {"domain_suffix": ["t.me", "tiktok.com", "google.com"], "outbound": "proxy"}, # Test these domains
                {"geosite": "cn", "outbound": "direct"},
                {"geoip": "cn", "outbound": "direct"},
                {"geosite": "category-ads-all", "outbound": "block"}, # Block ads globally
                {"geosite": "private", "outbound": "direct"}, # Private IPs direct
                {"network": "udp", "port": 53, "outbound": "dns-out"}, # UDP 53 for DNS
                {"outbound": "proxy"} # Default to proxy
            ],
            "final": "proxy", # Final fallback to proxy
            "dns_resolve_strategy": "prefer_ipv4"
        },
        "dns_outbounds": [
            {"tag": "dns-out", "outbound": "direct"} # DNS queries should go direct
        ]
    }
    return config

# 异步运行 sing-box 进程并执行测试
async def run_singbox_test(config_file, local_port, proxy_id):
    singbox_process = None
    try:
        # 清理旧的 sing-box 日志文件
        # 为了调试方便，这里将 sing-box 的日志也指向一个唯一的文件
        # 实际部署时可以考虑集中日志或只保留最新
        proxy_singbox_log_path = f"data/sing-box-{proxy_id}.log"
        if os.path.exists(proxy_singbox_log_path):
            os.remove(proxy_singbox_log_path)

        # 启动 sing-box 进程
        singbox_process = await asyncio.create_subprocess_exec(
            SINGBOX_BIN_PATH, "-C", config_file,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        logging.info(f"sing-box {proxy_id} (port: {local_port}) 已启动，PID: {singbox_process.pid}")

        # 给 sing-box 一点时间启动
        await asyncio.sleep(0.5) # 0.5秒启动时间

        # 检查 sing-box 是否仍在运行，如果启动失败会提前退出
        if singbox_process.returncode is not None:
            stdout_data, stderr_data = await singbox_process.communicate()
            logging.error(f"sing-box {proxy_id} 启动失败，返回码: {singbox_process.returncode}")
            logging.error(f"sing-box {proxy_id} stdout:\n{stdout_data.decode(errors='ignore')}")
            logging.error(f"sing-box {proxy_id} stderr:\n{stderr_data.decode(errors='ignore')}")
            return None, None

        # 检查代理可用性和性能
        # aiohttp 客户端会话，trust_env=True 允许使用环境变量（尽管我们这里显式设置代理）
        async with aiohttp.ClientSession(trust_env=True) as session:
            # aiohttp 使用 http:// 或 socks5:// 协议来指定代理
            proxy_url_for_aiohttp = f"http://127.0.0.1:{local_port}" # sing-box socks inbound acts as http proxy for aiohttp

            latency = None
            throughput = None

            # Test latency
            try:
                start_time = time.time()
                async with session.get(TEST_URLS[0], proxy=proxy_url_for_aiohttp, timeout=TEST_TIMEOUT) as response:
                    response.raise_for_status() # 抛出 HTTP 状态码非 2xx 的异常
                latency = (time.time() - start_time) * 1000
                logging.info(f"代理 {proxy_id} ({TEST_URLS[0]}) 延迟测试成功: {latency:.2f}ms")
            except Exception as e:
                logging.warning(f"代理 {proxy_id} ({TEST_URLS[0]}) 延迟测试失败: {type(e).__name__}: {e}")
                return None, None # 延迟测试失败，无需继续吞吐量测试

            # Test throughput (使用更大的文件以获得更准确的测量)
            try:
                test_file_url = f"http://speedtest.tele2.net/10MB.zip?_={random.randint(0, 100000)}" # 10MB 文件
                start_time_dl = time.time()
                # 吞吐量测试可以给更长的超时时间
                async with session.get(test_file_url, proxy=proxy_url_for_aiohttp, timeout=TEST_TIMEOUT * 2) as response:
                    response.raise_for_status()
                    total_bytes = 0
                    # 异步迭代响应内容块
                    async for chunk in response.content.iter_chunked(1024):
                        total_bytes += len(chunk)
                download_time = time.time() - start_time_dl
                if download_time > 0:
                    throughput = (total_bytes / (1024 * 1024)) / download_time # MB/s
                    logging.info(f"代理 {proxy_id} ({test_file_url}) 吞吐量测试成功: {throughput:.2f}MB/s")
                else:
                    throughput = 0
                    logging.warning(f"代理 {proxy_id} ({test_file_url}) 吞吐量测试时间过短。")
            except Exception as e:
                logging.warning(f"代理 {proxy_id} ({test_file_url}) 吞吐量测试失败: {type(e).__name__}: {e}")
                throughput = None

            return latency, throughput

    except asyncio.CancelledError:
        logging.warning(f"代理 {proxy_id} 测试被取消。")
        return None, None
    except Exception as e:
        logging.error(f"运行 sing-box 或测试代理 {proxy_id} 时发生未预期错误: {type(e).__name__}: {e}")
        return None, None
    finally:
        # 确保 sing-box 进程被终止
        if singbox_process:
            if singbox_process.returncode is None: # 进程仍在运行
                logging.info(f"正在终止 sing-box 进程 {singbox_process.pid}...")
                singbox_process.terminate()
                try:
                    await asyncio.wait_for(singbox_process.wait(), timeout=5)
                except asyncio.TimeoutError:
                    logging.warning(f"强制杀死 sing-box 进程 {singbox_process.pid} (超时)。")
                    singbox_process.kill()
            # else: 进程已经提前退出（例如启动失败）
        
        # 清理 sing-box 配置文件
        if os.path.exists(config_file):
            try:
                os.remove(config_file)
            except OSError as e:
                logging.warning(f"无法删除 sing-box 配置文件 {config_file}: {e}")
        
        # 确保通过端口清理可能残留的进程（冗余但安全）
        if local_port:
            cleanup_singbox(local_port)


def generate_proxy_id(proxy):
    """为代理生成一个唯一的ID"""
    # 使用代理的原始URL或关键信息生成一个哈希值
    # 确保哈希值是字符串
    # 尽可能包含更多唯一识别信息，如scheme, address, port, uuid, password, flow, sni, shortId
    unique_parts = [
        proxy.get('scheme'),
        proxy.get('address'),
        str(proxy.get('port')),
        proxy.get('uuid'),
        proxy.get('password'),
        proxy.get('flow'),
        proxy.get('sni'),
        proxy.get('publicKey'),
        proxy.get('shortId'),
        proxy.get('tag') # Use tag as a last resort if other unique identifiers are missing
    ]
    raw_id = "-".join(filter(None, unique_parts)) # filter(None, ...) removes None/empty strings
    return md5(raw_id.encode('utf-8')).hexdigest()

def load_failed_proxies():
    """加载之前保存的失败节点"""
    if os.path.exists(FAILED_PROXIES_FILE):
        try:
            with open(FAILED_PROXIES_FILE, 'r') as f:
                return set(json.load(f))
        except json.JSONDecodeError:
            logging.warning(f"无法解析 {FAILED_PROXIES_FILE}，可能文件已损坏。将重新开始。")
            return set()
    return set()

def save_failed_proxies(failed_proxies_set):
    """保存失败节点，限制数量"""
    # 只保留最新的 MAX_FAILED_PROXIES 个失败节点
    failed_list = list(failed_proxies_set)[-MAX_FAILED_PROXIES:]
    os.makedirs(os.path.dirname(FAILED_PROXIES_FILE), exist_ok=True)
    with open(FAILED_PROXIES_FILE, 'w') as f:
        json.dump(failed_list, f, indent=2)

def load_existing_proxies():
    """加载已存在于 OUTPUT_SUB_FILE 中的代理 URL 以进行去重"""
    existing = set()
    if os.path.exists(OUTPUT_SUB_FILE):
        try:
            with open(OUTPUT_SUB_FILE, 'r') as f:
                for line in f:
                    existing.add(line.strip())
        except Exception as e:
            logging.warning(f"加载 {OUTPUT_SUB_FILE} 失败: {e}")
    return existing

def singbox_to_proxy_url(proxy):
    """将 sing-box 配置格式的代理信息转换回 URL 格式"""
    # 这是一个简化版本，尝试重建原始 URL
    scheme = proxy.get("scheme", "").lower()
    address = proxy.get("address", "")
    port = proxy.get("port", "")
    tag_raw = proxy.get("tag", f"{scheme}-{address}") # Get original tag before encoding

    # Collect user info for schemes like VLESS/VMess/Trojan/SS
    userinfo_parts = []
    if scheme in ["vless", "vmess"] and proxy.get("uuid"):
        userinfo_parts.append(proxy["uuid"])
    elif scheme in ["trojan", "ss", "hy2"] and proxy.get("password"):
        userinfo_parts.append(proxy["password"])
    
    # For VMess, the userinfo part is base64 encoded JSON
    if scheme == "vmess":
        vmess_user_data = {
            "v": "2", # VMess version
            "ps": tag_raw,
            "id": proxy.get("uuid", ""),
            "aid": proxy.get("alter_id", 0),
            "scy": proxy.get("security"),
            "net": proxy.get("type"), # network type
            "type": "none", # no tls type for vmess
            "host": proxy.get("host"),
            "path": proxy.get("path"),
            "tls": "tls" if proxy.get("tls", {}).get("enabled") else "none",
            "sni": proxy.get("sni"),
            "fp": proxy.get("fp"), # uTLS fingerprint
            # Additional VMess parameters can be added here if needed
        }
        # Filter out None values for cleaner JSON
        vmess_user_data = {k: v for k, v in vmess_user_data.items() if v is not None}
        userinfo_encoded = base64.b64encode(json.dumps(vmess_user_data, separators=(',', ':')).encode('utf-8')).decode('utf-8')
        userinfo_part = userinfo_encoded.rstrip('=') # Remove padding for vmess urls
    elif userinfo_parts:
        userinfo_part = ":".join(userinfo_parts) # Basic username:password
    else:
        userinfo_part = ""

    # Base URL construction
    base_url = f"{scheme}://{address}:{port}"
    if userinfo_part:
        base_url = f"{scheme}://{userinfo_part}@{address}:{port}"

    # Reconstruct query parameters
    query_params_dict = {}
    for key in ['flow', 'sni', 'alpn', 'fp', 'publicKey', 'shortId', 'spiderX', 
                'type', 'path', 'host', 'serviceName', 'mode', 
                'encryption', 'obfs', 'obfsParam', 'up_mbps', 'down_mbps', 
                'security', 'method']: # 'obfsParam' for hysteria2 password
        val = proxy.get(key)
        if val is not None and not (scheme == "vmess" and key in ['host', 'path', 'sni', 'alpn', 'fp', 'security', 'method', 'type']): # vmess handles some in userinfo json
            if isinstance(val, list): # Handle list like alpn
                query_params_dict[key] = ','.join(val)
            elif key == 'obfs_password': # Map to obfsParam for Hysteria2 URL
                query_params_dict['obfsParam'] = str(val)
            else:
                query_params_dict[key] = str(val)

    # Add query parameters
    if query_params_dict:
        query_string = urllib.parse.urlencode(query_params_dict)
        base_url = f"{base_url}?{query_string}"
    
    # Add fragment (tag)
    if tag_raw:
        base_url = f"{base_url}#{urllib.parse.quote(tag_raw)}"

    return base_url


async def fetch_nodes_from_url(source_url, source_type):
    """异步从给定URL获取代理节点"""
    nodes = []
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(source_url, timeout=15) as response:
                response.raise_for_status()
                content = await response.text()

        if source_type == "plain":
            # 假设每行一个代理 URL
            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith('#'):
                    try:
                        node_info = parse_proxy_url(line)
                        if node_info and node_info.get('scheme') and node_info.get('address') and node_info.get('port'):
                            nodes.append(node_info)
                        else:
                            logging.warning(f"无法解析代理 URL (plain): {line}")
                    except Exception as e:
                        logging.warning(f"解析代理 URL (plain) 异常: {line} - {e}")
        elif source_type == "base64":
            try:
                decoded_content = base64.b64decode(content).decode('utf-8')
                for line in decoded_content.splitlines():
                    line = line.strip()
                    if line and not line.startswith('#'):
                        try:
                            node_info = parse_proxy_url(line)
                            if node_info and node_info.get('scheme') and node_info.get('address') and node_info.get('port'):
                                nodes.append(node_info)
                            else:
                                logging.warning(f"无法解析代理 URL (base64): {line}")
                        except Exception as e:
                            logging.warning(f"解析代理 URL (base64) 异常: {line} - {e}")
            except Exception as e:
                logging.error(f"Base64 解码或处理失败: {e}")
        elif source_type == "yaml":
            try:
                # 假设 YAML 内容是一个列表，每个元素是一个代理对象
                yaml_data = yaml.safe_load(content)
                if isinstance(yaml_data, list):
                    for item in yaml_data:
                        # 你需要根据 YAML 文件的具体结构来提取代理信息
                        # 这里只是一个示例，假设它直接是 sing-box 兼容的出站配置
                        if isinstance(item, dict) and item.get('type'):
                            # 对于 YAML 源，我们假设其直接提供了 sing-box 兼容的配置片段
                            # 你可能需要将其转换为 parse_proxy_url 可以理解的格式，或者直接使用
                            # 这里简单地存储，后续的 create_singbox_config 需要处理
                            nodes.append(item)
                        else:
                            logging.warning(f"无法解析 YAML 代理项: {item}")
                else:
                    logging.warning(f"YAML 内容不是一个列表: {source_url}")
            except yaml.YAMLError as e:
                logging.error(f"解析 YAML 失败: {e}")
        else:
            logging.warning(f"不支持的节点源类型: {source_type}")

    except aiohttp.ClientError as e:
        logging.error(f"从 {source_url} 获取代理失败: 网络或客户端错误 - {e}")
    except asyncio.TimeoutError:
        logging.error(f"从 {source_url} 获取代理超时。")
    except Exception as e:
        logging.error(f"从 {source_url} 获取代理时发生未知错误: {e}")
    return nodes

async def test_proxy(proxy, proxy_id):
    """
    测试单个代理的延迟和吞吐量。
    这个函数是异步的，应该在 asyncio 事件循环中运行。
    """
    # 为每个代理使用一个唯一的配置文件名，并存放在 data 目录下
    singbox_config_file = os.path.join("data", f"sing-box-config-{proxy_id}.json")
    local_port = None
    
    try:
        logging.info(f"正在测试代理: {proxy['tag']} (ID: {proxy_id})")
        
        # 查找可用端口
        local_port = find_available_port()
        if not local_port:
            logging.error(f"无法为代理 {proxy_id} 找到可用端口。")
            return None

        # 创建 sing-box 配置
        os.makedirs(os.path.dirname(singbox_config_file), exist_ok=True)
        config = create_singbox_config(proxy, local_port)
        with open(singbox_config_file, "w") as f:
            json.dump(config, f, indent=2)
        logging.info(f"为代理 {proxy_id} 创建了 sing-box 配置: {singbox_config_file}")
        logging.debug(f"Sing-box config for {proxy_id}:\n{json.dumps(config, indent=2)}") # Debug级别打印详细配置

        # 运行 sing-box 并进行测试
        latency, throughput = await run_singbox_test(singbox_config_file, local_port, proxy_id)

        if latency is not None and throughput is not None:
            logging.info(f"代理 {proxy.get('tag', 'unknown')} (ID: {proxy_id}) 测试成功: 延迟 {latency:.2f}ms, 吞吐量 {throughput:.2f}MB/s")
            return {"proxy": proxy, "latency": latency, "throughput": throughput}
        else:
            logging.warning(f"代理 {proxy.get('tag', 'unknown')} (ID: {proxy_id}) 测试失败或未返回有效数据。")
            return None

    except asyncio.CancelledError:
        logging.warning(f"代理 {proxy.get('tag', 'unknown')} (ID: {proxy_id}) 测试被取消。")
        return None
    except Exception as exc:
        # 捕获所有其他异常，并记录
        logging.error(f"代理 {proxy.get('tag', 'unknown')} (ID: {proxy_id}) 生成异常: {type(exc).__name__}: {exc}")
        return None
    finally:
        # 清理 sing-box 进程和配置文件
        if local_port: # 只有当端口被成功分配时才尝试清理进程
            cleanup_singbox(local_port) # 确保杀死所有监听该端口的 sing-box 进程
        if os.path.exists(singbox_config_file):
            try:
                os.remove(singbox_config_file)
            except OSError as e:
                logging.warning(f"无法删除 sing-box 配置文件 {singbox_config_file}: {e}")


# --- 主逻辑 ---
async def main_async():
    """异步主函数，协调所有操作"""
    # 创建数据目录
    os.makedirs("data", exist_ok=True)

    # 检查 sing-box 可执行文件是否存在
    if not os.path.exists(SINGBOX_BIN_PATH):
        logging.error(f"sing-box 可执行文件未找到: {SINGBOX_BIN_PATH}")
        logging.error("请确保已下载 sing-box 并放置在正确的位置（例如 './clash_bin/sing-box'）。")
        exit(1)

    # 下载 GeoIP 数据库 (如果不存在)
    if not os.path.exists(GEOIP_DB_PATH):
        logging.info("正在下载 GeoIP 数据库...")
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get("https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.db", timeout=30) as response:
                    response.raise_for_status() # 抛出 HTTP 错误
                    with open(GEOIP_DB_PATH, 'wb') as f:
                        while True:
                            chunk = await response.content.read(8192)
                            if not chunk:
                                break
                            f.write(chunk)
            logging.info("GeoIP 数据库已更新。")
        except Exception as e:
            logging.error(f"下载 GeoIP 数据库失败: {type(e).__name__}: {e}")
            # 继续执行，GeoIP 缺失可能导致部分路由规则失效，但不影响核心测试

    # 加载之前测试失败的节点
    failed_proxies_ids = load_failed_proxies()
    logging.info(f"已加载 {len(failed_proxies_ids)} 个失败节点。")

    logging.info("开始收集代理节点...")
    all_nodes = []
    for source in NODES_SOURCES:
        nodes_from_source = await fetch_nodes_from_url(source["url"], source["type"])
        all_nodes.extend(nodes_from_source)
        logging.info(f"已从 {source['url']} 获取到 {len(nodes_from_source)} 个代理节点。")

    if not all_nodes:
        logging.info("未获取到任何代理节点，跳过测试。")
        return

    # 去重
    unique_nodes_map = {}
    for node in all_nodes:
        node_id = generate_proxy_id(node)
        # 对于可能从不同源获取到相同代理但信息略有差异的情况，
        # 这里的去重逻辑可以更复杂，例如选择信息最全的那个。
        # 目前是简单的 ID 去重，以最后出现的为准。
        unique_nodes_map[node_id] = node
    
    nodes_to_test = []
    for node_id, node in unique_nodes_map.items():
        if node_id not in failed_proxies_ids:
            nodes_to_test.append(node)
        # else:
            # logging.debug(f"代理 {node.get('tag', 'unknown')} (ID: {node_id}) 已在失败列表中，跳过。")

    logging.info(f"已处理 {len(all_nodes)} 个代理节点（去重后 {len(unique_nodes_map)} 个，排除失败节点后 {len(nodes_to_test)} 个）。")

    if not nodes_to_test:
        logging.info("没有新的代理节点需要测试。")
        # 如果没有新节点要测试，但旧的失败节点列表存在，这里不会清空。
        # 如果想定期清理失败列表，可以在这里添加逻辑。
        return

    logging.info(f"开始并行测试 {len(nodes_to_test)} 个代理节点...")
    results = []
    
    # 使用 asyncio.Semaphore 来限制并发数量，防止同时启动过多 sing-box 进程
    semaphore = asyncio.Semaphore(MAX_WORKERS)

    # 用于包装 test_proxy 任务，使其能够使用 semaphore
    async def run_test_proxy_with_semaphore(proxy, proxy_id):
        async with semaphore:
            return await test_proxy(proxy, proxy_id)

    tasks = []
    for node in nodes_to_test:
        proxy_id = generate_proxy_id(node)
        tasks.append(run_test_proxy_with_semaphore(node, proxy_id))

    # 并发运行所有测试任务，并捕获异常
    # return_exceptions=True 会让协程内部抛出的异常作为结果返回，而不是中断 asyncio.gather
    all_test_results = await asyncio.gather(*tasks, return_exceptions=True)

    # 从现有的失败列表开始更新
    current_failed_proxies = set(failed_proxies_ids) 
    
    for i, result_or_exc in enumerate(all_test_results):
        original_proxy = nodes_to_test[i]
        original_proxy_id = generate_proxy_id(original_proxy)

        if isinstance(result_or_exc, Exception):
            # 这是 test_proxy 内部抛出并由 asyncio.gather 捕获的 Python 异常
            logging.error(f"代理 {original_proxy.get('tag', 'unknown')} (ID: {original_proxy_id}) 测试过程中发生未处理异常: {type(result_or_exc).__name__}: {result_or_exc}")
            current_failed_proxies.add(original_proxy_id)
        elif result_or_exc: # test_proxy 返回了成功结果 (非None)
            results.append(result_or_exc)
            # 如果之前是失败的，现在成功了，则从失败列表移除
            current_failed_proxies.discard(original_proxy_id)
        else: # test_proxy 返回 None (表示测试失败，但内部已处理异常或没有有效数据)
            logging.warning(f"代理 {original_proxy.get('tag', 'unknown')} (ID: {original_proxy_id}) 测试失败或未返回有效数据 (被标记为失败)。")
            current_failed_proxies.add(original_proxy_id)

    logging.info("代理测试完成。")

    # 保存失败节点
    if current_failed_proxies:
        save_failed_proxies(current_failed_proxies)
        logging.info(f"已保存 {len(current_failed_proxies)} 个失败节点到 {FAILED_PROXIES_FILE}")
    else:
        logging.info(f"没有需要保存的失败节点。")
        # 如果所有节点都成功或没有新的失败节点，可以考虑清空文件
        if os.path.exists(FAILED_PROXIES_FILE):
             os.remove(FAILED_PROXIES_FILE) # Remove if empty
             logging.info(f"已清空 {FAILED_PROXIES_FILE}。")


    # 排序结果：先按延迟升序，再按吞吐量降序
    results.sort(key=lambda x: (x["latency"], -x["throughput"]))

    # 加载历史可用节点
    existing_proxy_urls = load_existing_proxies()

    # 构建最终要写入 collectSub.txt 的 URL 列表
    # 保持历史已成功节点，并添加新的成功节点
    final_output_urls_set = set(existing_proxy_urls) # 使用set进行去重
    for result in results:
        proxy_url = singbox_to_proxy_url(result["proxy"])
        if proxy_url:
            formatted_url = f"{proxy_url}#{result['latency']:.2f}ms,throughput={result['throughput']:.2f}MB/s"
            final_output_urls_set.add(formatted_url)

    # 将集合转换回列表并排序，以便输出一致
    final_output_urls = sorted(list(final_output_urls_set))

    # 写入 collectSub.txt
    if final_output_urls:
        content = "\n".join(final_output_urls)
        os.makedirs(os.path.dirname(OUTPUT_SUB_FILE), exist_ok=True)
        with open(OUTPUT_SUB_FILE, "w") as f:
            f.write(content)
        logging.info(f"已保存 {len(final_output_urls)} 个可用节点到 {OUTPUT_SUB_FILE}")
        
        # 更新 sub.txt (Base64 encoded)
        content_b64 = base64.b64encode(content.encode('utf-8')).decode('utf-8')
        os.makedirs(os.path.dirname("data/sub.txt"), exist_ok=True) # Ensure data dir exists for sub.txt
        with open("data/sub.txt", "w") as f:
            f.write(content_b64)
        logging.info("订阅链接已更新到 data/sub.txt")
    else:
        logging.info("没有新的可用节点或所有节点测试失败，且无历史可用节点。")
        # 如果没有可用节点，清理输出文件
        if os.path.exists(OUTPUT_SUB_FILE):
            os.remove(OUTPUT_SUB_FILE) 
            logging.info(f"已清空 {OUTPUT_SUB_FILE}。")
        if os.path.exists("data/sub.txt"):
            os.remove("data/sub.txt") 
            logging.info(f"已清空 data/sub.txt。")


# --- 脚本入口点 ---
if __name__ == "__main__":
    try:
        asyncio.run(main_async())
    except RuntimeError as e:
        # 捕捉 "Event loop is closed" 这样的错误，通常发生在某些异步资源未正确关闭时
        logging.error(f"异步运行时错误: {e}")
    except Exception as e:
        logging.critical(f"脚本运行过程中发生致命错误: {e}", exc_info=True) # exc_info=True will print traceback
