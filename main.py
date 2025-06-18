import base64
import json
import os
import re
import subprocess
import time
import urllib.parse
import requests
import socket
import logging
import yaml
import threading
import concurrent.futures

# --- 配置日志 ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- 常量定义 ---
# sing-box 二进制文件路径 (请根据您的实际情况调整)
SINGBOX_BIN_PATH = "./clash_bin/sing-box"
# sing-box 配置文件路径
SINGBOX_CONFIG_PATH = "sing-box-config.json"
# sing-box 日志文件路径
SINGBOX_LOG_PATH = os.getenv("SINGBOX_LOG_PATH", "data/sing-box.log")
# GeoIP 数据库路径 (用于 sing-box 路由)
GEOIP_DB_PATH = "data/geoip.db"
# 输出有效代理的文件
OUTPUT_SUB_FILE = "data/collectSub.txt"

# 节点源配置列表
# 每个字典包含 'url' (节点订阅地址) 和 'type' (plain, base64, yaml)
NODES_SOURCES = [
    {
        "url": "https://raw.githubusercontent.com/qjlxg/hy2/refs/heads/main/configtg.txt",
        "type": "plain",
    },
    {
        "url": "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/base64.yaml",
        "type": "yaml",
    },
]

# 最大处理的代理数量，防止一次性处理过多导致内存或时间问题
MAX_PROXIES = 2500 # 适当增加以覆盖更多节点，但仍需注意性能

# 用于测试代理连通性的 URL 列表
TEST_URLS = ["https://www.google.com", "http://www.example.com", "https://www.cloudflare.com"]
# 单个 HTTP 请求的超时时间
HTTP_TIMEOUT_SECONDS = 10
# sing-box 启动后等待端口开放的超时时间
SINGBOX_STARTUP_TIMEOUT = 30
# 代理的监听端口
PROXY_PORT = 1080

# 并行测试的线程数
# 建议根据您的 CPU 核心数和网络带宽进行调整，过多的线程可能导致反效果
CONCURRENT_TESTS = 10 # 提高并行度

# --- 确保输出目录存在 ---
for path in [OUTPUT_SUB_FILE, SINGBOX_LOG_PATH, GEOIP_DB_PATH]:
    dirname = os.path.dirname(path)
    if dirname:
        os.makedirs(dirname, exist_ok=True)

# --- 辅助函数：IPv6 验证 ---
def is_valid_ipv6(addr):
    """验证 IPv6 地址格式"""
    try:
        addr = addr.strip("[]")
        socket.inet_pton(socket.AF_INET6, addr)
        return True
    except (socket.error, ValueError):
        return False

# --- 核心函数：将 YAML 代理字典转换为 sing-box 配置格式 ---
def _convert_yaml_to_singbox_proxy_object(yaml_proxy_dict):
    """
    将单个 YAML 代理字典（例如来自 Clash 配置）
    转换为 sing-box 出站配置字典。
    这是一个简化转换，可能需要根据
    具体的 YAML 代理定义和 sing-box 的完整功能进行扩展。
    """
    p_type = yaml_proxy_dict.get("type")
    tag = yaml_proxy_dict.get("name", f"{p_type}-node")
    server = yaml_proxy_dict.get("server")
    port = yaml_proxy_dict.get("port")

    if not server or not port:
        logging.error(f"YAML代理中缺少服务器或端口，跳过: {yaml_proxy_dict}")
        return None

    # sing-box 出站基础结构
    outbound = {
        "type": p_type,
        "tag": tag,
        "server": server,
        "server_port": int(port),
    }

    # 通用 TLS 设置
    # 常见的基于 WS/gRPC 的代理通常启用 TLS
    tls_enabled = yaml_proxy_dict.get("tls", False) or yaml_proxy_dict.get("network") in ["ws", "grpc"]
    if tls_enabled:
        outbound["tls"] = {
            "enabled": True,
            "server_name": yaml_proxy_dict.get("sni", server),
            "insecure": yaml_proxy_dict.get("skip-cert-verify", False),
        }

    # 传输设置 (WS 是常见的)
    transport_type = yaml_proxy_dict.get("network")
    if transport_type == "ws":
        outbound["transport"] = {
            "type": "ws",
            "path": yaml_proxy_dict.get("ws-path", "/"),
            "headers": {"Host": yaml_proxy_dict.get("ws-headers", {}).get("Host", server)}
        }
    # 其他传输类型如 'grpc' 可以在此添加

    if p_type == "ss":
        outbound["method"] = yaml_proxy_dict.get("cipher")
        outbound["password"] = yaml_proxy_dict.get("password")
    elif p_type == "trojan":
        outbound["password"] = yaml_proxy_dict.get("password")
        # TLS 和 Transport 已在上面处理
    elif p_type == "vmess":
        outbound["uuid"] = yaml_proxy_dict.get("uuid")
        outbound["security"] = yaml_proxy_dict.get("cipher", "auto") # Clash 中的 'cipher' 映射到 sing-box 的 'security'
        outbound["alter_id"] = int(yaml_proxy_dict.get("alterId", 0)) # Clash 使用 alterId
        
        # 修正：VMess TCP 传输不需要单独的 "transport" 字段
        # 安全地获取 network 类型
        vmess_network_type = yaml_proxy_dict.get("network") 
        if vmess_network_type not in ["tcp", "", None]: # 只有在不是纯TCP或空/None时才添加transport
            outbound["transport"] = {"type": vmess_network_type}
            if vmess_network_type == "ws":
                outbound["transport"]["path"] = yaml_proxy_dict.get("ws-path", "")
                outbound["transport"]["headers"] = {"Host": yaml_proxy_dict.get("ws-headers", {}).get("Host", "")}
            # Add other transport types if needed for YAML VMess
        
        # TLS for VMess, if enabled in YAML
        if yaml_proxy_dict.get("tls", False):
            outbound["tls"] = {
                "enabled": True,
                "server_name": yaml_proxy_dict.get("sni", server),
                "insecure": yaml_proxy_dict.get("skip-cert-verify", False)
            }

    elif p_type == "hysteria2":
        outbound["password"] = yaml_proxy_dict.get("password")
        # TLS 已在上面处理
        if "obfs" in yaml_proxy_dict:
            outbound["obfs"] = {
                "type": yaml_proxy_dict["obfs"],
                "password": yaml_proxy_dict.get("obfs-password")
            }
    elif p_type == "vless":
        outbound["uuid"] = yaml_proxy_dict.get("uuid")
        outbound["flow"] = yaml_proxy_dict.get("flow") # VLESS 特有
        
        # VLESS 几乎总是使用 TLS
        if tls_enabled: # 重新检查TLS是否启用，因为VLESS通常有特殊TLS要求
            tls_obj = outbound.get("tls", {"enabled": True}) # 获取或创建tls对象
            if yaml_proxy_dict.get("security") == "reality": # Reality是TLS的一个子类型
                # !!! 关键修正: 移除 "handshake" 字段，它在 sing-box 中不存在于 reality 对象下
                tls_obj["reality"] = { 
                    "enabled": True,
                    "public_key": yaml_proxy_dict.get("public-key"), # Clash YAML中使用 public-key
                    "short_id": yaml_proxy_dict.get("short-id"),     # Clash YAML中使用 short-id
                    "server_name": yaml_proxy_dict.get("sni", server), # Reality的SNI通常在Reality对象内或被Reality覆盖
                    "fingerprint": yaml_proxy_dict.get("fingerprint") # Fingerprint 可以在 Reality 内部
                }
                if not tls_obj["reality"].get("public_key") or not tls_obj["reality"].get("short_id"):
                    logging.error(f"YAML VLESS Reality 代理缺少必要的 public_key 或 short_id，跳过: {yaml_proxy_dict.get('name')}")
                    return None
            
            outbound["tls"] = tls_obj # 更新tls配置
            
            # 指纹和 xver 既可能在 TLS 根级别，也可能在 Reality 中
            # 仅当不在 Reality 配置中时才添加到 TLS 根级别
            if "fingerprint" in yaml_proxy_dict and "reality" not in outbound["tls"]:
                outbound["tls"]["fingerprint"] = yaml_proxy_dict["fingerprint"]
            if "xver" in yaml_proxy_dict:
                outbound["tls"]["xver"] = int(yaml_proxy_dict["xver"]) # xver 是整数

    # 根据需要添加其他代理类型

    return outbound

# --- 核心函数：解析代理 URL 字符串并转换为 sing-box 配置格式 ---
def parse_proxy_url_string(proxy_url):
    """解码代理 URL 字符串并转换为 sing-box 配置格式"""
    # 快速检查，跳过明显不是 URL 的行
    known_schemes = ("ss://", "vmess://", "trojan://", "hy2://", "vless://")
    if not proxy_url.startswith(known_schemes):
        logging.debug(f"跳过非代理 URL 格式的行: {proxy_url[:50]}...") # 记录前50个字符
        return None

    try:
        # 首先尝试解析 URL，如果 URL 格式本身就有问题，就直接跳过
        parsed = urllib.parse.urlparse(proxy_url)
        scheme = parsed.scheme
        if not scheme or not parsed.netloc: # 缺少scheme或netloc，视为无效URL
            logging.error(f"无效或不完整的 URL 格式，跳过: {proxy_url}")
            return None

        if scheme == "vmess":
            # 修正 Base64 解码的 padding 问题
            vmess_data_str = parsed.netloc
            # Base64解码前尝试去除不规范字符，只保留有效的Base64字符和等于号
            vmess_data_str = re.sub(r'[^a-zA-Z0-9+/=]', '', vmess_data_str)
            missing_padding = len(vmess_data_str) % 4
            if missing_padding:
                vmess_data_str += '=' * (4 - missing_padding)
            
            vmess_decoded_bytes = None
            try:
                vmess_decoded_bytes = base64.b64decode(vmess_data_str)
            except base64.binascii.Error as e:
                logging.error(f"VMess Base64 解码失败 (填充或格式错误) for {proxy_url}: {e}")
                return None
            
            if vmess_decoded_bytes is None: # Should not happen if previous try-except works, but for safety
                return None

            vmess_data = None
            try:
                # 尝试用 UTF-8 解码，如果失败，尝试忽略或替换错误字符
                vmess_data = json.loads(vmess_decoded_bytes.decode('utf-8'))
            except UnicodeDecodeError as e:
                logging.warning(f"VMess UTF-8 解码失败，尝试宽松模式 for {proxy_url}: {e}")
                try:
                    vmess_data = json.loads(vmess_decoded_bytes.decode('utf-8', errors='replace'))
                except json.JSONDecodeError as e_json_fallback:
                    logging.error(f"VMess JSON 解码失败 (UTF-8 宽松模式后) for {proxy_url}: {e_json_fallback}")
                    return None
            except json.JSONDecodeError as e:
                logging.error(f"VMess JSON 解码失败 (原始内容结构问题) for {proxy_url}: {e}")
                return None
            
            if vmess_data is None: # If all attempts failed
                return None
            
            transport_type = vmess_data.get("net", "tcp")
            
            transport_config = None
            # VMess TCP 传输不需要独立的 transport 配置
            if transport_type == "ws":
                transport_config = {
                    "type": transport_type,
                    "path": vmess_data.get("path", ""),
                }
                # 只有当 host 存在时才添加 headers
                if vmess_data.get("host"):
                    transport_config["headers"] = {"Host": vmess_data["host"]}
            # Add other transport types for URL based VMess if necessary

            vmess_outbound = {
                "type": "vmess",
                "tag": vmess_data.get("ps", "vmess-node"),
                "server": vmess_data.get("add"),
                "server_port": int(vmess_data.get("port")),
                "uuid": vmess_data.get("id"),
                "security": vmess_data.get("scy", "auto"),
                "alter_id": int(vmess_data.get("aid", 0)),
            }
            if transport_config: # 只有当 transport_config 不为 None 时才添加
                vmess_outbound["transport"] = transport_config

            # VMess TLS
            if vmess_data.get("tls") == "tls":
                vmess_outbound["tls"] = {
                    "enabled": True,
                    "server_name": vmess_data.get("sni", vmess_data.get("add")),
                    "insecure": vmess_data.get("allowInsecure", "0") == "1", # vmess 协议通常没有 allowInsecure 字段，但这里为了兼容性保留
                }
            
            return vmess_outbound

        elif scheme == "trojan":
            if "@" not in parsed.netloc:
                logging.error(f"无效的 Trojan URL 格式，缺少 '@': {proxy_url}")
                return None
            password, addr = parsed.netloc.split("@", 1)
            hostname_port = addr.split("?", 1)[0]
            if hostname_port.startswith("[") and "]" in hostname_port:
                match = re.match(r'^\[([0-9a-fA-F:]+)\](?::(\d+))?$', hostname_port)
                if not match:
                    logging.error(f"Trojan URL 中 IPv6 地址格式无效: {proxy_url}")
                    return None
                hostname = match.group(1)
                port = int(match.group(2)) if match.group(2) else 443
                if not is_valid_ipv6(hostname):
                    logging.error(f"Trojan URL 中解码后的 IPv6 地址无效: {proxy_url}")
                    return None
                hostname = f"[{hostname}]"
            else:
                parts = hostname_port.split(":")
                hostname = parts[0]
                port = int(parts[1]) if len(parts) > 1 else 443

            query = urllib.parse.parse_qs(parsed.query)
            network_type = query.get("type", ["tcp"])[0]

            transport_config = None
            if network_type == "ws":
                transport_config = {
                    "type": "ws",
                    "path": query.get("path", ["/"])[0],
                    "headers": {
                        "Host": query.get("host", [""])[0] or hostname.strip("[]")
                    }
                }
            # Add other transport types like 'grpc' for Trojan if needed

            return {
                "type": "trojan",
                "tag": urllib.parse.unquote(query.get("name", ["trojan-node"])[0]) or "trojan-node",
                "server": hostname,
                "server_port": int(port),
                "password": password,
                "tls": {
                    "enabled": True,
                    "server_name": query.get("sni", [""])[0] or hostname.strip("[]"),
                    "insecure": query.get("allowInsecure", ["0"])[0] == "1",
                },
                "transport": transport_config
            }

        elif scheme == "ss":
            # 修正 Base64 解码的 padding 问题
            # Shadowsocks URL 的 Base64 部分通常在 netloc (method:password@server:port) 或只有 netloc (method:password)
            # 这里假定 Base64 部分是整个 auth
            if "@" in parsed.netloc:
                auth, addr = parsed.netloc.split("@")
                
                auth_str = auth
                # Base64解码前尝试去除不规范字符
                auth_str = re.sub(r'[^a-zA-Z0-9+/=]', '', auth_str)
                missing_padding = len(auth_str) % 4
                if missing_padding:
                    auth_str += '=' * (4 - missing_padding)

                try:
                    # 使用 errors='replace' 处理解码错误
                    method_password = base64.b64decode(auth_str).decode('utf-8', errors='replace')
                    # 增加 split 的 maxsplit 参数以防止 extra ':' in password
                    method, password = method_password.split(":", 1)
                except (base64.binascii.Error, ValueError, UnicodeDecodeError) as e:
                    logging.error(f"Shadowsocks Base64 解码或解析失败 (auth部分) for {proxy_url}: {e}")
                    return None

                # 提取 hostname 和 port
                if ':' in addr:
                    hostname_parts = addr.split(':')
                    hostname = ':'.join(hostname_parts[:-1]) # Reconstruct hostname in case of IPv6 without brackets
                    port = hostname_parts[-1]
                else:
                    hostname = addr
                    port = 443 # Default port for SS if not specified in URL

            else: # ss://base64encoded_method_password@host:port (不常见但可能)
                method_password_str = parsed.netloc
                # Base64解码前尝试去除不规范字符
                method_password_str = re.sub(r'[^a-zA-Z0-9+/=]', '', method_password_str)
                missing_padding = len(method_password_str) % 4
                if missing_padding:
                    method_password_str += '=' * (4 - missing_padding)

                try:
                    method_password = base64.b64decode(method_password_str).decode('utf-8', errors='replace')
                    method, password = method_password.split(":", 1) # 增加 maxsplit
                except (base64.binascii.Error, ValueError, UnicodeDecodeError) as e:
                    logging.error(f"Shadowsocks Base64 解码或解析失败 (netloc部分) for {proxy_url}: {e}")
                    return None
                
                # Path可能包含host:port
                if not parsed.path.lstrip("/"): # 如果path是空的，则视为无效
                    logging.error(f"Shadowsocks URL 缺少服务器信息: {proxy_url}")
                    return None
                
                path_parts = parsed.path.lstrip("/").split(":")
                if len(path_parts) > 1:
                    hostname = ':'.join(path_parts[:-1]) # Reconstruct hostname for IPv6
                    port = path_parts[-1]
                else:
                    hostname = path_parts[0]
                    port = 443 # Default port if not in path

            return {
                "type": "shadowsocks",
                "tag": urllib.parse.unquote(parsed.fragment) or "ss-node",
                "server": hostname,
                "server_port": int(port),
                "method": method,
                "password": password,
            }

        elif scheme == "hy2":
            if "@" not in parsed.netloc:
                logging.error(f"无效的 Hysteria2 URL 格式，缺少 '@': {proxy_url}")
                return None
            password, addr = parsed.netloc.split("@", 1)
            hostname_port = addr.split("?", 1)[0]
            if hostname_port.startswith("[") and "]" in hostname_port:
                match = re.match(r'^\[([0-9a-fA-F:]+)\](?::(\d+))?$', hostname_port)
                if not match:
                    logging.error(f"Hysteria2 URL 中 IPv6 地址格式无效: {proxy_url}")
                    return None
                hostname = match.group(1)
                port = int(match.group(2)) if match.group(2) else 443
                if not is_valid_ipv6(hostname):
                    logging.error(f"Hysteria2 URL 中解码后的 IPv6 地址无效: {proxy_url}")
                    return None
                hostname = f"[{hostname}]"
            else:
                parts = hostname_port.split(":")
                hostname = parts[0]
                port = int(parts[1]) if len(parts) > 1 else 443

            query = urllib.parse.parse_qs(parsed.query)
            obfs = query.get("obfs", [""])[0]
            obfs_password = query.get("obfs-password", [""])[0]
            config = {
                "type": "hysteria2",
                "tag": urllib.parse.unquote(query.get("name", ["hy2-node"])[0]) or "hy2-node",
                "server": hostname,
                "server_port": int(port),
                "password": password,
                "tls": {
                    "enabled": True,
                    "server_name": query.get("sni", [""])[0] or hostname.strip("[]"),
                    "insecure": query.get("insecure", ["0"])[0] == "1",
                },
            }
            if obfs and obfs_password:
                config["obfs"] = {
                    "type": obfs,
                    "password": obfs_password,
                }
            return config

        elif scheme == "vless":
            # VLESS URL 格式: vless://UUID@SERVER:PORT?params#NAME
            if "@" not in parsed.netloc:
                logging.error(f"无效的 VLESS URL 格式，缺少 '@': {proxy_url}")
                return None
            uuid, addr_port = parsed.netloc.split("@", 1)
            hostname_port = addr_port.split("?", 1)[0]

            if hostname_port.startswith("[") and "]" in hostname_port:
                match = re.match(r'^\[([0-9a-fA-F:]+)\](?::(\d+))?$', hostname_port)
                if not match:
                    logging.error(f"VLESS URL 中 IPv6 地址格式无效: {proxy_url}")
                    return None
                hostname = match.group(1)
                port = int(match.group(2)) if match.group(2) else 443
                if not is_valid_ipv6(hostname):
                    logging.error(f"VLESS URL 中解码后的 IPv6 地址无效: {proxy_url}")
                    return None
                hostname = f"[{hostname}]"
            else:
                parts = hostname_port.split(":")
                hostname = parts[0]
                port = int(parts[1]) if len(parts) > 1 else 443

            query = urllib.parse.parse_qs(parsed.query)
            tag = urllib.parse.unquote(parsed.fragment) or "vless-node"

            tls_enabled = query.get("security", [""])[0] in ["tls", "reality"] or query.get("type", [""])[0] in ["ws", "grpc"]
            transport_type = query.get("type", [""])[0]

            transport_config = None
            if transport_type == "ws":
                transport_config = {
                    "type": "ws",
                    "path": query.get("path", ["/"])[0],
                    "headers": {
                        "Host": query.get("host", [""])[0] or hostname.strip("[]")
                    }
                }
            elif transport_type == "grpc":
                transport_config = {
                    "type": "grpc",
                    "service_name": query.get("serviceName", [""])[0]
                }
            # VLESS TCP 不需要 transport 配置，默认是 None

            vless_config = {
                "type": "vless",
                "tag": tag,
                "server": hostname,
                "server_port": int(port),
                "uuid": uuid,
                "flow": query.get("flow", [""])[0],
            }

            if tls_enabled:
                vless_config["tls"] = {
                    "enabled": True,
                    "server_name": query.get("sni", [""])[0] or hostname.strip("[]"),
                    "insecure": query.get("insecure", ["0"])[0] == "1",
                }
                # Reality 配置需要是一个字典
                if query.get("security", [""])[0] == "reality":
                    pbk = query.get("pbk", [""])[0]
                    sid = query.get("sid", [""])[0]
                    # !!! 关键修正: 移除 "handshake" 字段，它在 sing-box 中不存在于 reality 对象下
                    if not pbk or not sid:
                        logging.error(f"VLESS Reality 代理缺少必要的 public_key (pbk) 或 short_id (sid)，跳过: {proxy_url}")
                        return None
                    vless_config["tls"]["reality"] = {
                        "enabled": True,
                        "public_key": pbk, # "pbk" from URL query
                        "short_id": sid, # "sid" from URL query
                        "xver": int(query.get("xver", ["0"])[0]),
                        "spider_x": query.get("spiderX", [""])[0],
                        "server_name": query.get("fp", [""])[0] # In reality, fp is often the server_name or related
                    }
                    # Reality 的 server_name 常常和外部 SNI 一致或覆盖
                    if query.get("sni", [""])[0]:
                         vless_config["tls"]["reality"]["server_name"] = query.get("sni", [""])[0]
                    elif hostname.strip("[]"):
                         vless_config["tls"]["reality"]["server_name"] = hostname.strip("[]")

                # 指纹和 xver 既可能在 TLS 根级别，也可能在 Reality 中
                # 仅当不在 Reality 配置中时才添加到 TLS 根级别
                if query.get("fp", [""])[0] and "reality" not in vless_config["tls"]:
                    vless_config["tls"]["fingerprint"] = query.get("fp", [""])[0]
                
                if query.get("xver", ["0"])[0] != "0" and "reality" not in vless_config["tls"]:
                    vless_config["tls"]["xver"] = int(query.get("xver", ["0"])[0])


            if transport_config:
                vless_config["transport"] = transport_config

            return vless_config

        else:
            logging.warning(f"不支持的 URL 方案: {scheme} 对于 URL: {proxy_url}")
            return None

    except Exception as e:
        # 记录导致解析失败的原始 URL 及其具体的错误信息
        logging.error(f"解析代理 URL 失败 {proxy_url}: {e}")
        return None

# --- 获取代理列表 ---
def get_proxies():
    """
    从节点源获取代理列表。
    返回一个包含 sing-box 配置格式的字典列表。
    """
    all_singbox_proxies = [] # 这将存储 sing-box 配置对象
    for source in NODES_SOURCES:
        url = source["url"]
        source_type = source["type"]
        logging.info(f"正在从 {url} (类型: {source_type}) 获取代理...")
        try:
            response = requests.get(url, timeout=HTTP_TIMEOUT_SECONDS)
            response.raise_for_status() # 检查 HTTP 请求是否成功

            content = response.text
            if source_type == "base64":
                try:
                    # 对于 Base64 解码，同样去除不规范字符并填充
                    content = re.sub(r'[^a-zA-Z0-9+/=]', '', content)
                    missing_padding = len(content) % 4
                    if missing_padding:
                        content += '=' * (4 - missing_padding)
                    content = base64.b64decode(content).decode('utf-8', errors='replace') # 使用 errors='replace' 处理解码错误
                except Exception as e:
                    logging.error(f"无法解码来自 {url} 的 Base64 内容: {e}")
                    continue
            
            if source_type == "yaml":
                try:
                    yaml_data = yaml.safe_load(content)
                    if isinstance(yaml_data, dict) and "proxies" in yaml_data and isinstance(yaml_data["proxies"], list):
                        for yaml_proxy_dict in yaml_data["proxies"]:
                            singbox_proxy_obj = _convert_yaml_to_singbox_proxy_object(yaml_proxy_dict)
                            if singbox_proxy_obj:
                                all_singbox_proxies.append(singbox_proxy_obj)
                        logging.info(f"成功从 YAML 源 {url} 处理了 {len(yaml_data['proxies'])} 个代理。")
                    else:
                        logging.error(f"来自 {url} 的 YAML 内容不包含有效的 'proxies' 列表。")
                    continue # 已完成 YAML 处理，转到下一个源
                except yaml.YAMLError as e:
                    logging.error(f"无法解析来自 {url} 的 YAML 内容: {e}")
                    continue
                except Exception as e:
                    logging.error(f"处理来自 {url} 的 YAML 时发生意外错误: {e}")
                    continue

            # 对于 'plain' 和其他基于 URL 的类型，直接处理行
            lines = [line.strip() for line in content.splitlines() if line.strip()]
            for line in lines:
                singbox_proxy_obj = parse_proxy_url_string(line)
                if singbox_proxy_obj:
                    all_singbox_proxies.append(singbox_proxy_obj)
            logging.info(f"成功从 {url} 获取了 {len(lines)} 个代理。")

        except requests.exceptions.RequestException as e:
            logging.error(f"无法从 {url} 获取代理: {e}")
        except Exception as e:
            logging.error(f"处理 {url} 时发生意外错误: {e}")

    # 限制代理数量
    return all_singbox_proxies[:MAX_PROXIES]

# --- 生成 sing-box 配置文件 ---
def generate_singbox_config(proxy):
    """生成 sing-box 配置文件"""
    # 移除可能存在的 transport 为 None 的情况，否则会写入 null
    if "transport" in proxy and proxy["transport"] is None:
        del proxy["transport"]
    if "tls" in proxy and proxy["tls"] is None:
        del proxy["tls"]

    config = {
        "log": {
            "level": "debug",
            "output": SINGBOX_LOG_PATH,
        },
        "inbounds": [
            {
                "type": "http",
                "tag": "http-in",
                "listen": "127.0.0.1",
                "listen_port": PROXY_PORT,
            },
        ],
        "outbounds": [
            proxy,
            {
                "type": "direct",
                "tag": "direct",
            },
        ],
        "route": {
            "geoip": {
                "path": GEOIP_DB_PATH,
                "download_url": "https://github.com/SagerNet/sing-box/releases/latest/download/geoip.db",
                "download_detour": "direct",
            },
            "rules": [
                {
                    "domain": ["www.google.com", "www.example.com", "www.cloudflare.com"],
                    "outbound": proxy["tag"],
                },
                {
                    "geoip": ["cn"],
                    "outbound": "direct",
                },
            ],
        },
    }
    with open(SINGBOX_CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=2)
    return SINGBOX_CONFIG_PATH

# --- 等待端口开放 ---
def wait_for_port(host, port, timeout=30, interval=1):
    """等待端口变得可用"""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(interval)
            s.connect((host, port))
            s.close()
            logging.info(f"端口 {port} 已打开!")
            return True
        except (socket.error, ConnectionRefusedError):
            # logging.debug(f"正在等待端口 {port}...") # 避免过多日志
            time.sleep(interval)
    logging.error(f"端口 {port} 在 {timeout} 秒内未打开。")
    return False

# --- 测试代理节点速度 ---
def test_proxy(proxy):
    """测试代理节点速度"""
    process = None
    try:
        config_path = generate_singbox_config(proxy)
        result = subprocess.run([SINGBOX_BIN_PATH, "check", "-c", config_path], capture_output=True, text=True)
        if result.returncode != 0:
            logging.error(f"代理 {proxy['tag']} 的 sing-box 配置无效: {result.stderr.strip()}") # strip 去除多余空白
            return None

        process = subprocess.Popen(
            [SINGBOX_BIN_PATH, "run", "-c", config_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1, # 行缓冲
            universal_newlines=True, # 确保在不同OS下正确处理行尾
        )

        # 启动一个独立的线程来读取 sing-box 的输出并写入日志文件，避免阻塞
        def log_singbox_output():
            for line in iter(process.stdout.readline, ''):
                # 过滤掉 sing-box 启动时的 INFO 级别的繁琐日志，只保留 ERROR/FATAL 或特定关键信息
                if "INFO" not in line or "starting sing-box" in line or "main: configuration loaded" in line or "main: started" in line:
                    with open(SINGBOX_LOG_PATH, "a") as log_f:
                        log_f.write(line)
                
        log_thread = threading.Thread(target=log_singbox_output)
        log_thread.daemon = True  # 守护线程，主程序退出时自动终止
        log_thread.start()

        if not wait_for_port('127.0.0.1', PROXY_PORT, timeout=SINGBOX_STARTUP_TIMEOUT):
            if process.poll() is not None:
                logging.error(f"sing-box 进程提前退出，代理为 {proxy['tag']}。")
            else:
                logging.error(f"sing-box 对于代理 {proxy['tag']} 未能准备就绪。")
            return None

        # 针对每个测试 URL 进行测试
        for test_url in TEST_URLS:
            try:
                start_time = time.time()
                response = requests.get(
                    test_url,
                    proxies={"http": f"http://127.0.0.1:{PROXY_PORT}", "https": f"http://127.0.0.1:{PROXY_PORT}"},
                    timeout=HTTP_TIMEOUT_SECONDS,
                )
                latency = (time.time() - start_time) * 1000
                if response.status_code == 200:
                    logging.info(f"代理 {proxy['tag']} 成功通过 {test_url}, 延迟 {latency:.2f}ms")
                    return {"proxy": proxy, "latency": latency} # 找到一个成功就返回
                else:
                    logging.warning(f"代理 {proxy['tag']} 未能通过 {test_url}, 状态码 {response.status_code}")
            except requests.RequestException as e:
                logging.error(f"代理 {proxy['tag']} 测试 {test_url} 失败: {e}")
        return None # 所有测试 URL 都失败了

    except subprocess.SubprocessError as e:
        logging.error(f"执行 sing-box 时发生子进程错误，代理 {proxy.get('tag', 'unknown')}: {e}")
        return None
    except Exception as e:
        logging.error(f"测试代理 {proxy.get('tag', 'unknown')} 时发生意外错误: {e}")
        return None
    finally:
        if process:
            process.terminate() # 首先尝试优雅终止
            try:
                process.wait(timeout=5) # 给它5秒钟时间终止
            except subprocess.TimeoutExpired:
                logging.warning(f"未能终止代理 {proxy.get('tag', 'unknown')} 的 sing-box 进程，正在强制杀死。")
                process.kill() # 强制杀死
                process.wait(timeout=5) # 再次等待，确保进程完全结束

        # 清理配置文件
        if os.path.exists(SINGBOX_CONFIG_PATH):
            os.remove(SINGBOX_CONFIG_PATH)

# --- 主函数 ---
def main():
    """主函数：获取、测试代理并保存结果"""
    logging.info("开始获取代理节点...")
    proxies_to_test = get_proxies() # 现在这里直接返回 sing-box 对象
    logging.info(f"共获取到 {len(proxies_to_test)} 个代理节点。")

    if not proxies_to_test:
        logging.error("没有找到代理可以测试。")
        return

    results = []
    # 使用 ThreadPoolExecutor 进行并行测试
    # `max_workers` 控制同时运行的代理测试数量
    with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENT_TESTS) as executor:
        # 提交所有代理测试任务
        future_to_proxy = {executor.submit(test_proxy, proxy_obj): proxy_obj for proxy_obj in proxies_to_test}
        
        for future in concurrent.futures.as_completed(future_to_proxy):
            proxy_obj = future_to_proxy[future]
            try:
                result = future.result() # 获取测试结果
                if result:
                    results.append(result)
            except Exception as exc:
                logging.error(f"代理 {proxy_obj.get('tag', 'unknown')} 生成异常: {exc}")

    results.sort(key=lambda x: x["latency"])
    with open(OUTPUT_SUB_FILE, "w") as f:
        for result in results:
            # 对于输出文件，因为现在可能有来自 YAML 的代理，无法保证有原始 URL
            # 统一输出代理的 tag 和 server/port 信息，以及延迟
            proxy_info = f"{result['proxy']['tag']}"
            if 'server' in result['proxy'] and 'server_port' in result['proxy']:
                 proxy_info += f" ({result['proxy']['server']}:{result['proxy']['server_port']})"
            f.write(f"{proxy_info}#{result['latency']:.2f}ms\n")

    logging.info(f"已保存 {len(results)} 个有效代理到 {OUTPUT_SUB_FILE}")
    if len(results) == 0:
        logging.warning("没有找到任何有效的代理节点。")

if __name__ == "__main__":
    main()
