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
SINGBOX_BIN_PATH = "./clash_bin/sing-box"
SINGBOX_CONFIG_PATH = "sing-box-config.json"
SINGBOX_LOG_PATH = os.getenv("SINGBOX_LOG_PATH", "data/sing-box.log")
GEOIP_DB_PATH = "data/geoip.db"
OUTPUT_SUB_FILE = "data/collectSub.txt"

# 节点源配置列表
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

MAX_PROXIES = 25000
TEST_URLS = ["https://www.google.com", "http://www.example.com", "https://www.cloudflare.com"]
HTTP_TIMEOUT_SECONDS = 10
SINGBOX_STARTUP_TIMEOUT = 30
PROXY_PORT = 1080
CONCURRENT_TESTS = 10

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

# --- 新增函数：将 sing-box 代理对象转换回 URL ---
def singbox_to_proxy_url(proxy):
    """将 sing-box 格式的代理对象转换回标准代理 URL"""
    try:
        proxy_type = proxy.get("type")
        tag = proxy.get("tag", f"{proxy_type}-node")
        server = proxy.get("server")
        port = proxy.get("server_port")
        if not server or not port:
            logging.error(f"代理 {tag} 缺少服务器或端口，无法转换为 URL")
            return None

        if proxy_type == "shadowsocks":
            method = proxy.get("method")
            password = proxy.get("password")
            if not method or not password:
                logging.error(f"Shadowsocks 代理 {tag} 缺少加密方法或密码")
                return None
            auth = f"{method}:{password}"
            auth_b64 = base64.b64encode(auth.encode('utf-8')).decode('utf-8')
            hostname = f"[{server}]" if is_valid_ipv6(server) else str(server)
            fragment = urllib.parse.quote(tag)
            return f"ss://{auth_b64}@{hostname}:{port}#{fragment}"

        elif proxy_type == "vmess":
            uuid = proxy.get("uuid")
            security = proxy.get("security", "auto")
            alter_id = proxy.get("alter_id", 0)
            if not uuid:
                logging.error(f"VMess 代理 {tag.va.tag} 缺少 UUID")
                return None
            vmess_data = {
                "v": "1",
                "ps": tag,
                "add": server,
                "port": str(port),
                "id": uuid,
                "scy": security,
                "aid": str(alter_id),
            }
            if proxy.get("tls", {}).get("enabled"):
                vmess_data["tls"] = "tls"
                vmess_data["sni"] = proxy["tls"].get("server_name", server)
                vmess_data["allowInsecure"] = "1" if proxy["tls"].get("insecure") else "0"
            transport = proxy.get("transport", {})
            if transport.get("type") == "ws":
                vmess_data["net"] = "ws"
                vmess_data["path"] = transport.get("path", "")
                vmess_data["host"] = transport.get("headers", {}).get("Host", "")
            vmess_data_b64 = base64.b64encode(json.dumps(vmess_data).encode('utf-8')).decode('utf-8')
            hostname = f"[{server}]" if is_valid_ipv6(server) else str(server)
            return f"vmess://{vmess_data_b64}@{hostname}:{port}#{urllib.parse.quote(tag)}"

        elif proxy_type == "trojan":
            password = proxy.get("password")
            if not password:
                logging.error(f"Trojan 代理 {tag} 缺少密码")
                return None
            hostname = f"[{server}]" if is_valid_ipv6(server) else str(server)
            query_params = {}
            if proxy.get("tls", {}).get("enabled"):
                query_params["sni"] = proxy["tls"].get("server_name", server)
                if proxy["tls"].get("insecure"):
                    query_params["allowInsecure"] = "1"
            transport = proxy.get("transport", {})
            if transport.get("type") == "ws":
                query_params["type"] = "ws"
                query_params["path"] = transport.get("path", "/")
                query_params["host"] = transport.get("headers", {}).get("Host", "")
            query_string = urllib.parse.urlencode(query_params)
            fragment = urllib.parse.quote(tag)
            return f"trojan://{password}@{hostname}:{port}{'' if not query_string else '?' + query_string}#{fragment}"

        elif proxy_type == "hysteria2":
            password = proxy.get("password")
            if not password:
                logging.error(f"Hysteria2 代理 {tag} 缺少密码")
                return None
            hostname = f"[{server}]" if is_valid_ipv6(server) else str(server)
            query_params = {}
            if proxy.get("tls", {}).get("enabled"):
                query_params["sni"] = proxy["tls"].get("server_name", server)
                if proxy["tls"].get("insecure"):
                    query_params["insecure"] = "1"
            obfs = proxy.get("obfs", {})
            if obfs.get("type") and obfs.get("password"):
                query_params["obfs"] = obfs["type"]
                query_params["obfs-password"] = obfs["password"]
            query_string = urllib.parse.urlencode(query_params)
            fragment = urllib.parse.quote(tag)
            return f"hy2://{password}@{hostname}:{port}{'' if not query_string else '?' + query_string}#{fragment}"

        elif proxy_type == "vless":
            uuid = proxy.get("uuid")
            if not uuid:
                logging.error(f"VLESS 代理 {tag} 缺少 UUID")
                return None
            hostname = f"[{server}]" if is_valid_ipv6(server) else str(server)
            query_params = {}
            if proxy.get("flow"):
                query_params["flow"] = proxy["flow"]
            if proxy.get("tls", {}).get("enabled"):
                query_params["security"] = "tls"
                query_params["sni"] = proxy["tls"].get("server_name", server)
                if proxy["tls"].get("insecure"):
                    query_params["insecure"] = "1"
                if proxy["tls"].get("reality"):
                    query_params["security"] = "reality"
                    query_params["pbk"] = proxy["tls"]["reality"].get("public_key")
                    query_params["sid"] = proxy["tls"]["reality"].get("short_id")
                    query_params["fp"] = proxy["tls"]["reality"].get("server_name", server)
            transport = proxy.get("transport", {})
            if transport.get("type") == "ws":
                query_params["type"] = "ws"
                query_params["path"] = transport.get("path", "/")
                query_params["host"] = transport.get("headers", {}).get("Host", "")
            elif transport.get("type") == "grpc":
                query_params["type"] = "grpc"
                query_params["serviceName"] = transport.get("service_name", "")
            query_string = urllib.parse.urlencode(query_params)
            fragment = urllib.parse.quote(tag)
            return f"vless://{uuid}@{hostname}:{port}{'' if not query_string else '?' + query_string}#{fragment}"

        else:
            logging.warning(f"不支持的代理类型 {proxy_type}，无法转换为 URL")
            return None

    except Exception as e:
        logging.error(f"转换代理 {tag} 为 URL 失败: {e}")
        return None

# --- 核心函数：将 YAML 代理字典转换为 sing-box 配置格式 ---
def _convert_yaml_to_singbox_proxy_object(yaml_proxy_dict):
    p_type = yaml_proxy_dict.get("type")
    tag = yaml_proxy_dict.get("name", f"{p_type}-node")
    server = yaml_proxy_dict.get("server")
    port = yaml_proxy_dict.get("port")

    if not server or not port:
        logging.error(f"YAML代理中缺少服务器或端口，跳过: {yaml_proxy_dict}")
        return None

    outbound = {
        "type": p_type,
        "tag": tag,
        "server": server,
        "server_port": int(port),
    }

    tls_enabled = yaml_proxy_dict.get("tls", False) or yaml_proxy_dict.get("network") in ["ws", "grpc"]
    if tls_enabled:
        outbound["tls"] = {
            "enabled": True,
            "server_name": yaml_proxy_dict.get("sni", server),
            "insecure": yaml_proxy_dict.get("skip-cert-verify", False),
        }

    transport_type = yaml_proxy_dict.get("network")
    if transport_type == "ws":
        outbound["transport"] = {
            "type": "ws",
            "path": yaml_proxy_dict.get("ws-path", "/"),
            "headers": {"Host": yaml_proxy_dict.get("ws-headers", {}).get("Host", server)}
        }

    if p_type == "ss":
        outbound["method"] = yaml_proxy_dict.get("cipher")
        outbound["password"] = yaml_proxy_dict.get("password")
    elif p_type == "trojan":
        outbound["password"] = yaml_proxy_dict.get("password")
    elif p_type == "vmess":
        outbound["uuid"] = yaml_proxy_dict.get("uuid")
        outbound["security"] = yaml_proxy_dict.get("cipher", "auto")
        outbound["alter_id"] = int(yaml_proxy_dict.get("alterId", 0))
        vmess_network_type = yaml_proxy_dict.get("network")
        if vmess_network_type not in ["tcp", "", None]:
            outbound["transport"] = {"type": vmess_network_type}
            if vmess_network_type == "ws":
                outbound["transport"]["path"] = yaml_proxy_dict.get("ws-path", "")
                outbound["transport"]["headers"] = {"Host": yaml_proxy_dict.get("ws-headers", {}).get("Host", "")}
        if yaml_proxy_dict.get("tls", False):
            outbound["tls"] = {
                "enabled": True,
                "server_name": yaml_proxy_dict.get("sni", server),
                "insecure": yaml_proxy_dict.get("skip-cert-verify", False)
            }
    elif p_type == "hysteria2":
        outbound["password"] = yaml_proxy_dict.get("password")
        if "obfs" in yaml_proxy_dict:
            outbound["obfs"] = {
                "type": yaml_proxy_dict["obfs"],
                "password": yaml_proxy_dict.get("obfs-password")
            }
    elif p_type == "vless":
        outbound["uuid"] = yaml_proxy_dict.get("uuid")
        outbound["flow"] = yaml_proxy_dict.get("flow")
        if tls_enabled:
            tls_obj = outbound.get("tls", {"enabled": True})
            if yaml_proxy_dict.get("security") == "reality":
                tls_obj["reality"] = {
                    "enabled": True,
                    "public_key": yaml_proxy_dict.get("public-key"),
                    "short_id": yaml_proxy_dict.get("short-id"),
                    "server_name": yaml_proxy_dict.get("sni", server),
                    "fingerprint": yaml_proxy_dict.get("fingerprint")
                }
                if not tls_obj["reality"].get("public_key") or not tls_obj["reality"].get("short_id"):
                    logging.error(f"YAML VLESS Reality 代理缺少必要的 public_key 或 short_id，跳过: {yaml_proxy_dict.get('name')}")
                    return None
            outbound["tls"] = tls_obj
            if "fingerprint" in yaml_proxy_dict and "reality" not in outbound["tls"]:
                outbound["tls"]["fingerprint"] = yaml_proxy_dict["fingerprint"]
            if "xver" in yaml_proxy_dict:
                outbound["tls"]["xver"] = int(yaml_proxy_dict["xver"])

    return outbound

# --- 核心函数：解析代理 URL 字符串并转换为 sing-box 配置格式 ---
def parse_proxy_url_string(proxy_url):
    known_schemes = ("ss://", "vmess://", "trojan://", "hy2://", "vless://")
    if not proxy_url.startswith(known_schemes):
        logging.debug(f"跳过非代理 URL 格式的行: {proxy_url[:50]}...")
        return None

    try:
        parsed = urllib.parse.urlparse(proxy_url)
        scheme = parsed.scheme
        if not scheme or not parsed.netloc:
            logging.error(f"无效或不完整的 URL 格式，跳过: {proxy_url}")
            return None

        if scheme == "vmess":
            vmess_data_str = parsed.netloc
            vmess_data_str = re.sub(r'[^a-zA-Z0-9+/=]', '', vmess_data_str)
            missing_padding = len(vmess_data_str) % 4
            if missing_padding:
                vmess_data_str += '=' * (4 - missing_padding)
            
            try:
                vmess_decoded_bytes = base64.b64decode(vmess_data_str)
            except base64.binascii.Error as e:
                logging.error(f"VMess Base64 解码失败 for {proxy_url}: {e}")
                return None
            
            try:
                vmess_data = json.loads(vmess_decoded_bytes.decode('utf-8'))
            except UnicodeDecodeError:
                vmess_data = json.loads(vmess_decoded_bytes.decode('utf-8', errors='replace'))
            except json.JSONDecodeError as e:
                logging.error(f"VMess JSON 解码失败 for {proxy_url}: {e}")
                return None

            transport_type = vmess_data.get("net", "tcp")
            transport_config = None
            if transport_type == "ws":
                transport_config = {
                    "type": transport_type,
                    "path": vmess_data.get("path", ""),
                    "headers": {"Host": vmess_data.get("host", "")} if vmess_data.get("host") else {}
                }

            vmess_outbound = {
                "type": "vmess",
                "tag": vmess_data.get("ps", "vmess-node"),
                "server": vmess_data.get("add"),
                "server_port": int(vmess_data.get("port")),
                "uuid": vmess_data.get("id"),
                "security": vmess_data.get("scy", "auto"),
                "alter_id": int(vmess_data.get("aid", 0)),
            }
            if transport_config:
                vmess_outbound["transport"] = transport_config
            if vmess_data.get("tls") == "tls":
                vmess_outbound["tls"] = {
                    "enabled": True,
                    "server_name": vmess_data.get("sni", vmess_data.get("add")),
                    "insecure": vmess_data.get("allowInsecure", "0") == "1",
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
            if "@" in parsed.netloc:
                auth, addr = parsed.netloc.split("@")
                auth_str = re.sub(r'[^a-zA-Z0-9+/=]', '', auth)
                missing_padding = len(auth_str) % 4
                if missing_padding:
                    auth_str += '=' * (4 - missing_padding)
                try:
                    method_password = base64.b64decode(auth_str).decode('utf-8', errors='replace')
                    method, password = method_password.split(":", 1)
                except (base64.binascii.Error, ValueError, UnicodeDecodeError) as e:
                    logging.error(f"Shadowsocks Base64 解码或解析失败 for {proxy_url}: {e}")
                    return None
                hostname_parts = addr.split(':')
                hostname = ':'.join(hostname_parts[:-1])
                port = hostname_parts[-1]
            else:
                method_password_str = parsed.netloc
                method_password_str = re.sub(r'[^a-zA-Z0-9+/=]', '', method_password_str)
                missing_padding = len(method_password_str) % 4
                if missing_padding:
                    method_password_str += '=' * (4 - missing_padding)
                try:
                    method_password = base64.b64decode(method_password_str).decode('utf-8', errors='replace')
                    method, password = method_password.split(":", 1)
                except (base64.binascii.Error, ValueError, UnicodeDecodeError) as e:
                    logging.error(f"Shadowsocks Base64 解码或解析失败 for {proxy_url}: {e}")
                    return None
                path_parts = parsed.path.lstrip("/").split(":")
                if len(path_parts) > 1:
                    hostname = ':'.join(path_parts[:-1])
                    port = path_parts[-1]
                else:
                    hostname = path_parts[0]
                    port = 443
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
                if query.get("security", [""])[0] == "reality":
                    pbk = query.get("pbk", [""])[0]
                    sid = query.get("sid", [""])[0]
                    if not pbk or not sid:
                        logging.error(f"VLESS Reality 代理缺少必要的 public_key 或 short_id，跳过: {proxy_url}")
                        return None
                    vless_config["tls"]["reality"] = {
                        "enabled": True,
                        "public_key": pbk,
                        "short_id": sid,
                        "server_name": query.get("fp", [""])[0],
                    }
                    if query.get("sni", [""])[0]:
                        vless_config["tls"]["reality"]["server_name"] = query.get("sni", [""])[0]
                    elif hostname.strip("[]"):
                        vless_config["tls"]["reality"]["server_name"] = hostname.strip("[]")
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
        logging.error(f"解析代理 URL 失败 {proxy_url}: {e}")
        return None

# --- 获取代理列表 ---
def get_proxies():
    all_singbox_proxies = []
    for source in NODES_SOURCES:
        url = source["url"]
        source_type = source["type"]
        logging.info(f"正在从 {url} (类型: {source_type}) 获取代理...")
        try:
            response = requests.get(url, timeout=HTTP_TIMEOUT_SECONDS)
            response.raise_for_status()
            content = response.text
            if source_type == "base64":
                try:
                    content = re.sub(r'[^a-zA-Z0-9+/=]', '', content)
                    missing_padding = len(content) % 4
                    if missing_padding:
                        content += '=' * (4 - missing_padding)
                    content = base64.b64decode(content).decode('utf-8', errors='replace')
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
                    continue
                except yaml.YAMLError as e:
                    logging.error(f"无法解析来自 {url} 的 YAML 内容: {e}")
                    continue
                except Exception as e:
                    logging.error(f"处理来自 {url} 的 YAML 时发生意外错误: {e}")
                    continue
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
    return all_singbox_proxies[:MAX_PROXIES]

# --- 生成 sing-box 配置文件 ---
def generate_singbox_config(proxy):
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
            time.sleep(interval)
    logging.error(f"端口 {port} 在 {timeout} 秒内未打开。")
    return False

# --- 测试代理节点速度 ---
def test_proxy(proxy):
    process = None
    try:
        config_path = generate_singbox_config(proxy)
        result = subprocess.run([SINGBOX_BIN_PATH, "check", "-c", config_path], capture_output=True, text=True)
        if result.returncode != 0:
            logging.error(f"代理 {proxy['tag']} 的 sing-box 配置无效: {result.stderr.strip()}")
            return None
        process = subprocess.Popen(
            [SINGBOX_BIN_PATH, "run", "-c", config_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True,
        )
        def log_singbox_output():
            for line in iter(process.stdout.readline, ''):
                if "INFO" not in line or "starting sing-box" in line or "main: configuration loaded" in line or "main: started" in line:
                    with open(SINGBOX_LOG_PATH, "a") as log_f:
                        log_f.write(line)
        log_thread = threading.Thread(target=log_singbox_output)
        log_thread.daemon = True
        log_thread.start()
        if not wait_for_port('127.0.0.1', PROXY_PORT, timeout=SINGBOX_STARTUP_TIMEOUT):
            if process.poll() is not None:
                logging.error(f"sing-box 进程提前退出，代理为 {proxy['tag']}。")
            else:
                logging.error(f"sing-box 对于代理 {proxy['tag']} 未能准备就绪。")
            return None
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
                    return {"proxy": proxy, "latency": latency}
                else:
                    logging.warning(f"代理 {proxy['tag']} 未能通过 {test_url}, 状态码 {response.status_code}")
            except requests.RequestException as e:
                logging.error(f"代理 {proxy['tag']} 测试 {test_url} 失败: {e}")
        return None
    except subprocess.SubprocessError as e:
        logging.error(f"执行 sing-box 时发生子进程错误，代理 {proxy.get('tag', 'unknown')}: {e}")
        return None
    except Exception as e:
        logging.error(f"测试代理 {proxy.get('tag', 'unknown')} 时发生意外错误: {e}")
        return None
    finally:
        if process:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                logging.warning(f"未能终止代理 {proxy.get('tag', 'unknown')} 的 sing-box 进程，正在强制杀死。")
                process.kill()
                process.wait(timeout=5)
        if os.path.exists(SINGBOX_CONFIG_PATH):
            os.remove(SINGBOX_CONFIG_PATH)

# --- 主函数 ---
def main():
    logging.info("开始获取代理节点...")
    proxies_to_test = get_proxies()
    logging.info(f"共获取到 {len(proxies_to_test)} 个代理节点。")
    if not proxies_to_test:
        logging.error("没有找到代理可以测试。")
        return
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENT_TESTS) as executor:
        future_to_proxy = {executor.submit(test_proxy, proxy_obj): proxy_obj for proxy_obj in proxies_to_test}
        for future in concurrent.futures.as_completed(future_to_proxy):
            proxy_obj = future_to_proxy[future]
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as exc:
                logging.error(f"代理 {proxy_obj.get('tag', 'unknown')} 生成异常: {exc}")
    results.sort(key=lambda x: x["latency"])
    proxy_urls = []
    for result in results:
        proxy_url = singbox_to_proxy_url(result["proxy"])
        if proxy_url:
            proxy_urls.append(f"{proxy_url}#{result['latency']:.2f}ms")
    if proxy_urls:
        content = "\n".join(proxy_urls)
        content_b64 = base64.b64encode(content.encode('utf-8')).decode('utf-8')
        with open(OUTPUT_SUB_FILE, "w") as f:
            f.write(content_b64)
    logging.info(f"已保存 {len(results)} 个有效代理到 {OUTPUT_SUB_FILE} (Base64 编码)")
    if len(results) == 0:
        logging.warning("没有找到任何有效的代理节点。")

if __name__ == "__main__":
    main()
