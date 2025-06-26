import asyncio
import json
import logging
import random
import shutil
import socket
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
import base64
import urllib.parse
import aiohttp
import binascii
import os
import yaml
import re
import sys

# 确保 Python 版本为 3.7 或更高
if sys.version_info < (3, 7):
    raise RuntimeError("此脚本需要 Python 3.7 或更高版本")

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 常量
OUTPUT_FILE_PATH = "data/all.txt"
FAILED_NODES_FILE = "data/failed_nodes.txt"
CLASH_PATH = os.getenv("CLASH_CORE_PATH", "./clash")
TEST_URLS = [
    "https://www.google.com",
    "https://www.youtube.com",
    "https://www.cloudflare.com",
    "https://api.github.com",
]
BATCH_SIZE = 500
MAX_CONCURRENT = 10
TIMEOUT = 2
CLASH_BASE_CONFIG_URLS = [
    "https://snippet.host/oouyda/raw",
]

# 全局变量
GLOBAL_CLASH_CONFIG_TEMPLATE: Optional[Dict[str, Any]] = None

def load_failed_nodes(file_path: Path) -> Set[str]:
    """从文件中加载已知的无效节点名称"""
    if not file_path.exists():
        return set()
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return {line.strip() for line in f if line.strip()}
    except Exception as e:
        logger.error(f"加载无效节点文件 {file_path} 失败: {e}")
        return set()

def save_failed_node(file_path: Path, node_name: str):
    """将无效节点名称保存到文件"""
    try:
        with open(file_path, "a", encoding="utf-8") as f:
            f.write(f"{node_name}\n")
    except Exception as e:
        logger.error(f"保存无效节点 {node_name} 到文件 {file_path} 失败: {e}")


async def fetch_clash_base_config(url: str) -> Optional[Dict[str, Any]]:
    """从指定 URL 下载并解析 Clash 配置文件"""
    async with aiohttp.ClientSession() as session:
        try:
            logger.info(f"正在从 {url} 下载 Clash 配置...")
            async with session.get(url, timeout=10) as response:
                response.raise_for_status()
                content = await response.text()
                logger.info(f"成功从 {url} 下载配置")
                return yaml.safe_load(content)
        except aiohttp.ClientError as e:
            logger.error(f"下载 Clash 配置失败 ({url}): {e}")
            return None
        except yaml.YAMLError as e:
            logger.error(f"解析 YAML 失败 ({url}): {e}")
            return None
        except asyncio.TimeoutError:
            logger.error(f"下载 Clash 配置超时 ({url})")
            return None
        except Exception as e:
            logger.error(f"下载或解析 Clash 配置时发生未知错误 ({url}): {e}")
            return None

async def fetch_all_configs(urls: List[str]) -> List[Dict[str, Any]]:
    """从多个 URL 获取代理节点，合并并去重"""
    nodes: List[Dict[str, Any]] = []
    seen_nodes = set()

    for url in urls:
        config = await fetch_clash_base_config(url)
        if config is None:
            logger.warning(f"无法从 {url} 获取节点，跳过")
            continue

        proxies = config.get("proxies", [])
        if not proxies:
            logger.warning(f"从 {url} 获取的配置中没有 proxies 列表")
            continue

        for proxy in proxies:
            # 确保 proxy 是字典类型
            if not isinstance(proxy, dict):
                logger.warning(f"跳过非字典类型的代理条目: {proxy}")
                continue

            unique_key = (
                proxy.get("server", ""),
                proxy.get("port", 0),
                proxy.get("cipher", ""),
                proxy.get("password", ""),
                proxy.get("type", "")
            )
            if unique_key in seen_nodes:
                logger.debug(f"跳过重复节点: {proxy.get('name', '未知')}")
                continue
            seen_nodes.add(unique_key)
            nodes.append(proxy)

        logger.info(f"从 {url} 获取 {len(proxies)} 个节点，合并后总计 {len(nodes)} 个唯一节点")

    return nodes

async def parse_shadowsocks(url: str) -> Optional[Dict[str, Any]]:
    """解析 Shadowsocks 链接，返回 Clash 代理配置"""
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "ss":
            return None

        if "@" not in parsed.netloc:
            logger.warning(f"SS 链接格式无效（缺少@）: {url}")
            return None

        credentials_b64, server_info = parsed.netloc.split("@", 1)
        server, port_str = server_info.split(":", 1)
        port = int(port_str.split("?")[0])

        method = ""
        password = ""

        try:
            decoded_credentials = base64.b64decode(credentials_b64).decode("utf-8")
            if ":" in decoded_credentials:
                method, password = decoded_credentials.split(":", 1)
            else:
                logger.warning(f"SS 链接凭据格式异常（无冒号），尝试作为 SS 2022 处理: {url}")
                key_bytes = base64.b64decode(credentials_b64)
                if len(key_bytes) == 16:
                    method = "2022-blake3-aes-128-gcm"
                elif len(key_bytes) == 32:
                    method = "2022-blake3-aes-256-gcm"
                else:
                    logger.warning(f"SS 链接凭据长度无效 ({len(key_bytes)} 字节)，跳过: {url}")
                    return None
                password = base64.b64encode(key_bytes).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            try:
                key_bytes = base64.b64decode(credentials_b64)
                if len(key_bytes) == 16:
                    method = "2022-blake3-aes-128-gcm"
                elif len(key_bytes) == 32:
                    method = "2022-blake3-aes-256-gcm"
                else:
                    logger.warning(f"SS 链接凭据长度无效 ({len(key_bytes)} 字节)，跳过: {url}")
                    return None
                password = base64.b64encode(key_bytes).decode("utf-8")
            except binascii.Error as e:
                logger.warning(f"解析 SS 链接凭据失败: {url}, 错误: {e}")
                return None

        query_params = urllib.parse.parse_qs(parsed.query)
        # 获取节点名称，如果 # 后有内容则作为名称，否则生成默认名称
        node_name_from_hash = urllib.parse.unquote(parsed.fragment) if parsed.fragment else None

        proxy_config = {
            "name": node_name_from_hash if node_name_from_hash else f"ss-{server}-{port}",
            "type": "ss",
            "server": server,
            "port": port,
            "cipher": method,
            "password": password,
        }

        plugin = query_params.get("plugin", [None])[0]
        plugin_opts = query_params.get("plugin_opts", [None])[0]

        if plugin:
            if plugin in ("obfs-local", "simple-obfs"):
                if "obfs=http" in plugin_opts:
                    proxy_config["plugin"] = "obfs"
                    proxy_config["plugin-opts"] = {"mode": "http"}
                    host = re.search(r"obfs-host=([^;]+)", plugin_opts)
                    if host:
                        proxy_config["plugin-opts"]["host"] = host.group(1)
                elif "obfs=tls" in plugin_opts:
                    proxy_config["plugin"] = "obfs"
                    proxy_config["plugin-opts"] = {"mode": "tls"}
                    host = re.search(r"obfs-host=([^;]+)", plugin_opts)
                    if host:
                        proxy_config["plugin-opts"]["host"] = host.group(1)
                else:
                    logger.warning(f"SS 链接: 未知或不支持的 obfs 插件模式: {plugin_opts}, 继续测试: {url}")
            elif plugin == "v2ray-plugin":
                logger.warning(f"SS 链接: v2ray-plugin 支持不完整，继续测试: {url}")
                proxy_config["plugin"] = "v2ray-plugin"
                proxy_config["plugin-opts"] = {"mode": "websocket"}
                if "tls" in plugin_opts:
                    proxy_config["plugin-opts"]["tls"] = True
                if "host" in plugin_opts:
                    host = re.search(r"host=([^;]+)", plugin_opts)
                    if host:
                        proxy_config["plugin-opts"]["host"] = host.group(1)
            else:
                logger.warning(f"SS 链接: 未知插件类型: {plugin}, 继续测试: {url}")

        return proxy_config
    except Exception as e:
        logger.warning(f"解析 SS 链接失败: {url}, 错误: {e}")
        return None

async def parse_hysteria2(url: str) -> Optional[Dict[str, Any]]:
    """解析 Hysteria2 链接，返回 Clash 代理配置"""
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "hy2" and parsed.scheme != "hysteria2": # 支持 hy2 和 hysteria2
            return None

        uuid_and_server_info = parsed.netloc
        if "@" not in uuid_and_server_info:
            logger.warning(f"Hysteria2 链接格式无效（缺少@）: {url}")
            return None

        uuid_str, server_port_info = uuid_and_server_info.split("@", 1)
        server, port_str = server_port_info.split(":", 1)
        port = int(port_str)

        query_params = urllib.parse.parse_qs(parsed.query)

        password = query_params.get("password", [uuid_str])[0]
        if "password" in query_params:
            password = query_params["password"][0]

        insecure = query_params.get("insecure", ["0"])[0].lower() == "1"
        sni = query_params.get("sni", [server])[0]
        alpn_str = query_params.get("alpn", ["h3"])[0]
        alpn = [alpn_str] if isinstance(alpn_str, str) else alpn_str

        obfs = query_params.get("obfs", [None])[0]
        obfs_password = query_params.get("obfs-password", [None])[0]

        # 获取节点名称，如果 # 后有内容则作为名称，否则生成默认名称
        node_name_from_hash = urllib.parse.unquote(parsed.fragment) if parsed.fragment else None

        proxy_config = {
            "name": node_name_from_hash if node_name_from_hash else f"hysteria2-{server}-{port}",
            "type": "hysteria2",
            "server": server,
            "port": port,
            "password": password,
            "tls": True,
            "skip-cert-verify": insecure,
            "sni": sni,
            "alpn": alpn,
        }

        if obfs == "salamander" and obfs_password:
            proxy_config["obfs"] = "salamander"
            proxy_config["obfs-password"] = obfs_password
        elif obfs and obfs != "none":
            logger.warning(f"Hysteria2 链接中不支持的混淆类型: {obfs}, 继续测试: {url}")

        return proxy_config
    except Exception as e:
        logger.warning(f"解析 Hysteria2 链接失败: {url}, 错误: {e}")
        return None

async def parse_trojan(url: str) -> Optional[Dict[str, Any]]:
    """解析 Trojan 链接，返回 Clash 代理配置"""
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "trojan":
            return None

        password_and_server_info = parsed.netloc
        if "@" not in password_and_server_info:
            logger.warning(f"Trojan 链接格式无效（缺少@）: {url}")
            return None

        password, server_port_info = password_and_server_info.split("@", 1)
        server, port_str = server_port_info.split(":", 1)
        port = int(port_str)

        query_params = urllib.parse.parse_qs(parsed.query)

        sni = query_params.get("sni", [server])[0]
        alpn = query_params.get("alpn", [])
        if alpn:
            alpn = alpn[0].split(',') # alpn 可能有多个值，用逗号分隔
        else:
            alpn = None
        
        # 允许不安全的TLS
        allow_insecure = query_params.get("allowInsecure", ["0"])[0].lower() == "1"

        # 获取节点名称，如果 # 后有内容则作为名称，否则生成默认名称
        node_name_from_hash = urllib.parse.unquote(parsed.fragment) if parsed.fragment else None

        proxy_config = {
            "name": node_name_from_hash if node_name_from_hash else f"trojan-{server}-{port}",
            "type": "trojan",
            "server": server,
            "port": port,
            "password": urllib.parse.unquote(password), # 解码密码中的特殊字符
            "tls": True,
            "skip-cert-verify": allow_insecure,
            "sni": sni,
        }
        if alpn:
            proxy_config["alpn"] = alpn

        # 处理 WebSocket
        if query_params.get("type", ["tcp"])[0] == "ws":
            proxy_config["network"] = "ws"
            ws_opts = {}
            if "path" in query_params:
                ws_opts["path"] = query_params["path"][0]
            if "host" in query_params:
                ws_opts["headers"] = {"Host": query_params["host"][0]}
            if ws_opts:
                proxy_config["ws-opts"] = ws_opts

        # Clash 的 Trojan 不直接支持 flow
        if "flow" in query_params:
            logger.warning(f"Trojan 链接: Clash 不直接支持 flow 参数，跳过: {url}")

        return proxy_config
    except Exception as e:
        logger.warning(f"解析 Trojan 链接失败: {url}, 错误: {e}")
        return None

async def parse_vmess(url: str) -> Optional[Dict[str, Any]]:
    """解析 Vmess 链接，返回 Clash 代理配置"""
    try:
        if not url.startswith("vmess://"):
            return None
        
        encoded_json = url[len("vmess://"):]
        decoded_json_bytes = base64.b64decode(encoded_json)
        decoded_json = decoded_json_bytes.decode("utf-8")
        vmess_data = json.loads(decoded_json)

        server = vmess_data.get("add")
        port = int(vmess_data.get("port"))
        uuid = vmess_data.get("id")
        alterId = int(vmess_data.get("aid", 0))
        cipher = vmess_data.get("scy", "auto") # 尝试获取加密方式
        
        # 获取节点名称，优先使用 ps 字段
        node_name = vmess_data.get("ps", f"vmess-{server}-{port}")

        proxy_config = {
            "name": node_name,
            "type": "vmess",
            "server": server,
            "port": port,
            "uuid": uuid,
            "alterId": alterId,
            "cipher": cipher,
        }

        # 处理 TLS
        if vmess_data.get("tls") == "tls":
            proxy_config["tls"] = True
            if vmess_data.get("sni"):
                proxy_config["servername"] = vmess_data["sni"]
            if vmess_data.get("allowInsecure", "0") == "1":
                proxy_config["skip-cert-verify"] = True

        # 处理网络类型 (network)
        network = vmess_data.get("net")
        if network:
            proxy_config["network"] = network
            if network == "ws":
                ws_opts = {}
                if "path" in vmess_data:
                    ws_opts["path"] = vmess_data["path"]
                if "host" in vmess_data:
                    ws_opts["headers"] = {"Host": vmess_data["host"]}
                if ws_opts:
                    proxy_config["ws-opts"] = ws_opts
            elif network == "grpc":
                grpc_opts = {}
                if "serviceName" in vmess_data:
                    grpc_opts["serviceName"] = vmess_data["serviceName"]
                if grpc_opts:
                    proxy_config["grpc-opts"] = grpc_opts
            else:
                logger.warning(f"VMess 链接: 不支持的网络类型: {network}, 继续测试: {url}")

        return proxy_config
    except (json.JSONDecodeError, binascii.Error, UnicodeDecodeError) as e:
        logger.warning(f"解析 VMess 链接 JSON/Base64 失败: {url}, 错误: {e}")
        return None
    except Exception as e:
        logger.warning(f"解析 VMess 链接失败: {url}, 错误: {e}")
        return None

async def parse_vless(url: str) -> Optional[Dict[str, Any]]:
    """解析 VLESS 链接，返回 Clash 代理配置"""
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "vless":
            return None

        # VLESS 链接通常是 uuid@server:port
        uuid_and_server_info = parsed.netloc
        if "@" not in uuid_and_server_info:
            logger.warning(f"VLESS 链接格式无效（缺少@）: {url}")
            return None

        uuid_str, server_port_info = uuid_and_server_info.split("@", 1)
        server, port_str = server_port_info.split(":", 1)
        port = int(port_str)

        query_params = urllib.parse.parse_qs(parsed.query)

        # 获取节点名称，如果 # 后有内容则作为名称，否则生成默认名称
        node_name_from_hash = urllib.parse.unquote(parsed.fragment) if parsed.fragment else None

        proxy_config = {
            "name": node_name_from_hash if node_name_from_hash else f"vless-{server}-{port}",
            "type": "vless",
            "server": server,
            "port": port,
            "uuid": uuid_str,
            "tls": query_params.get("security", [""])[0] == "tls",
        }

        if proxy_config["tls"]:
            if "sni" in query_params:
                proxy_config["servername"] = query_params["sni"][0]
            if query_params.get("allowInsecure", ["0"])[0].lower() == "1":
                proxy_config["skip-cert-verify"] = True
            
            # Reality (XTLS-rprx-vision)
            if query_params.get("flow") == "xtls-rprx-vision":
                proxy_config["flow"] = "xtls-rprx-vision"
                if "reality-opts" in query_params: # Clash 不直接支持 reality-opts 字段，但可以尝试解析其中的 sni 和 fp
                    reality_opts_str = query_params["reality-opts"][0]
                    # 这里需要更复杂的解析，因为 reality-opts 是一个URL编码的JSON字符串或者类似的格式
                    # 考虑到通用性，Clash 对 Reality 的支持主要依赖于 flow 和 sni
                    # 如果有新的Clash版本支持更详细的reality-opts，再补充
                    logger.warning(f"VLESS 链接: reality-opts 字段可能不支持或需要手动配置: {reality_opts_str}")


        # 处理网络类型 (network)
        network = query_params.get("type", ["tcp"])[0]
        if network:
            proxy_config["network"] = network
            if network == "ws":
                ws_opts = {}
                if "path" in query_params:
                    ws_opts["path"] = query_params["path"][0]
                if "host" in query_params:
                    ws_opts["headers"] = {"Host": query_params["host"][0]}
                if ws_opts:
                    proxy_config["ws-opts"] = ws_opts
            elif network == "grpc":
                grpc_opts = {}
                if "serviceName" in query_params:
                    grpc_opts["serviceName"] = query_params["serviceName"][0]
                if grpc_opts:
                    proxy_config["grpc-opts"] = grpc_opts
            else:
                logger.warning(f"VLESS 链接: 不支持的网络类型: {network}, 继续测试: {url}")

        return proxy_config
    except Exception as e:
        logger.warning(f"解析 VLESS 链接失败: {url}, 错误: {e}")
        return None

async def parse_plain_text_node(link: str) -> Optional[Dict[str, Any]]:
    """根据链接前缀，调用相应的解析函数"""
    link = link.strip()
    if link.startswith("ss://"):
        return await parse_shadowsocks(link)
    elif link.startswith("hysteria2://") or link.startswith("hy2://"):
        return await parse_hysteria2(link)
    elif link.startswith("trojan://"):
        return await parse_trojan(link)
    elif link.startswith("vmess://"):
        return await parse_vmess(link)
    elif link.startswith("vless://"):
        return await parse_vless(link)
    else:
        logger.warning(f"不支持的明文链接类型: {link}")
        return None


def validate_proxy_entry(proxy_entry: Dict[str, Any]) -> bool:
    """验证代理节点格式是否符合 Clash 要求"""
    supported_protocols = ["ss", "vmess", "hysteria2", "vless", "trojan"]
    # 扩大支持的加密方式列表，以包含 SS 2022
    supported_ciphers = [
        "chacha20-ietf-poly1305", "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
        "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
        "none" # 某些协议可能加密方式为none
    ]
    try:
        if not isinstance(proxy_entry, dict):
            raise ValueError("代理节点必须为字典格式")

        if "type" not in proxy_entry:
            raise ValueError("代理节点缺少 'type' 字段")

        if proxy_entry["type"] not in supported_protocols:
            logger.warning(f"不支持的代理协议类型: {proxy_entry['type']}. 支持的协议: {supported_protocols}, 继续测试")
            return True

        if "name" not in proxy_entry:
            proxy_entry["name"] = f"{proxy_entry['type']}-{proxy_entry.get('server', 'unknown')}-{proxy_entry.get('port', '0')}"
            logger.warning(f"代理节点缺少 'name' 字段，已生成: {proxy_entry['name']}")

        if "server" not in proxy_entry:
            raise ValueError("代理节点缺少 'server' 字段")

        if "port" not in proxy_entry:
            raise ValueError("代理节点缺少 'port' 字段")

        if proxy_entry["server"] == "1.1.1.1" and proxy_entry["port"] == 1:
            logger.warning(f"跳过无效节点: {proxy_entry['name']}")
            return False

        if proxy_entry["type"] == "ss":
            if "cipher" not in proxy_entry or "password" not in proxy_entry:
                raise ValueError("Shadowsocks 节点缺少 'cipher' 或 'password' 字段")
            if proxy_entry["cipher"] not in supported_ciphers:
                logger.warning(f"不支持的 Shadowsocks 加密方式: {proxy_entry['cipher']}. 支持的加密方式: {supported_ciphers}, 继续测试")
                return True
        elif proxy_entry["type"] == "vmess":
            if "uuid" not in proxy_entry or "cipher" not in proxy_entry:
                raise ValueError("VMess 节点缺少 'uuid' 或 'cipher' 字段")
            if proxy_entry.get("network") == "ws" and "ws-opts" not in proxy_entry:
                logger.warning(f"VMess WebSocket 节点缺少 'ws-opts' 字段，继续测试")
                return True
        elif proxy_entry["type"] == "hysteria2":
            if "password" not in proxy_entry and "auth" not in proxy_entry:
                raise ValueError("Hysteria2 节点缺少 'password' 或 'auth' 字段")
            if proxy_entry.get("obfs") and "obfs-password" not in proxy_entry:
                logger.warning(f"Hysteria2 节点启用了 obfs 但缺少 'obfs-password' 字段，继续测试")
                return True
        elif proxy_entry["type"] == "vless":
            if "uuid" not in proxy_entry or "tls" not in proxy_entry:
                raise ValueError("VLESS 节点缺少 'uuid' 或 'tls' 字段")
            if proxy_entry.get("flow") == "xtls-rprx-vision" and "reality-opts" not in proxy_entry:
                logger.warning(f"VLESS 节点使用 xtls-rprx-vision 流控但缺少 'reality-opts' 字段，继续测试")
                return True
        elif proxy_entry["type"] == "trojan":
            if "password" not in proxy_entry:
                raise ValueError("Trojan 节点缺少 'password' 字段")
            if proxy_entry.get("network") == "ws" and "ws-opts" not in proxy_entry:
                logger.warning(f"Trojan WebSocket 节点缺少 'ws-opts' 字段，继续测试")
                return True

        return True
    except ValueError as e:
        logger.warning(f"节点 {proxy_entry.get('name', '未知')} 验证失败: {str(e)}. 完整配置: {proxy_entry}")
        return False

async def generate_clash_config(proxy_entry: Dict[str, Any], socks_port: int) -> Dict[str, Any]:
    """为单个代理节点生成 Clash 配置文件"""
    if GLOBAL_CLASH_CONFIG_TEMPLATE is None:
        raise ValueError("Clash 基础配置模板未加载。请先调用 fetch_clash_base_config")

    if not validate_proxy_entry(proxy_entry):
        raise ValueError(f"无效代理节点 {proxy_entry.get('name', '未知')}，跳过生成")

    # 深拷贝模板，防止修改原始模板
    config = json.loads(json.dumps(GLOBAL_CLASH_CONFIG_TEMPLATE))

    config["port"] = random.randint(10000, 15000)
    config["socks-port"] = socks_port
    config["allow-lan"] = False
    config["mode"] = "rule"
    config["log-level"] = "debug"

    # 清空并添加当前代理
    config.setdefault("proxies", []).clear()
    config["proxies"].append(proxy_entry)

    proxy_name = proxy_entry["name"]
    # 检查是否存在名为 "Proxy" 的代理组，如果不存在则创建
    proxy_group_exists = False
    if "proxy-groups" in config and isinstance(config["proxy-groups"], list):
        for group in config["proxy-groups"]:
            if group.get("name") == "Proxy":
                group["proxies"] = [proxy_name, "DIRECT", "REJECT"]
                proxy_group_exists = True
                break
    if not proxy_group_exists:
        config["proxy-groups"] = [
            {
                "name": "Proxy",
                "type": "select",
                "proxies": [proxy_name, "DIRECT", "REJECT"]
            }
        ]

    # 确保规则包含测试所需的规则和 MATCH 规则
    if "rules" not in config or not isinstance(config["rules"], list):
        config["rules"] = []
    
    # 确保测试规则存在
    test_rules = [
        "DOMAIN-SUFFIX,google.com,Proxy",
        "DOMAIN-SUFFIX,googleusercontent.com,Proxy", # 修正此处的域名
        "DOMAIN-SUFFIX,cloudflare.com,Proxy",
        "DOMAIN-SUFFIX,github.com,Proxy",
    ]
    for rule in test_rules:
        if rule not in config["rules"]:
            config["rules"].insert(0, rule) # 将测试规则放在前面

    if "MATCH,Proxy" not in config["rules"]:
        config["rules"].append("MATCH,Proxy")

    return config

async def test_node(clash_config: Dict[str, Any], node_identifier: str, index: int, total: int) -> bool:
    """测试单个代理节点"""
    temp_dir = Path(tempfile.gettempdir())
    socks_port = random.randint(20000, 25000)
    clash_config["socks-port"] = socks_port
    clash_config["port"] = random.randint(10000, 15000)

    config_path = temp_dir / f"clash_config_{os.getpid()}_{socks_port}.yaml"
    process = None
    try:
        with open(config_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(clash_config, f, allow_unicode=True, sort_keys=False)

        process = await asyncio.create_subprocess_exec(
            CLASH_PATH,
            "-f",
            str(config_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        await asyncio.sleep(2)

        if process.returncode is not None:
            stdout, stderr = await process.communicate()
            logger.error(f"Clash 启动失败 (节点: {node_identifier})")
            logger.error(f"配置文件内容:\n{yaml.dump(clash_config, indent=2, sort_keys=False)}")
            logger.error(f"Stdout: {stdout.decode(errors='ignore')}")
            logger.error(f"Stderr: {stderr.decode(errors='ignore')}")
            return False

        try:
            reader, writer = await asyncio.open_connection('127.0.0.1', socks_port)
            writer.close()
            await writer.wait_closed()
        except ConnectionRefusedError:
            logger.warning(f"Clash SOCKS5 端口 {socks_port} 未开放 (节点: {node_identifier})")
            return False
        except Exception as e:
            logger.warning(f"连接 SOCKS5 端口 {socks_port} 失败 (节点: {node_identifier}): {e}")
            return False

        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False),
            timeout=aiohttp.ClientTimeout(total=TIMEOUT),
        ) as session:
            proxy = f"http://127.0.0.1:{socks_port}" # Clash 的 SOCKS5 端口也支持 HTTP 代理
            for url in TEST_URLS:
                try:
                    async with session.get(url, proxy=proxy) as response:
                        if response.status != 200:
                            logger.info(
                                f"节点 {node_identifier} 连接 {url} 失败 "
                                f"(状态码: {response.status}, 尝试 1/1)"
                            )
                            return False
                        break # 成功则跳出内层循环
                except aiohttp.ClientConnectionError as e:
                    logger.info(
                        f"节点 {node_identifier} 连接 {url} 失败: {e} "
                        f"(尝试 1/1)"
                    )
                    return False
                except asyncio.TimeoutError:
                    logger.info(
                        f"节点 {node_identifier} 测试 {url} 超时 "
                        f"(尝试 1/1)"
                    )
                    return False
                except Exception as e:
                    logger.info(
                        f"节点 {node_identifier} 测试 {url} 失败: {e} "
                        f"(尝试 1/1)"
                    )
                    return False

        logger.info(f"[{index}/{total}] ✓ 节点 {node_identifier} 通过所有测试")
        return True
    except Exception as e:
        logger.error(f"测试节点 {node_identifier} 失败: {e}")
        return False
    finally:
        if process and process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=2)
            except asyncio.TimeoutError:
                logger.warning(f"无法正常终止 Clash 进程 (节点: {node_identifier})，强制杀死")
                process.kill()
        if config_path.exists():
            try:
                config_path.unlink()
            except OSError as e:
                logger.warning(f"无法删除配置文件 {config_path}: {e}")

async def main():
    """主函数：从多个 URL 和明文链接加载代理节点，测试并保存有效节点"""
    Path("data").mkdir(parents=True, exist_ok=True)

    global GLOBAL_CLASH_CONFIG_TEMPLATE
    for url in CLASH_BASE_CONFIG_URLS:
        GLOBAL_CLASH_CONFIG_TEMPLATE = await fetch_clash_base_config(url)
        if GLOBAL_CLASH_CONFIG_TEMPLATE is not None:
            logger.info(f"使用 {url} 作为 Clash 配置模板")
            break
    if GLOBAL_CLASH_CONFIG_TEMPLATE is None:
        logger.error("无法从任何 URL 获取 Clash 基础配置，程序退出")
        return

    # 加载已知的无效节点列表
    known_failed_nodes = load_failed_nodes(Path(FAILED_NODES_FILE))
    logger.info(f"已加载 {len(known_failed_nodes)} 个上次运行的无效节点。")

    # 从 URL 获取节点
    nodes_from_urls = await fetch_all_configs(CLASH_BASE_CONFIG_URLS)
    
    # 手动添加明文节点链接
    plain_text_node_links = [
        "trojan://fuck@42.236.73.72:443?security=tls&sni=www.zitian.cn&alpn=http/1.1&type=tcp#0,54%7CChina_None_trojan_1129",
        "trojan://9bb27128-e6d2-4cac-bbd3-beb46c4417f8@hk01.trojanyyds.xyz:443?security=tls&type=tcp#14,16,498,1007,1058,1422%7C%F0%9F%87%AF%F0%9F%87%B5JP-74.22...%20%231",
        "vmess://eyJhZGQiOiIxMjAuMjEwLjIwNS41OSIsImFpZCI6IjY0IiwiaG9zdCI6IiIsImlkIjoiNDE4MDQ4YWYtYTI5My00Yjk5LTliMGMtOThjYTM1ODBkZDI0IiwibmV0IjoidGNwIiwicGF0aCI6IiIsInBvcnQiOiI1MDAwMiIsInBzIjoiMTQxLDE0MiwxNDQsMTQ1LDE0NiwxNDcsMTQ4LDE0OSwxNTAsMjQwfEdpdGh1YuaQnOe0olRyb2phbkxpbmtzICMzNSIsInNjeSI6ImF1dG8iLCJzbmkiOiIiLCJ0bHMiOiIiLCJ0eXBlIjoiIiwidiI6IjIifQ==",
        "hy2://nfsn666@ld-arm.nfsn666.gq:8888?insecure=1&sni=ld-arm.nfsn666.gq#2C%207C%20E%209A%20A%20EF%20B%208F%2040vpnserverrr%2028Hysteria%20233-25635",
        "hy2://nfsn666@130.162.182.250:8888?insecure=1&sni=ld-arm.nfsn666.gq#2C%207CChannel%2020id%203A%2040Shadow%20xy%20F%209F%20AC%20F%209F%20A7-25634",
        "ss://Y2hhY2hhMjAtaWV0Zjphc2QxMjM0NTY=@103.149.182.191:8388#3-14%F0%9F%A6%97_19",
        "trojan://0ac1a0a8-2a02-4ec8-acbe-704a13a471ab@18.140.18.90:443?security=tls&sni=fscca.fscloud123456789.com&allowInsecure=1&type=tcp#458%7C%E6%96%B0%E5%8A%A0%E5%9D%A1Singapore+-+Singapore+%F0%9F%8C%8F+TR-TCP-TLS+...+%2357",
        "vless://60bdbed7-228b-466b-bd8c-32e779a5aea9@ipe.alighan.ir:2083?security=tls&sni=germany.alighan.ir&type=ws&path=/?ed%3D2048&host=germany.alighan.ir&encryption=none#4Jadi-10206-36058",
        "vmess://eyJhZGQiOiIxMTEuMjYuMTA5Ljc5IiwiYWlkIjoiMiIsImhvc3QiOiJvY2JjLmNvbSIsImlkIjoiY2JiM2Y4NzctZDFmYi0zNDRjLTg3YTktZDE1M2JmZmQ1NDg0IiwibmV0Ijoid3MiLCJwYXRoIjoiL29vb28iLCJwb3J0IjoiMzA4MjgiLCJwcyI6IjRKYWRpLTE2NjA5LTE5MTg4Iiwic2N5IjoiYXV0byIsInNuaSI6Im9jYmkuY29tIiwidGxzIjoiIiwidHlwZSI6IiIsInY6IjIifQ==",
        "vmess://eyJhZGQiOiIxMjAuMjMyLjE1My40MCIsImFpZCI6IjY0IiwiaG9zdCI6IiIsImlkIjoiNDE4MDQ4YWYtYTI5My00Yjk5LTliMGMtOThjYTM1ODBkZDI0IiwibmV0IjoidGNwIiwicGF0aCI6IiIsInBvcnQiOiIzMTIwOSIsInBzIjoiNEphZGktMTY2NDAtMTkyMTkiLCJzY3kiOiJhdXRvIiwic25pIjoiIiwidGxzIjoiIiwidHlwZSI6IiIsInYiOiIyIn0=",
        "vmess://eyJhZGQiOiIxODMuMjM2LjUxLjM4IiwiYWlkIjoiNjQiLCJob3N0IjoiIiwiaWQiOiI0MTgwNDhhZi1hMjkzLTRiOTktOWIwYy05OGNhMzU4MGRkMjQiLCJuZXQiOiJ0Y3AiLCJwYXRoIjoiIiwicG9ydCI6IjQ5MzAyIiwicHMiOiI0SmFkaS0xNzc4OC0yMDM2NyIsInNjeSI6ImF1dG8iLCJzbmkiOiJudWxsIiwidGxzIjoiIiwidHlwZSI6IiIsInYiOiIyIn0=",
        "vmess://eyJhZGQiOiIxODMuMjM2LjUxLjM4IiwiYWlkIjoiMCIsImhvc3QiOiIiLCJpZCI6IjQxODA0OGFmLWEyOTMtNGI5OS05YjBjLTk4Y2EzNTgwZGQyNCIsIm5ldCI6InRjcCIsInBhdGgiOiIiLCJwb3J0IjoiMzM5MTkiLCJwcyI6IjRKYWRpLTE3Nzk1LTIwMzc0Iiwic2N5IjoiYXV0byIsInNuaSI6Im51bGwiLCJ0bHMiOiIiLCJ0eXBlIjoiIiwidiI6IjIifQ==",
        "vmess://eyJhZGQiOiJ2MTIuaGVkdWlhbi5saW5rIiwiYWlkIjoiMiIsImhvc3QiOiJvY2JjLmNvbSIsImlkIjoiY2JiM2Y4NzctZDFmYi0zNDRjLTg3YTktZDE1M2JmZmQ1NDg0IiwibmV0Ijoid3MiLCJwYXRoIjoiL29vb28iLCJwb3J0IjoiMzA4MTIiLCJwcyI6IjRKYWRpLTE5NzA2LTIyMjg1Iiwic2N5IjoiYXV0byIsInNuaSI6Im9jYmkuY29tIiwidGxzIjoiIiwidHlwZSI6IiIsInYiOiIyIn0=",
        "vmess://eyJhZGQiOiJ2OS5oZWR1aWFuLmxpbmsiLCJhaWQiOiIyIiwiaG9zdCI6ImJhaWR1LmNvbSIsImlkIjoiY2JiM2Y4NzctZDFmYi0zNDRjLTg3YTktZDE1M2JmZmQ1NDg0IiwibmV0Ijoid3MiLCJwYXRoIjoiL29vb28iLCJwb3J0IjoiMzA4MDkiLCJwcyI6IjRKYWRpLTE5NzI4LTIyMzA3Iiwic2N5IjoiYXV0byIsInNuaSI6ImJhaWR1LmNvbSIsInRscyI6IiIsInR5cGUiOiIiLCJ2IjoiMiJ9",
        "trojan://0b971bb0-f0af-11ee-8f57-1239d0255272@172.67.159.13:443?security=tls&sni=uk1.test3.net&type=tcp#4Jadi-3251-29103",
        "trojan://0bc8c688-e142-4a64-8885-f8c7498f8a90@172.67.68.8:443?security=tls&sni=tro4replit.bunnylblbblbl.eu.org&allowInsecure=1&type=tcp#4Jadi-3252-29104",
        "trojan://123456@104.18.11.39:443?security=tls&sni=trojan-amp-id01.globalssh.xyz&allowInsecure=1&type=tcp#4Jadi-3310-29162",
        "trojan://18844%2540zxcvbn@49.212.204.123:443?security=tls&sni=49.212.204.123&allowInsecure=1&type=tcp#4Jadi-3339-29191",
        "trojan://20210200-49c6-11ed-a9ef-1239d0255272@172.67.24.177:443?security=tls&sni=kipi.covid19.go.id&allowInsecure=1&type=tcp#4Jadi-3368-29220",
    ]

    nodes_from_plain_text: List[Dict[str, Any]] = []
    logger.info(f"开始解析 {len(plain_text_node_links)} 个明文链接...")
    for link in plain_text_node_links:
        node = await parse_plain_text_node(link)
        if node:
            nodes_from_plain_text.append(node)
    logger.info(f"成功解析 {len(nodes_from_plain_text)} 个明文链接。")

    # 合并所有节点并去重
    all_nodes: List[Dict[str, Any]] = []
    seen_nodes_keys = set() # 用于去重的集合

    def get_unique_key(proxy: Dict[str, Any]) -> tuple:
        # 创建一个可哈希的唯一标识符
        if proxy["type"] == "ss":
            return (proxy.get("server", ""), proxy.get("port", 0), proxy.get("cipher", ""), proxy.get("password", ""), proxy.get("type", ""))
        elif proxy["type"] == "vmess":
            return (proxy.get("server", ""), proxy.get("port", 0), proxy.get("uuid", ""), proxy.get("alterId", 0), proxy.get("network", ""), proxy.get("tls", False), proxy.get("ws-opts", {}).get("path", ""))
        elif proxy["type"] == "hysteria2":
            return (proxy.get("server", ""), proxy.get("port", 0), proxy.get("password", ""), proxy.get("sni", ""), proxy.get("obfs", ""), proxy.get("obfs-password", ""))
        elif proxy["type"] == "vless":
            return (proxy.get("server", ""), proxy.get("port", 0), proxy.get("uuid", ""), proxy.get("tls", False), proxy.get("network", ""), proxy.get("flow", ""), proxy.get("ws-opts", {}).get("path", ""))
        elif proxy["type"] == "trojan":
            return (proxy.get("server", ""), proxy.get("port", 0), proxy.get("password", ""), proxy.get("sni", ""), proxy.get("network", ""), proxy.get("ws-opts", {}).get("path", ""))
        else:
            # 对于其他未知类型，简单拼接所有键值对作为唯一标识
            return tuple(sorted(proxy.items()))


    for node in nodes_from_urls + nodes_from_plain_text:
        unique_key = get_unique_key(node)
        if unique_key not in seen_nodes_keys:
            all_nodes.append(node)
            seen_nodes_keys.add(unique_key)
        else:
            logger.debug(f"跳过合并后的重复节点: {node.get('name', '未知')}")
            
    logger.info(f"所有来源合并后总计 {len(all_nodes)} 个唯一代理节点。")

    if not all_nodes:
        logger.error("节点列表为空，无法进行测试。")
        return

    if not Path(CLASH_PATH).is_file() or not os.access(CLASH_PATH, os.X_OK):
        logger.error(f"Clash 可执行文件 '{CLASH_PATH}' 不存在或不可执行。请检查 CLASH_CORE_PATH")
        return

    valid_proxy_dicts: List[Dict[str, Any]] = []
    failure_reasons: Dict[str, int] = {"server_disconnected": 0, "invalid_format": 0, "timeout": 0, "other": 0}
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)

    # 过滤掉已知的无效节点，并准备进行测试的节点列表
    nodes_to_test = []
    skipped_count = 0
    for node in all_nodes:
        node_name = node.get("name", "未知代理")
        if node_name in known_failed_nodes:
            logger.info(f"跳过已知无效节点: {node_name}")
            skipped_count += 1
            continue
        nodes_to_test.append(node)

    logger.info(f"将测试 {len(nodes_to_test)} 个新节点（跳过 {skipped_count} 个已知无效节点）。")

    for i in range(0, len(nodes_to_test), BATCH_SIZE):
        batch = nodes_to_test[i:i + BATCH_SIZE]
        tasks = []
        for j, proxy_entry in enumerate(batch):
            async def test_with_semaphore(idx: int, entry: Dict[str, Any]):
                async with semaphore:
                    node_identifier = entry.get("name", "未知代理")
                    if not validate_proxy_entry(entry):
                        logger.info(f"[{i + idx + 1}/{len(nodes_to_test)}] ✗ 节点 {node_identifier} 格式无效，已跳过")
                        failure_reasons["invalid_format"] += 1
                        save_failed_node(Path(FAILED_NODES_FILE), node_identifier)
                        return None
                    try:
                        clash_config = await generate_clash_config(entry, 0)
                        if await test_node(clash_config, node_identifier, i + idx + 1, len(nodes_to_test)):
                            return entry
                        logger.info(f"[{i + idx + 1}/{len(nodes_to_test)}] ✗ 节点 {node_identifier} 无效或延迟过高，已跳过")
                        save_failed_node(Path(FAILED_NODES_FILE), node_identifier)
                        if "server disconnected" in str(entry).lower(): # 这部分判断可能需要更精细，直接从测试结果判断
                             failure_reasons["server_disconnected"] += 1
                        elif "timeout" in str(entry).lower():
                             failure_reasons["timeout"] += 1
                        else:
                             failure_reasons["other"] += 1
                        return None
                    except ValueError as ve: # 捕获 generate_clash_config 抛出的无效节点错误
                        logger.info(f"[{i + idx + 1}/{len(nodes_to_test)}] ✗ 节点 {node_identifier} 生成配置失败: {ve}，已跳过")
                        failure_reasons["invalid_format"] += 1
                        save_failed_node(Path(FAILED_NODES_FILE), node_identifier)
                        return None
                    except Exception as e:
                        logger.error(f"[{i + idx + 1}/{len(nodes_to_test)}] 测试节点 {node_identifier} 失败: {e}")
                        failure_reasons["other"] += 1
                        save_failed_node(Path(FAILED_NODES_FILE), node_identifier)
                        return None

            tasks.append(test_with_semaphore(j, proxy_entry))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        valid_batch_proxy_dicts = [r for r in results if isinstance(r, dict) and r is not None]
        valid_proxy_dicts.extend(valid_batch_proxy_dicts)

        if valid_batch_proxy_dicts:
            with open(f"data/temp_valid_batch_{i//BATCH_SIZE + 1}.yaml", "w", encoding="utf-8") as f:
                yaml.safe_dump({"proxies": valid_batch_proxy_dicts}, f, allow_unicode=True, sort_keys=False)
            logger.info(f"批次 {i//BATCH_SIZE + 1} 完成，当前有效节点数: {len(valid_proxy_dicts)}")
        else:
            logger.info(f"批次 {i//BATCH_SIZE + 1} 完成，此批次无有效节点")

    if valid_proxy_dicts:
        with open(OUTPUT_FILE_PATH, "w", encoding="utf-8") as f:
            yaml.safe_dump({"proxies": valid_proxy_dicts}, f, allow_unicode=True, sort_keys=False)
        logger.info(f"测试完成，保存 {len(valid_proxy_dicts)} 个有效节点到 {OUTPUT_FILE_PATH}")
    else:
        logger.warning("没有找到有效节点")

    logger.info(f"测试总结：总节点数: {len(all_nodes)}, 有效节点: {len(valid_proxy_dicts)}")
    logger.info(f"失败原因统计: {failure_reasons}")

if __name__ == "__main__":
    asyncio.run(main())
