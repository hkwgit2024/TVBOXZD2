import asyncio
import json
import logging
import random
import shutil
import socket
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
import base64
import urllib.parse
import aiohttp
import binascii # 引入 binascii 用于处理 base64 错误

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 定义常量
NODE_FILE_PATH = "data/sub_2.txt"
OUTPUT_FILE_PATH = "data/all.txt"
CONNECTION_TIMEOUT = 10  # 秒
TEST_URLS = [
    "http://www.google.com/generate_204",
    "http://cp.cloudflare.com/",
    "http://www.baidu.com"
]
SINGBOX_CORE_PATH = "./sing-box"

# 支持的 Shadowsocks 加密方法
VALID_SS_METHODS = {
    "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "rc4-md5", "chacha20-ietf", "xchacha20", "none" # 'none' for plain/obfs
}

class NodeParser:
    """负责解析不同协议的节点链接"""
    def parse(self, node_link: str) -> Optional[Dict[str, Any]]:
        node_link = node_link.strip()
        if not node_link:
            return None

        original_link = node_link
        node_data = None # 初始化为 None

        # 初步检查 Shadowsocks 和 SSR 链接：
        # 这里进行更宽松的检查，让具体的解析函数处理更复杂的逻辑
        # 移除之前的严格检查，因为它们可能导致有效链接被误判
        
        if node_link.startswith("vmess://"):
            node_data = self._parse_vmess(node_link)
        elif node_link.startswith("trojan://"):
            node_data = self._parse_trojan(node_link)
        elif node_link.startswith("ss://"):
            node_data = self._parse_shadowsocks(node_link)
        elif node_link.startswith("ssr://"):
            node_data = self._parse_ssr(node_link)
        elif node_link.startswith("vless://"):
            node_data = self._parse_vless(node_link)
        elif node_link.startswith("hysteria2://"):
            node_data = self._parse_hysteria2(node_link)
        # TODO: 添加对 TUIC 等其他协议的解析
        else:
            logging.warning(f"警告: 不支持或无法识别的节点链接格式: {node_link[:50]}...")
        
        if node_data:
            node_data['original_link'] = original_link
        return node_data

    def _parse_vmess(self, link: str) -> Optional[Dict[str, Any]]:
        try:
            base64_str = link[len("vmess://"):]
            missing_padding = len(base64_str) % 4
            if missing_padding:
                base64_str += '=' * (4 - missing_padding)
            decoded_json = base64.b64decode(base64_str).decode('utf-8')
            data = json.loads(decoded_json)
            
            node = {
                "type": "vmess",
                "name": data.get("ps", f"{data['add']}:{data['port']}"),
                "server": data["add"],
                "port": int(data["port"]),
                "uuid": data["id"],
                "alterId": int(data.get("aid", 0)),
                "security": data.get("scy", "auto"),
                "network": data.get("net", "tcp"),
                "tls": data.get("tls", "") == "tls",
                "sni": data.get("sni", data["add"]),
                "host": data.get("host", data["add"]),
                "path": data.get("path", "/"),
                "allowInsecure": data.get("allowInsecure", False),
            }
            if node["network"] == "ws":
                node["wsSettings"] = {"path": node["path"], "headers": {"Host": node["host"]}}
            return node
        except Exception as e:
            logging.error(f"解析 VMess 链接失败: {link[:50]}... 错误: {e}")
            return None

    def _parse_trojan(self, link: str) -> Optional[Dict[str, Any]]:
        try:
            parsed = urllib.parse.urlparse(link)
            password = parsed.username
            server = parsed.hostname
            port = parsed.port
            if not all([password, server, port]): # Ensure essential parts exist
                raise ValueError("Trojan link missing essential components (password, server, or port).")

            params = urllib.parse.parse_qs(parsed.query)
            
            node = {
                "type": "trojan",
                "name": urllib.parse.unquote(parsed.fragment or f"{server}:{port}"),
                "server": server,
                "port": port,
                "password": password,
                "network": params.get("type", ["tcp"])[0],
                "tls": True, # Trojan 默认要求 TLS
                "sni": params.get("sni", [server])[0],
                "host": params.get("host", [server])[0],
                "path": params.get("path", ["/"])[0],
                "allowInsecure": params.get("allowInsecure", ["0"])[0] == "1",
            }
            return node
        except Exception as e:
            logging.error(f"解析 Trojan 链接失败: {link[:50]}... 错误: {e}")
            return None

    def _parse_shadowsocks(self, link: str) -> Optional[Dict[str, Any]]:
        try:
            parts = link[len("ss://"):].split("#")
            tag = urllib.parse.unquote(parts[1]) if len(parts) > 1 else ""
            
            creds_and_addr_with_params = parts[0]
            
            creds_and_addr = creds_and_addr_with_params
            params = {}
            if "?" in creds_and_addr_with_params:
                creds_and_addr, query = creds_and_addr_with_params.split("?", 1)
                params = urllib.parse.parse_qs(query)

            if "@" not in creds_and_addr:
                logging.warning(f"SS 链接格式不标准（无@符号），可能带插件或凭据未编码，跳过: {link[:50]}...")
                return None

            creds_b64, addr = creds_and_addr.split("@", 1)
            
            # --- 改进的 base64 解码和凭据解析 ---
            creds_decoded = ""
            # 尝试添加填充
            missing_padding = len(creds_b64) % 4
            if missing_padding != 0:
                creds_b64 += '=' * (4 - missing_padding)
            
            try:
                # 尝试 urlsafe_b64decode
                creds_bytes = base64.urlsafe_b64decode(creds_b64)
                creds_decoded = creds_bytes.decode('utf-8')
            except (binascii.Error, UnicodeDecodeError):
                # 如果 urlsafe 失败，尝试标准 b64decode
                try:
                    creds_bytes = base64.b64decode(creds_b64)
                    creds_decoded = creds_bytes.decode('utf-8')
                except (binascii.Error, UnicodeDecodeError) as e:
                    logging.error(f"解析 Shadowsocks 链接 (凭据解码失败): {link[:50]}... 错误: {e}")
                    return None
            # --- 解码结束 ---

            method, password = "", ""
            if ":" in creds_decoded:
                method, password = creds_decoded.split(":", 1)
            else:
                # 如果没有冒号，尝试直接作为密码，方法为默认
                password = creds_decoded
                # 假设默认方法，但更推荐严格要求方法
                method = "chacha20-ietf-poly1305" # 或其他默认值，或者直接返回 None

            if method not in VALID_SS_METHODS:
                logging.warning(f"不支持的 Shadowsocks 加密方法: {method} 在链接: {link[:50]}... 跳过.")
                return None
            
            server, port_str = addr.split(":", 1)
            port = int(port_str)

            node = {
                "type": "shadowsocks",
                "name": tag or f"SS-{server}:{port}",
                "server": server,
                "port": port,
                "method": method,
                "password": password,
            }
            
            if params.get("plugin"): # simple-obfs, v2ray-plugin 等
                node["plugin"] = params.get("plugin", [""])[0]
                # plugin_opts 的解析通常更复杂，需要根据具体插件类型来
                # 这里简单处理，将所有剩余参数作为 plugin_opts
                plugin_opts_list = [f"{k}={v[0]}" for k, v in params.items() if k != "plugin"]
                if plugin_opts_list:
                    node["plugin_opts"] = "&".join(plugin_opts_list)

            return node
        except Exception as e:
            logging.error(f"解析 Shadowsocks 链接失败: {link[:50]}... 错误: {e}")
            return None

    def _parse_ssr(self, link: str) -> Optional[Dict[str, Any]]:
        try:
            base64_str = link[len("ssr://"):]
            missing_padding = len(base64_str) % 4
            if missing_padding:
                base64_str += '=' * (4 - missing_padding)
            
            # SSR 链接通常是 urlsafe_b64decode 且解码后是 utf-8
            decoded_str = base64.urlsafe_b64decode(base64_str).decode('utf-8')
            
            # ssr://server:port:protocol:method:obfs:password_base64/?params#remarks
            # 兼容没有 /?params 的情况
            main_part = decoded_str.split("/?")[0]
            params_part = decoded_str.split("/?")[1] if "/?" in decoded_str else ""
            
            parts = main_part.split(":")
            if len(parts) < 6:
                logging.warning(f"SSR 链接格式不完整 (至少6部分): {link[:50]}...")
                return None
            
            server, port, protocol, method, obfs, password_b64 = parts[:6]
            
            password = base64.urlsafe_b64decode(password_b64).decode('utf-8') # 密码也需要 base64 解码

            params = urllib.parse.parse_qs(params_part)
            
            node = {
                "type": "ssr",
                "name": urllib.parse.unquote(params.get("remarks", [""])[0] or f"SSR-{server}:{port}"),
                "server": server,
                "port": int(port),
                "method": method,
                "password": password,
                "protocol": protocol,
                "obfs": obfs,
                "protocol_param": urllib.parse.unquote(params.get("protoparam", [""])[0]),
                "obfs_param": urllib.parse.unquote(params.get("obfsparam", [""])[0]),
            }
            return node
        except Exception as e:
            logging.error(f"解析 SSR 链接失败: {link[:50]}... 错误: {e}")
            return None

    def _parse_vless(self, link: str) -> Optional[Dict[str, Any]]:
        try:
            parsed = urllib.parse.urlparse(link)
            uuid = parsed.username
            server = parsed.hostname
            port = parsed.port
            if not all([uuid, server, port]): # Essential checks
                raise ValueError("VLESS link missing essential components.")

            params = urllib.parse.parse_qs(parsed.query)
            
            node = {
                "type": "vless",
                "name": urllib.parse.unquote(parsed.fragment or f"{server}:{port}"),
                "server": server,
                "port": port,
                "uuid": uuid,
                "encryption": "none",
                "flow": params.get("flow", [""])[0],
                "network": params.get("type", ["tcp"])[0],
                "tls": params.get("security", [""]) == ["tls"],
                "reality": params.get("security", [""]) == ["reality"],
                "sni": params.get("sni", [server])[0] if params.get("security", [""]) != ["reality"] else server, # Default SNI for Reality is server
                "pbk": params.get("pbk", [""])[0], # Public Key for Reality
                "sid": params.get("sid", [""])[0], # Short ID for Reality
                "fp": params.get("fp", [""])[0], # Fingerprint for Reality
                "dest": params.get("dest", [""])[0], # Dest for Reality (server:port)
                "allowInsecure": params.get("insecure", ["0"])[0] == "1", # Added for consistency
            }
            if node["network"] == "ws":
                node["path"] = params.get("path", ["/"])[0]
                node["host"] = params.get("host", [server])[0]
            elif node["network"] == "grpc":
                node["serviceName"] = params.get("serviceName", [""])[0]
                node["multiMode"] = params.get("multiMode", ["0"])[0] == "1"
            return node
        except Exception as e:
            logging.error(f"解析 VLESS 链接失败: {link[:50]}... 错误: {e}")
            return None

    def _parse_hysteria2(self, link: str) -> Optional[Dict[str, Any]]:
        try:
            parsed = urllib.parse.urlparse(link)
            password = parsed.username
            server = parsed.hostname
            port = parsed.port or 443
            if not all([password, server, port]):
                raise ValueError("Hysteria2 link missing essential components.")

            params = urllib.parse.parse_qs(parsed.query)
            
            node = {
                "type": "hysteria2",
                "name": urllib.parse.unquote(parsed.fragment or f"{server}:{port}"),
                "server": server,
                "port": port,
                "password": password,
                "sni": params.get("sni", [server])[0],
                "insecure": params.get("insecure", ["0"])[0] == "1",
                "obfs": params.get("obfs", [""])[0],
                "obfs_password": params.get("obfs-password", [""])[0],
            }
            return node
        except Exception as e:
            logging.error(f"解析 Hysteria2 链接失败: {link[:50]}... 错误: {e}")
            return None

class SingboxConfigGenerator:
    """根据解析的节点信息生成 Singbox 配置"""
    def generate(self, node: Dict[str, Any], local_port: int) -> Optional[Dict[str, Any]]:
        base_config = {
            "inbounds": [
                {
                    "type": "socks",
                    "listen": "127.0.0.1",
                    "listen_port": local_port,
                    "udp_relay_mode": "per-session",
                    "sniff": True,
                    "sniff_override_destination": True
                }
            ],
            "outbounds": [
                {"type": "direct", "tag": "direct"},
                {"type": "block", "tag": "block"}
            ],
            "log": {"level": "warn"},
            "dns": {
                "servers": [
                    {"address": "8.8.8.8", "strategy": "prefer_ipv4"},
                    {"address": "1.1.1.1", "strategy": "prefer_ipv4"}
                ]
            }
        }

        outbound = self._build_outbound(node)
        if not outbound:
            return None
        
        outbound["tag"] = "proxy"
        base_config["outbounds"].insert(0, outbound)

        base_config["route"] = {
            "rules": [
                {"protocol": ["dns"], "outbound": "dns-out"},
                {"outbound": "proxy"}
            ],
            "final": "proxy"
        }
        
        return base_config

    def _build_outbound(self, node: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        protocol_type = node['type']
        
        transport_settings = {}
        network = node.get("network", "tcp")
        tls_enabled = node.get("tls", False)
        
        # Singbox TLS settings (common structure)
        tls_config = {}
        if tls_enabled:
            tls_config = {
                "enabled": True,
                "server_name": node.get("sni", node["server"]),
                "disable_sni": False, # Explicitly enable SNI unless specific
                "insecure": node.get("allowInsecure", node.get("insecure", False)),
                "utls": {"enabled": True, "fingerprint": node.get("fp", "chrome")} # Use provided FP or default
            }
            # Reality specific settings for VLESS
            if node.get("reality", False) and protocol_type == "vless":
                tls_config["reality"] = {
                    "enabled": True,
                    "public_key": node.get("pbk", ""),
                    "short_id": node.get("sid", ""),
                }
                # No SNI if reality is used, as SNI is part of reality handshakes
                if node.get("dest"): # Only add if dest is explicitly provided for reality
                     tls_config["reality"]["dest"] = node["dest"]


        # Transport settings (WS, gRPC)
        if network == "ws":
            transport_settings = {
                "type": "ws",
                "path": node.get("path", "/"),
                "headers": {"Host": node.get("host", node["server"])}
            }
        elif network == "grpc":
            transport_settings = {
                "type": "grpc",
                "service_name": node.get("serviceName", ""),
                "idle_timeout": "15s",
                "ping_timeout": "15s",
                "permit_without_stream": True # For some gRPC setups
            }
        # Add other transport types as needed (h2, quic etc.)

        outbound = {
            "type": protocol_type,
            "server": node["server"],
            "server_port": node["port"],
        }
        
        if protocol_type == "vmess":
            outbound.update({
                "uuid": node["uuid"],
                "security": node.get("security", "auto"),
                "alter_id": node.get("alterId", 0),
            })
            if tls_enabled:
                outbound["tls"] = tls_config

        elif protocol_type == "trojan":
            outbound["password"] = node["password"]
            outbound["tls"] = tls_config # Trojan always uses TLS

        elif protocol_type == "vless":
            outbound.update({
                "uuid": node["uuid"],
                "flow": node.get("flow", ""),
                "tls": tls_config, # VLESS uses TLS
            })

        elif protocol_type == "shadowsocks":
            outbound.update({
                "method": node["method"],
                "password": node["password"],
            })
            # Singbox for SS with plugins might use 'transport' section or specific 'plugin' outbound type
            # For now, we assume simple SS or rely on Singbox's internal plugin handling
            if node.get("plugin") == "simple-obfs": # Example for simple-obfs
                transport_settings["type"] = "tcp" # Obfs is on TCP transport
                transport_settings["tcp_fast_open"] = True # Example, if supported
                transport_settings["obfs"] = {
                    "type": node.get("plugin_opts_type", "http"), # http or tls
                    "host": node.get("plugin_opts_host", "www.bing.com")
                }
            elif node.get("plugin"):
                logging.warning(f"Singbox Config Generator: 未知或不支持的 Shadowsocks 插件: {node['plugin']}")
                # You might need to build a custom outbound for specific plugins not natively supported by sing-box SS type.

        elif protocol_type == "ssr":
            # Singbox 不直接支持 SSR 协议，需要转换为 Shadowsocks + 插件
            # 这是 SSR 转 SS 的大致逻辑，可能需要更精确的映射
            # 警告：Singbox 对 SSR 的支持有限，通常通过转换为 SS + 混淆
            logging.warning(f"Singbox Config Generator: Singbox 不直接支持 SSR，尝试转换为 Shadowsocks + 插件: {node['name']}")
            
            # Simplified conversion, might not cover all SSR features
            outbound["type"] = "shadowsocks"
            outbound["method"] = node["method"]
            outbound["password"] = node["password"]
            
            # SSR 的混淆和协议可能需要映射到 Singbox 的传输层设置
            if node.get("obfs"):
                if "http" in node["obfs"]:
                    transport_settings["type"] = "tcp"
                    transport_settings["tcp_fast_open"] = True
                    transport_settings["obfs"] = {"type": "http"}
                    # obfs_param might contain host for http obfs
                    if node.get("obfs_param"):
                        transport_settings["obfs"]["host"] = node["obfs_param"].split(':')[0]
                elif "tls" in node["obfs"]:
                    transport_settings["type"] = "tcp"
                    transport_settings["tcp_fast_open"] = True
                    transport_settings["obfs"] = {"type": "tls"}
                    if node.get("obfs_param"):
                        transport_settings["obfs"]["host"] = node["obfs_param"].split(':')[0]
                else:
                    logging.warning(f"Singbox Config Generator: 不支持的 SSR 混淆类型: {node['obfs']}")
            
            # Singbox 可能不支持 SSR 协议，这里需要进行协议转换或忽略。
            # 如果是不可识别的协议或混淆，直接返回 None
            if not transport_settings and node.get("obfs"):
                 logging.warning(f"无法为 SSR 节点 {node['name']} 生成兼容的 Singbox 传输设置，跳过。")
                 return None

        elif protocol_type == "hysteria2":
            outbound.update({
                "password": node["password"],
            })
            # Hysteria2 在 Singbox 中是独立的协议类型，但其 TLS 和 Obfs 都在协议内部定义
            tls_config_h2 = {
                "enabled": True,
                "server_name": node.get("sni", node["server"]),
                "insecure": node.get("insecure", False),
            }
            if node.get("obfs"):
                tls_config_h2["obfs"] = {
                    "type": node["obfs"],
                    "password": node.get("obfs_password", ""),
                }
            outbound["tls"] = tls_config_h2
            # Hysteria2 默认使用 UDP 传输，不需要额外的 transport 设置
            
        else:
            logging.error(f"不支持生成 Singbox 配置的协议类型: {protocol_type}")
            return None

        if transport_settings:
            outbound["transport"] = transport_settings
        
        # 只有当协议本身不内嵌 TLS 配置时才添加独立的 TLS 字段
        if tls_enabled and protocol_type not in ["trojan", "vless", "hysteria2"]:
             outbound["tls"] = tls_config


        return outbound


def find_available_port(start: int = 10000, end: int = 60000) -> int:
    """查找一个可用的本地端口"""
    while True:
        port = random.randint(start, end)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(('127.0.0.1', port))
                return port
            except OSError:
                continue

async def measure_latency(node: Dict[str, Any]) -> int:
    """测量单个节点的延迟"""
    temp_dir = Path(tempfile.mkdtemp(prefix="singbox_test_"))
    config_path = temp_dir / "config.json"
    
    proc = None
    try:
        port = find_available_port()
        config_generator = SingboxConfigGenerator()
        singbox_config = config_generator.generate(node, port)
        
        if not singbox_config:
            logging.error(f"无法为节点 {node.get('name', node.get('server'))} 生成 Singbox 配置。节点类型可能不支持或解析失败。")
            return -1
        
        config_path.write_text(json.dumps(singbox_config, indent=2))
        
        # 启动 Singbox 核心进程
        command = [SINGBOX_CORE_PATH, "run", "-c", str(config_path)]
        
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        # 稍微等待 Singbox 启动
        await asyncio.sleep(1.5) # 适当增加等待时间

        # 检查进程是否已退出 (即启动失败)
        if proc.returncode is not None:
            stdout, stderr = await proc.communicate()
            logging.error(f"Singbox 核心进程启动失败，检查配置：{config_path}")
            logging.error(f"Stdout: {stdout.decode(errors='ignore')}") # 忽略解码错误
            logging.error(f"Stderr: {stderr.decode(errors='ignore')}") # 忽略解码错误
            return -1

        proxies = {
            'http': f'socks5://127.0.0.1:{port}',
            'https': f'socks5://127.0.0.1:{port}'
        }

        start_time = time.perf_counter()
        # aiohttp 默认会解析 HTTP 和 HTTPS 的代理，所以只需要传入 http 代理即可
        async with aiohttp.ClientSession(headers={"User-Agent": "Mozilla/5.0"}) as session:
            for url in TEST_URLS:
                try:
                    async with session.get(
                            url,
                            proxy=proxies['http'], # aiohttp只接受一个proxy参数，http/https通用
                            timeout=CONNECTION_TIMEOUT,
                            allow_redirects=True
                    ) as resp:
                        if resp.status in (200, 204):
                            latency = int((time.perf_counter() - start_time) * 1000)
                            if 0 <= latency <= 10000: # 假设最大延迟10秒
                                return latency
                            else:
                                logging.warning(f"节点 {node.get('name', node.get('server'))} 延迟过高或不合理：{latency}ms")
                                return -1
                        else:
                            logging.debug(f"节点 {node.get('name', node.get('server'))} 测试 URL {url} 返回非 200/204 状态码: {resp.status}")
                            continue # 继续尝试下一个URL
                except (aiohttp.ClientError, asyncio.TimeoutError, ConnectionRefusedError) as e:
                    logging.debug(f"通过节点 {node.get('name', node.get('server'))} 测试 URL {url} 失败: {type(e).__name__}: {e}")
                    continue # 继续尝试下一个URL
            logging.info(f"节点 {node.get('name', node.get('server'))} 未能通过所有测试 URL。")
            return -1 # 所有URL都失败

    except Exception as e:
        logging.error(f"测试节点 {node.get('name', node.get('server'))} 时发生异常: {type(e).__name__}: {e}")
        return -1
    finally:
        if proc and proc.returncode is None: # 如果进程仍在运行
            try:
                proc.terminate()
                await asyncio.wait_for(proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                proc.kill()
            except Exception as e:
                logging.error(f"停止 Singbox 进程时发生错误: {type(e).__name__}: {e}")
        if temp_dir.exists():
            shutil.rmtree(temp_dir)


async def main():
    parser = NodeParser()
    
    # 1. 读取节点并去重
    unique_nodes_links = set()
    if Path(NODE_FILE_PATH).exists():
        with open(NODE_FILE_PATH, 'r', encoding='utf-8') as f:
            for line in f:
                stripped_line = line.strip()
                if stripped_line and not stripped_line.startswith("#"): # 忽略注释行
                    unique_nodes_links.add(stripped_line)
    
    logging.info(f"读取到 {len(unique_nodes_links)} 个去重后的节点链接。")

    parsed_nodes: List[Dict[str, Any]] = []
    for link in unique_nodes_links:
        node = parser.parse(link)
        if node:
            parsed_nodes.append(node)
            
    logging.info(f"成功解析出 {len(parsed_nodes)} 个有效节点配置。")

    # 2. 异步测试所有节点
    total_nodes_to_test = len(parsed_nodes)
    if total_nodes_to_test == 0:
        logging.info("没有可测试的节点。")
        return

    sem = asyncio.Semaphore(5)  # 控制并发数，可根据服务器性能调整
    results: List[Dict[str, Any]] = []

    async def _test_node_task(idx: int, node: Dict[str, Any]):
        async with sem:
            node_id = node.get('name', f"{node['server']}:{node['port']}")
            latency = await measure_latency(node)
            if 0 <= latency <= 10000: # 再次检查延迟范围
                node['latency'] = latency
                results.append(node)
                logging.info(f"[{idx}/{total_nodes_to_test}] ✓ 节点 {node_id} 测试通过，延迟：{latency} ms")
            else:
                logging.info(f"[{idx}/{total_nodes_to_test}] ✗ 节点 {node_id} 无效或延迟过高，已跳过")

    tasks = [
        _test_node_task(i + 1, node)
        for i, node in enumerate(parsed_nodes)
    ]
    await asyncio.gather(*tasks)

    # 3. 保存测试结果
    results.sort(key=lambda x: x['latency']) # 按延迟排序

    output_dir = Path(OUTPUT_FILE_PATH).parent
    output_dir.mkdir(parents=True, exist_ok=True) # 确保输出目录存在

    with open(OUTPUT_FILE_PATH, 'w', encoding='utf-8') as f:
        for node in results:
            # 输出原始链接，并在后面附带节点名称和延迟信息
            # 确保 original_link 存在，因为它是 parse() 方法中添加的
            f.write(f"{node.get('original_link', node.get('name', 'UNKNOWN_LINK'))} # {node['name']} [{node['latency']}ms]\n")

    logging.info(f"测试完成：共处理 {total_nodes_to_test} 个节点，其中 {len(results)} 个有效，结果已保存到 {OUTPUT_FILE_PATH}")


if __name__ == "__main__":
    asyncio.run(main())
