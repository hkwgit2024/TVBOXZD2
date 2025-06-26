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
import re
import subprocess
import urllib.parse
import aiohttp
import binascii

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
    "rc4-md5", "chacha20-ietf", "xchacha20"
}

class NodeParser:
    """负责解析不同协议的节点链接"""
    def parse(self, node_link: str) -> Optional[Dict[str, Any]]:
        node_link = node_link.strip()
        if not node_link:
            return None

        # 初步检查 Shadowsocks 链接
        if node_link.startswith("ss://"):
            if "@" not in node_link or ":" not in node_link.split("@")[-1]:
                logging.warning(f"无效的 Shadowsocks 链接格式: {node_link[:50]}...")
                return None

        original_link = node_link
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
        else:
            logging.warning(f"不支持或无法识别的节点链接格式: {node_link[:50]}...")
            node_data = None
        
        if node_data:
            node_data['original_link'] = original_link
        return node_data

    def _parse_vmess(self, link: str) -> Optional[Dict[str, Any]]:
        try:
            base64_str = link[len("vmess://"):]
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
            params = urllib.parse.parse_qs(parsed.query)
            
            node = {
                "type": "trojan",
                "name": urllib.parse.unquote(parsed.fragment or f"{server}:{port}"),
                "server": server,
                "port": port,
                "password": password,
                "network": params.get("type", ["tcp"])[0],
                "tls": True,
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
            
            creds_and_addr = parts[0]
            params = {}
            if "?" in creds_and_addr:
                creds_and_addr, query = creds_and_addr.split("?", 1)
                params = urllib.parse.parse_qs(query)

            if "@" in creds_and_addr:
                creds, addr = creds_and_addr.split("@", 1)
                
                try:
                    missing_padding = len(creds) % 4
                    if missing_padding != 0:
                        creds += '=' * (4 - missing_padding)
                    
                    try:
                        creds_bytes = base64.urlsafe_b64decode(creds)
                        creds_decoded = creds_bytes.decode('utf-8')
                    except (binascii.Error, UnicodeDecodeError):
                        try:
                            creds_bytes = base64.b64decode(creds)
                            creds_decoded = creds_bytes.decode('utf-8')
                        except (binascii.Error, UnicodeDecodeError):
                            creds_decoded = creds
                        
                    if ":" in creds_decoded:
                        method, password = creds_decoded.split(":", 1)
                    else:
                        method = "aes-256-gcm"
                        password = creds_decoded
                except Exception as e:
                    logging.error(f"解析 Shadowsocks 凭据失败: {link[:50]}... 错误: {e}")
                    return None
                
                if method not in VALID_SS_METHODS:
                    logging.warning(f"不支持的 Shadowsocks 加密方法: {method} 在链接: {link[:50]}...")
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
                
                if params.get("plugin"):
                    plugin = params.get("plugin", [""])[0]
                    plugin_opts = ";".join([f"{k}={v[0]}" for k, v in params.items() if k != "plugin"])
                    node["plugin"] = plugin
                    node["plugin_opts"] = plugin_opts
                
                return node
            else:
                logging.warning(f"SS 链接格式不标准（无@符号）: {link[:50]}...")
                return None
        except Exception as e:
            logging.error(f"解析 Shadowsocks 链接失败: {link[:50]}... 错误: {e}")
            return None

    def _parse_ssr(self, link: str) -> Optional[Dict[str, Any]]:
        try:
            base64_str = link[len("ssr://"):]
            missing_padding = len(base64_str) % 4
            if missing_padding != 0:
                base64_str += '=' * (4 - missing_padding)
            
            decoded_str = base64.urlsafe_b64decode(base64_str).decode('utf-8')
            parts = decoded_str.split(":")
            if len(parts) < 6:
                logging.warning(f"SSR 链接格式不完整: {link[:50]}...")
                return None
            
            server, port, protocol, method, obfs, password_b64 = parts[:6]
            password = base64.urlsafe_b64decode(password_b64).decode('utf-8')
            params = {}
            if "/" in decoded_str:
                param_str = decoded_str.split("/?")[1]
                param_pairs = param_str.split("&")
                for pair in param_pairs:
                    k, v = pair.split("=")
                    params[k] = base64.urlsafe_b64decode(v).decode('utf-8')
            
            node = {
                "type": "ssr",
                "name": params.get("remarks", f"SSR-{server}:{port}"),
                "server": server,
                "port": int(port),
                "method": method,
                "password": password,
                "protocol": protocol,
                "obfs": obfs,
                "protocol_param": params.get("protoparam", ""),
                "obfs_param": params.get("obfsparam", ""),
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
                "sni": params.get("sni", [server])[0] if params.get("security", [""]) != ["reality"] else params.get("pbk", [""])[0],
                "fp": params.get("fp", [""])[0],
                "dest": params.get("dest", [""])[0],
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
            port = parsed.port
            params = urllib.parse.parse_qs(parsed.query)
            
            node = {
                "type": "hysteria2",
                "name": urllib.parse.unquote(parsed.fragment or f"{server}:{port}"),
                "server": server,
                "port": port or 443,
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
        tls = node.get("tls", False)

        if network == "ws":
            transport_settings["type"] = "ws"
            transport_settings["path"] = node.get("path", "/")
            transport_settings["headers"] = {"Host": node.get("host", node["server"])}
        elif network == "grpc":
            transport_settings["type"] = "grpc"
            transport_settings["service_name"] = node.get("serviceName", "")
            transport_settings["idle_timeout"] = "15s"
            transport_settings["ping_timeout"] = "15s"

        tls_settings = {}
        if tls:
            tls_settings = {
                "enabled": True,
                "server_name": node.get("sni", node["server"]),
                "insecure": node.get("allowInsecure", False),
                "utls": {"enabled": True, "fingerprint": "chrome"}
            }
            if node.get("reality", False):
                tls_settings["reality"] = {
                    "enabled": True,
                    "public_key": node.get("pbk", ""),
                    "short_id": node.get("sid", ""),
                }
                if node.get("fingerprint"):
                    tls_settings["utls"] = {"enabled": True, "fingerprint": node["fingerprint"]}

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
        elif protocol_type == "trojan":
            outbound["password"] = node["password"]
            outbound["tls"] = tls_settings
        elif protocol_type == "vless":
            outbound.update({
                "uuid": node["uuid"],
                "flow": node.get("flow", ""),
                "tls": tls_settings,
            })
        elif protocol_type == "shadowsocks":
            outbound.update({
                "method": node["method"],
                "password": node["password"],
            })
            if node.get("plugin"):
                outbound["plugin"] = node["plugin"]
                outbound["plugin_opts"] = node["plugin_opts"]
        elif protocol_type == "ssr":
            outbound.update({
                "method": node["method"],
                "password": node["password"],
                "protocol": node["protocol"],
                "obfs": node["obfs"],
                "protocol_param": node["protocol_param"],
                "obfs_param": node["obfs_param"],
            })
        elif protocol_type == "hysteria2":
            outbound.update({
                "password": node["password"],
                "tls": {
                    "enabled": True,
                    "server_name": node.get("sni", node["server"]),
                    "insecure": node.get("insecure", False),
                }
                "obfs": node.get("obfs"", ""none"") if node.get("obfs") else None,
                "obfs_password": node.get("obfs_password", ""),
            })
        else:
            logging.error(f"不支持生成 Singbox 配置的协议类型: {protocol_type}")
            return None

        if transport_settings:
            outbound["transport"] = transport_settings
        
        if tls and protocol_type not in ["trojan", "vless", "hysteria2"]:
            outbound["tls"] = tls_settings

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
    """测度单个节点的延迟"""
    temp_dir = Path(tempfile.mkdtemp(prefix="singbox_test_"))
    config_path = temp_dir / "config.json")
    
    proc = None
    try:
        port = find_available_port()
        config_generator = SingboxConfigGenerator()
        singbox_config = config_generator.generate(node, port)
        
        if not singbox_config:
            logging.error(f"无法为节点 {node.get('name', node.get('server'))} 生成 Singbox 配置。")
            return -1
        
        config_path.write_text(json.dumps(singbox_config, indent=2))
        
        command = [SINGBOX_CORE_PATH, "run", "-c", str(config_path))]
        
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        await asyncio.sleep(1)

        if proc.returncode is not None:
            stdout, stderr = await proc.communicate()
            logging.error(f"Singbox 核心进程启动失败: {config_path}")
            logging.error(f"Stdout: {stdout.decode()}")
            logging.error(f"Stderr: {stderr.decode()}")
            return -1

        proxies = {
            'http': f'socks5://127.0.0.1:{port}',
            'https': f'socks5://127.0.0.1:{port}'
        }

        start_time = time.perf_counter()
        async with aiohttp.ClientSession(headers={"User-Agent": "Mozilla/5.0"}) as session:
            for url in TEST_URLS:
                try:
                    async with session.get(
                        url,
                        proxy=proxies['http'],
                        timeout=CONNECTION_TIMEOUT,
                        allow_redirects=True
                    ) as resp:
                        if resp.status in (200, 204):
                            latency = int((time.perf_counter() - start_time) * 1000)
                            if 0 <= latency <= 10000:
                                return latency
                            logging.warning(f"节点 {node.get('name', node.get('server'))} 延迟过高: {latency}ms")
                            return -1
                        else:
                            logging.debug(f"Node {node.get("name", node.get("server"))} test URL {url} returned non-200/204 status: {resp.status}")
                            continue
                        except (aiohttp.ClientError, asyncio.TimeoutError, ConnectionRefusedError) as e:
                            logging.debug(f"Testing {url} via node {node.get("name", node.get("server"))} failed: {e}")
                            continue
                logging.info(f"Node {node.get("name", node.get("server"))} failed all test URLs.")
                return -1

    except Exception as e:
        logging.error(f"Error testing node {node.get('name', node.get('server'))}: {e}")
        return -1
    finally:
        if proc and proc.returncode is None:
            try:
                proc.terminate()
                await asyncio.wait_for(proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                proc.kill()
            except Exception as e:
                logging.error(f"Error stopping Singbox process: {e}")
        if temp_dir.exists():
            shutil.rmtree(temp_dir)


async def main():
    parser = NodeParser()
    
    unique_nodes_links = set()
    if Path(NODE_FILE_PATH).exists():
        with open(NODE_FILE_PATH, 'r', encoding='utf-8') as f:
            for line in f:
                stripped_line = line.strip()
                if stripped_line and not stripped_line.startswith("#"):
                    unique_nodes_links.add(stripped_line)
    
    logging.info(f"Read {len(unique_nodes_links)} unique node links.")
    parsed_nodes: List[Dict[str, Any]] = []
    for link in unique_nodes_links:
        node = parser.parse(link)
        if node:
            parsed_nodes.append(node)
            
    logging.info(f"Successfully parsed {len(parsed_nodes)} valid nodes.")

    total_nodes = len(parsed_nodes)
    if total_nodes == 0:
        logging.info("No valid nodes to test.")
        return

    sem = asyncio.Semaphore(5)  # 降低并发数以提高稳定性
    results: List[Dict[str, Any]] = []

    async def test_node_task(idx: int, node: Dict[str, Any]):
        async with sem:
            node_id = node.get('name', f"{node['server'][-1]}:{node['port']}")
            latency = await measure_latency(node)
            if 0 <= latency <= 10000:
                node['latency'] = latency
                results.append(node)
                logging.info(f"[{idx}/{total_nodes}] ✓ Node {node_id} passed, latency: {latency} ms")
            else:
                logging.info(f"[{idx}/{total_nodes}] ✗ Node {node_id} invalid or high latency, skipped")

    tasks = [test_node_task(i + 1, node) for i, node in enumerate(parsed_nodes)]
    await asyncio.gather(*tasks)

    results.sort(key=lambda x: x['latency'])

    output_dir = Path(OUTPUT_FILE_PATH).parent
    output_dir.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_FILE_PATH, 'w', encoding='utf-8') as f:
        for node in results:
            f.write(f"{node['original_link']} # {node['name']} [{node['latency']}ms]\n")

    logging.info(f"Test completed: {len(results)} valid nodes out of {total_nodes}, saved to {OUTPUT_FILE_PATH}")


if __name__ == "__main__":
    asyncio.run(main())
