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
import binascii
import re
import os

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
SINGBOX_CORE_PATH = os.getenv("SINGBOX_CORE_PATH", "./sing-box")  # 从环境变量获取

# 支持的 Shadowsocks 加密方法
VALID_SS_METHODS = {
    "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "rc4-md5", "chacha20-ietf", "xchacha20", "none",
    "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"
}

class NodeParser:
    """负责解析不同协议的节点链接"""
    def parse(self, node_link: str) -> Optional[Dict[str, Any]]:
        node_link = node_link.strip()
        if not node_link:
            return None

        original_link = node_link
        node_data = None
        
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
            if not all([password, server, port]):
                raise ValueError("Trojan link missing essential components.")
            
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
            # 验证链接格式
            if not re.match(r'^ss://[\w\-+=/]+(@[\w\.\-]+:\d+.*)?$', link):
                logging.warning(f"无效的 Shadowsocks 链接格式: {link[:50]}...")
                return None

            parts = link[len("ss://"):].split("#")
            tag = urllib.parse.unquote(parts[1]) if len(parts) > 1 else ""
            
            creds_and_addr_with_params = parts[0]
            creds_and_addr, params = creds_and_addr_with_params, {}
            if "?" in creds_and_addr_with_params:
                creds_and_addr, query = creds_and_addr_with_params.split("?", 1)
                params = urllib.parse.parse_qs(query)

            if "@" not in creds_and_addr:
                logging.warning(f"SS 链接缺少 @ 分隔符: {link[:50]}...")
                return None

            creds_b64, addr = creds_and_addr.split("@", 1)
            missing_padding = len(creds_b64) % 4
            if missing_padding:
                creds_b64 += '=' * (4 - missing_padding)
            
            try:
                creds_bytes = base64.urlsafe_b64decode(creds_b64)
                try:
                    creds_decoded = creds_bytes.decode('utf-8')
                except UnicodeDecodeError:
                    # UUID 或二进制密码，可能是 Shadowsocks 2022 协议
                    creds_decoded = creds_bytes.hex()
                    logging.warning(f"SS 链接凭据非 UTF-8，转换为十六进制: {link[:50]}... 凭据: {creds_decoded[:16]}...")
                    method = "2022-blake3-aes-256-gcm"  # 优先尝试 2022 协议
                    password = creds_decoded
                else:
                    # 检查是否为 method:password 格式
                    if ":" in creds_decoded:
                        method, password = creds_decoded.split(":", 1)
                    else:
                        method = "2022-blake3-aes-256-gcm"  # 默认 2022 协议
                        password = creds_decoded
                        logging.warning(f"SS 链接缺少加密方法，使用默认值: {method} for {link[:50]}...")
            except (binascii.Error, UnicodeDecodeError) as e:
                logging.error(f"解码 Shadowsocks 凭据失败: {link[:50]}... 错误: {e}")
                return None

            if method not in VALID_SS_METHODS:
                logging.warning(f"不支持的 Shadowsocks 加密方法: {method} 在链接: {link[:50]}...")
                return None

            if ":" not in addr:
                logging.warning(f"SS 链接地址格式错误（缺少 server:port）: {link[:50]}...")
                return None

            server, port_str = addr.split(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                logging.warning(f"SS 链接端口无效: {port_str} 在链接: {link[:50]}...")
                return None

            node = {
                "type": "shadowsocks",
                "name": tag or f"SS-{server}:{port}",
                "server": server,
                "port": port,
                "method": method,
                "password": password,
            }
            
            if params.get("plugin"):
                node["plugin"] = params.get("plugin", [""])[0]
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
            
            decoded_str = base64.urlsafe_b64decode(base64_str).decode('utf-8')
            
            main_part = decoded_str.split("/?")[0]
            params_part = decoded_str.split("/?")[1] if "/?" in decoded_str else ""
            
            parts = main_part.split(":")
            if len(parts) < 6:
                logging.warning(f"SSR 链接格式不完整: {link[:50]}...")
                return None
            
            server, port, protocol, method, obfs, password_b64 = parts[:6]
            
            password = base64.urlsafe_b64decode(password_b64).decode('utf-8')
            
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
            if not all([uuid, server, port]):
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
                "sni": params.get("sni", [server])[0] if params.get("security", [""]) != ["reality"] else server,
                "pbk": params.get("pbk", [""])[0],
                "sid": params.get("sid", [""])[0],
                "fp": params.get("fp", [""])[0],
                "dest": params.get("dest", [""])[0],
                "allowInsecure": params.get("insecure", ["0"])[0] == "1",
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
                    "sniff": True,
                    "sniff_override_destination": True
                }
            ],
            "outbounds": [
                {"type": "direct", "tag": "direct"},
                {"type": "block", "tag": "block"},
                {"type": "dns", "tag": "dns-out"}
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
                {"protocol": "dns", "outbound": "dns-out"},
                {"network": "tcp,udp", "outbound": "proxy"}
            ],
            "final": "proxy"
        }
        
        return base_config

    def _build_outbound(self, node: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        protocol_type = node['type']
        
        transport_settings = {}
        network = node.get("network", "tcp")
        tls_enabled = node.get("tls", False)
        
        tls_config = {}
        if tls_enabled:
            tls_config = {
                "enabled": True,
                "server_name": node.get("sni", node["server"]),
                "insecure": node.get("allowInsecure", node.get("insecure", False)),
                "utls": {"enabled": True, "fingerprint": node.get("fp", "chrome")}
            }
            if node.get("reality", False) and protocol_type == "vless":
                tls_config["reality"] = {
                    "enabled": True,
                    "public_key": node.get("pbk", ""),
                    "short_id": node.get("sid", ""),
                }
                if node.get("dest"):
                    tls_config["reality"]["dest"] = node["dest"]

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
                "permit_without_stream": True
            }

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
            outbound["tls"] = tls_config

        elif protocol_type == "vless":
            outbound.update({
                "uuid": node["uuid"],
                "flow": node.get("flow", ""),
                "tls": tls_config,
            })

        elif protocol_type == "shadowsocks":
            outbound.update({
                "method": node["method"],
                "password": node["password"],
            })
            if node.get("plugin") == "simple-obfs":
                transport_settings["type"] = "tcp"
                transport_settings["tcp_fast_open"] = True
                transport_settings["obfs"] = {
                    "type": node.get("plugin_opts_type", "http"),
                    "host": node.get("plugin_opts_host", "www.bing.com")
                }
            elif node.get("plugin"):
                logging.warning(f"不支持的 Shadowsocks 插件: {node['plugin']} for {node['name']}")
                return None

        elif protocol_type == "ssr":
            logging.warning(f"Singbox 不原生支持 SSR，尝试转换为 Shadowsocks: {node['name']}")
            outbound["type"] = "shadowsocks"
            outbound["method"] = node["method"]
            outbound["password"] = node["password"]
            
            supported_obfs = {
                "plain": None,
                "http_simple": {"type": "tcp", "obfs": {"type": "http", "host": node.get("obfs_param", "www.bing.com")}},
                "http_post": {"type": "tcp", "obfs": {"type": "http", "host": node.get("obfs_param", "www.bing.com")}},
                "tls1.2_ticket_auth": {"type": "tcp", "obfs": {"type": "tls", "host": node.get("obfs_param", "www.bing.com")}}
            }
            
            if node["obfs"] in supported_obfs and supported_obfs[node["obfs"]]:
                transport_settings.update(supported_obfs[node["obfs"]])
            elif node["obfs"] != "plain":
                logging.warning(f"不支持的 SSR 混淆类型: {node['obfs']} for {node['name']}")
                return None
            
            if node["protocol"] != "origin":
                logging.warning(f"不支持的 SSR 协议: {node['protocol']} for {node['name']}")
                return None

        elif protocol_type == "hysteria2":
            outbound.update({
                "password": node["password"],
            })
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
            
        else:
            logging.error(f"不支持生成 Singbox 配置的协议类型: {protocol_type}")
            return None

        if transport_settings:
            outbound["transport"] = transport_settings
        
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
        # 验证 Sing-box 核心路径
        singbox_path = Path(SINGBOX_CORE_PATH)
        if not singbox_path.exists() or not singbox_path.is_file():
            logging.error(f"Sing-box 核心路径无效: {SINGBOX_CORE_PATH}")
            return -1
        if not os.access(singbox_path, os.X_OK):
            logging.error(f"Sing-box 核心不可执行: {SINGBOX_CORE_PATH}")
            return -1

        port = find_available_port()
        config_generator = SingboxConfigGenerator()
        singbox_config = config_generator.generate(node, port)
        
        if not singbox_config:
            logging.error(f"无法为节点 {node.get('name', node.get('server'))} 生成 Singbox 配置")
            return -1
        
        config_path.write_text(json.dumps(singbox_config, indent=2))
        
        command = [str(singbox_path), "run", "-c", str(config_path)]
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        wait_time = 2.0 if node["type"] == "hysteria2" else 1.5
        await asyncio.sleep(wait_time)

        if proc.returncode is not None:
            stdout, stderr = await proc.communicate()
            logging.error(f"Singbox 启动失败 (节点: {node.get('name', node.get('server'))})")
            logging.error(f"配置文件内容: {config_path.read_text()}")
            logging.error(f"Stdout: {stdout.decode(errors='ignore')}")
            logging.error(f"Stderr: {stderr.decode(errors='ignore')}")
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
                            logging.warning(f"节点 {node.get('name', node.get('server'))} 延迟不合理: {latency}ms")
                            return -1
                        logging.debug(f"节点 {node.get('name', node.get('server'))} 测试 URL {url} 返回状态码: {resp.status}")
                        continue
                except (aiohttp.ClientError, asyncio.TimeoutError, ConnectionRefusedError) as e:
                    logging.debug(f"节点 {node.get('name', node.get('server'))} 测试 URL {url} 失败: {type(e).__name__}: {e}")
                    continue
            logging.info(f"节点 {node.get('name', node.get('server'))} 未能通过所有测试 URL")
            return -1

    except Exception as e:
        logging.error(f"测试节点 {node.get('name', node.get('server'))} 时发生异常: {type(e).__name__}: {e}")
        return -1
    finally:
        if proc and proc.returncode is None:
            try:
                proc.terminate()
                await asyncio.wait_for(proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                proc.kill()
            except Exception as e:
                logging.error(f"停止 Singbox 进程时发生错误: {type(e).__name__}: {e}")
        if temp_dir.exists():
            shutil.rmtree(temp_dir, ignore_errors=True)

async def main():
    parser = NodeParser()
    
    # 验证节点文件
    if not Path(NODE_FILE_PATH).exists():
        logging.error(f"节点文件 {NODE_FILE_PATH} 不存在")
        return
    
    # 读取节点并去重
    unique_nodes_links = set()
    with open(NODE_FILE_PATH, 'r', encoding='utf-8') as f:
        for line in f:
            stripped_line = line.strip()
            if stripped_line and not stripped_line.startswith("#"):
                unique_nodes_links.add(stripped_line)
    
    logging.info(f"读取到 {len(unique_nodes_links)} 个去重后的节点链接")

    parsed_nodes: List[Dict[str, Any]] = []
    for link in unique_nodes_links:
        node = parser.parse(link)
        if node:
            parsed_nodes.append(node)
            
    logging.info(f"成功解析出 {len(parsed_nodes)} 个有效节点配置")

    # 异步测试所有节点（分批处理）
    total_nodes_to_test = len(parsed_nodes)
    if total_nodes_to_test == 0:
        logging.info("没有可测试的节点")
        return

    batch_size = 1000  # 每批测试 1000 个节点
    sem = asyncio.Semaphore(5)
    results: List[Dict[str, Any]] = []

    async def _test_node_task(idx: int, node: Dict[str, Any]):
        async with sem:
            node_id = node.get('name', f"{node['server']}:{node['port']}")
            latency = await measure_latency(node)
            if 0 <= latency <= 10000:
                node['latency'] = latency
                results.append(node)
                logging.info(f"[{idx}/{total_nodes_to_test}] ✓ 节点 {node_id} 测试通过，延迟: {latency} ms")
            else:
                logging.info(f"[{idx}/{total_nodes_to_test}] ✗ 节点 {node_id} 无效或延迟过高，已跳过")

    for i in range(0, len(parsed_nodes), batch_size):
        batch = parsed_nodes[i:i + batch_size]
        tasks = [_test_node_task(i + j + 1, node) for j, node in enumerate(batch)]
        await asyncio.gather(*tasks)

    # 保存测试结果
    results.sort(key=lambda x: x['latency'])

    output_dir = Path(OUTPUT_FILE_PATH).parent
    output_dir.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_FILE_PATH, 'w', encoding='utf-8') as f:
        for node in results:
            f.write(f"{node.get('original_link', node.get('name', 'UNKNOWN_LINK'))} # {node['name']} [{node['latency']}ms]\n")

    logging.info(f"测试完成：共处理 {total_nodes_to_test} 个节点，其中 {len(results)} 个有效，结果已保存到 {OUTPUT_FILE_PATH}")

if __name__ == "__main__":
    asyncio.run(main())
