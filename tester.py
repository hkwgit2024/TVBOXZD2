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
# 请根据实际情况设置 Singbox 核心的路径
# 如果在 GitHub Actions 中，需要确保 Singbox 核心可执行文件被下载到此路径
SINGBOX_CORE_PATH = "./sing-box"

class NodeParser:
    """负责解析不同协议的节点链接"""
    def parse(self, node_link: str) -> Optional[Dict[str, Any]]:
        node_link = node_link.strip()
        if not node_link:
            return None

        if node_link.startswith("vmess://"):
            return self._parse_vmess(node_link)
        elif node_link.startswith("trojan://"):
            return self._parse_trojan(node_link)
        elif node_link.startswith("ss://"):
            return self._parse_shadowsocks(node_link)
        elif node_link.startswith("vless://"):
            return self._parse_vless(node_link)
        # TODO: 添加对其他协议（如 hysteria2://, tuic:// 等）的解析
        else:
            logging.warning(f"警告: 不支持或无法识别的节点链接格式: {node_link[:50]}...")
            return None

    def _parse_vmess(self, link: str) -> Optional[Dict[str, Any]]:
        try:
            # VMess 链接通常是 base64 编码的 JSON
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
            # 更多 Vmess 网络设置可以根据需要添加
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
                "tls": True, # Trojan 默认要求 TLS
                "sni": params.get("sni", [server])[0],
                "host": params.get("host", [server])[0],
                "path": params.get("path", ["/"])[0],
                "allowInsecure": params.get("allowInsecure", ["0"])[0] == "1",
            }
            # 更多 Trojan 网络设置可以根据需要添加
            return node
        except Exception as e:
            logging.error(f"解析 Trojan 链接失败: {link[:50]}... 错误: {e}")
            return None

    def _parse_shadowsocks(self, link: str) -> Optional[Dict[str, Any]]:
        try:
            # ss://method:password@server:port#tag
            parts = link[len("ss://"):].split("#")
            tag = urllib.parse.unquote(parts[1]) if len(parts) > 1 else ""
            
            creds_and_addr = parts[0]
            if "@" in creds_and_addr:
                creds_b64, addr = creds_and_addr.split("@", 1)
                creds = base64.b64decode(creds_b64).decode('utf-8')
                method, password = creds.split(":", 1)
            else:
                # SS Simple-Obfs or Plugin format (ss://[method:password@]server:port?plugin=...)
                # For simplicity, assume base64 credentials for now.
                # Complex SS links with plugins might require more advanced parsing.
                logging.warning(f"SS链接格式复杂，尝试基础解析: {link}")
                return None # 需要更复杂的正则或库来解析带插件的SS链接

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
            return node
        except Exception as e:
            logging.error(f"解析 Shadowsocks 链接失败: {link[:50]}... 错误: {e}")
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
                "encryption": "none", # VLESS 默认 encryption 为 none
                "flow": params.get("flow", [""])[0],
                "network": params.get("type", ["tcp"])[0],
                "tls": params.get("security", [""]) == ["tls"],
                "reality": params.get("security", [""]) == ["reality"], # VLESS + Reality
                "sni": params.get("sni", [server])[0] if params.get("security", [""]) != ["reality"] else params.get("pbk", [""])[0], # for reality, sni is serviceName in some clients
                "fp": params.get("fp", [""])[0], # fingerprint for reality
                "dest": params.get("dest", [""])[0], # dest for reality
            }
            if node["network"] == "ws":
                node["path"] = params.get("path", ["/"])[0]
                node["host"] = params.get("host", [server])[0]
            elif node["network"] == "grpc":
                node["serviceName"] = params.get("serviceName", [""])[0]
                node["multiMode"] = params.get("multiMode", ["0"])[0] == "1"
            # 更多 Vless 网络设置可以根据需要添加
            return node
        except Exception as e:
            logging.error(f"解析 VLESS 链接失败: {link[:50]}... 错误: {e}")
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
            "log": {"level": "warn"}, # reduce log verbosity
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
        
        # 将生成的出站添加到配置中，并确保其tag为proxy
        outbound["tag"] = "proxy"
        base_config["outbounds"].insert(0, outbound) # 插入到direct之前

        # 路由规则：所有流量走proxy
        base_config["route"] = {
            "rules": [
                {"protocol": ["dns"], "outbound": "dns-out"}, # optional, if you want specific DNS handling
                {"outbound": "proxy"}
            ],
            "final": "proxy" # 确保所有未匹配的流量走proxy
        }
        
        return base_config

    def _build_outbound(self, node: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        protocol_type = node['type']
        
        # 共同的传输层设置
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
            transport_settings["idle_timeout"] = "15s" # 默认值
            transport_settings["ping_timeout"] = "15s" # 默认值
            # multi_mode in singbox is usually for inbound, for outbound it's simplified.
        # 对于其他网络类型，如 tcp, h2, quic 等，Singbox 的配置方式略有不同

        # TLS/Reality 设置
        tls_settings = {}
        if tls:
            tls_settings = {
                "enabled": True,
                "server_name": node.get("sni", node["server"]),
                "insecure": node.get("allowInsecure", False),
                "utls": {"enabled": True, "fingerprint": "chrome"} # 默认使用chrome指纹
            }
            if node.get("reality", False): # VLESS + Reality
                tls_settings["reality"] = {
                    "enabled": True,
                    "public_key": node.get("pbk", ""), # Assuming 'pbk' key for public_key
                    "short_id": node.get("sid", ""), # Assuming 'sid' for short_id
                }
                if node.get("fingerprint"):
                    tls_settings["utls"] = {"enabled": True, "fingerprint": node["fingerprint"]}


        outbound = {
            "type": protocol_type,
            "server": node["server"],
            "server_port": node["port"],
        }
        
        # 根据协议类型填充特有设置
        if protocol_type == "vmess":
            outbound.update({
                "uuid": node["uuid"],
                "security": node.get("security", "auto"),
                "alter_id": node.get("alterId", 0),
            })
        elif protocol_type == "trojan":
            outbound["password"] = node["password"]
            outbound["tls"] = tls_settings # Trojan 强制 TLS
        elif protocol_type == "vless":
            outbound.update({
                "uuid": node["uuid"],
                "flow": node.get("flow", ""),
                "tls": tls_settings, # VLESS TLS settings
            })
        elif protocol_type == "shadowsocks":
            outbound.update({
                "method": node["method"],
                "password": node["password"],
            })
            # SS可能也有插件或混淆，需要根据node信息填充
        elif protocol_type == "http":
            outbound.update({
                "username": node.get("username"),
                "password": node.get("password")
            })
        elif protocol_type == "socks":
            outbound.update({
                "username": node.get("username"),
                "password": node.get("password")
            })
        else:
            logging.debug(f"不支持生成 Singbox 配置的协议类型: {protocol_type}")
            return None

        # 添加传输层设置
        if transport_settings:
            outbound["transport"] = transport_settings
        
        # 添加 TLS 设置（VLESS 和 VMESS 在 Singbox 中 TLS 是独立字段，Trojan 在协议内）
        if tls and protocol_type not in ["trojan", "vless"]: # VLESS, Trojan have it nested
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
    """测量单个节点的延迟"""
    temp_dir = Path(tempfile.mkdtemp(prefix="singbox_test_"))
    config_path = temp_dir / "config.json"
    
    proc = None
    try:
        port = find_available_port()
        config_generator = SingboxConfigGenerator()
        singbox_config = config_generator.generate(node, port)
        
        if not singbox_config:
            logging.error(f"无法为节点 {node.get('name', node.get('server'))} 生成 Singbox 配置。")
            return -1
        
        config_path.write_text(json.dumps(singbox_config, indent=2))
        
        # 启动 Singbox 核心进程
        # 注意: 在 GitHub Actions 中，需要确保 SINGBOX_CORE_PATH 是可执行的
        command = [SINGBOX_CORE_PATH, "run", "-c", str(config_path)]
        
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        # 稍微等待 Singbox 启动
        await asyncio.sleep(1) 

        if proc.returncode is not None:
            stdout, stderr = await proc.communicate()
            logging.error(f"Singbox 核心进程启动失败，检查配置：{config_path}")
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
                except (aiohttp.ClientError, asyncio.TimeoutError, ConnectionRefusedError) as e:
                    logging.debug(f"通过节点 {node.get('name', node.get('server'))} 测试 URL {url} 失败: {e}")
                    continue
            logging.info(f"节点 {node.get('name', node.get('server'))} 未能通过所有测试 URL。")
            return -1 # 所有URL都失败

    except Exception as e:
        logging.error(f"测试节点 {node.get('name', node.get('server'))} 时发生异常: {e}")
        return -1
    finally:
        if proc and proc.returncode is None: # 如果进程仍在运行
            try:
                proc.terminate()
                await asyncio.wait_for(proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                proc.kill()
            except Exception as e:
                logging.error(f"停止 Singbox 进程时发生错误: {e}")
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

    sem = asyncio.Semaphore(10)  # 控制并发数，可根据服务器性能调整
    results: List[Dict[str, Any]] = []

    async def _test_node_task(idx: int, node: Dict[str, Any]):
        async with sem:
            node_id = node.get('name', f"{node['server']}:{node['port']}")
            latency = await measure_latency(node)
            if 0 <= latency <= 10000: # 再次检查延迟范围
                node['latency'] = latency
                node['name'] = f"{node['name']} [{latency}ms]"
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
            # 您可以选择输出原始链接或带有延迟信息的名称
            # 这里以原始链接为例，如果需要，也可以输出其他格式
            if 'original_link' in node: # 如果解析时保存了原始链接
                 f.write(f"{node['original_link']} #{node['name']}\n")
            else:
                f.write(f"{node['name']}\n") # 如果没有原始链接，就只输出名称

    logging.info(f"测试完成：共处理 {total_nodes_to_test} 个节点，其中 {len(results)} 个有效，结果已保存到 {OUTPUT_FILE_PATH}")


if __name__ == "__main__":
    asyncio.run(main())
