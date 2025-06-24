import os
import re
import json
import yaml
import base64
import hashlib
import asyncio
import logging
import socket
import ssl
from urllib.parse import urlparse, unquote, parse_qs
from typing import List, Dict, Optional
from tqdm.asyncio import tqdm_asyncio
import aiofiles
from pathlib import Path
import pycountry
import httpx

# --- 配置 ---
CONFIG_FILE = "config.yaml"  # 外部配置文件
DEFAULT_CONFIG = {
    "input": {
        "sub_file": "data/sub.txt",
        "history_file": "data/history_results.json",
    },
    "output": {
        "dir": "data/",
        "json_file": "enhanced_nodes.json",
        "clash_file": "sub_clash.yaml",
        "v2ray_file": "sub_v2ray.json",
        "quantumult_file": "sub_quantumult.conf",
        "base64_file": "sub_base64.txt",
        "checksum_file": "checksums.txt",
    },
    "test": {
        "timeout_seconds": float(os.getenv("TEST_TIMEOUT", 1)),
        "max_concurrent": 50,
    },
    "log": {
        "level": os.getenv("LOG_LEVEL", "INFO").upper(),
        "file": "data/logfile.txt",
    },
    "output_format": os.getenv("OUTPUT_FORMAT", "all").lower(),  # json,clash,v2ray,quantumult,base64,all
}

# 加载外部配置
def load_config():
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f)
            return {**DEFAULT_CONFIG, **config}
        return DEFAULT_CONFIG
    except Exception as e:
        logging.error(f"加载配置文件 {CONFIG_FILE} 失败: {e}")
        return DEFAULT_CONFIG

CONFIG = load_config()

# --- 日志配置 ---
logging.basicConfig(
    level=getattr(logging, CONFIG["log"]["level"], logging.INFO),
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(CONFIG["log"]["file"], encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)

# --- 正则表达式 ---
PROTOCOL_RE = re.compile(r"^(vless|vmess|trojan|ss|hy2|hysteria2):\/\/[^\s]+$", re.IGNORECASE)
NODE_LINK_RE = re.compile(r"^(vless|vmess|trojan|ss|hy2|hysteria2):\/\/(.*)")
HOST_PORT_FULL_RE = re.compile(r"^(?:\[([0-9a-fA-F:]+)\]|([0-9]{1,3}(?:\.[0-9]{1,3}){3})|([a-zA-Z0-9.-]+)):([0-9]+)$")

# --- 数据结构 ---
class NodeInfo:
    def __init__(
        self,
        original_link: str,
        protocol: str,
        server: str,
        port: int,
        remarks: str,
        delay_ms: float = -1,
        status: str = "Unknown",
        country: Optional[str] = None,
        params: Dict = None,
    ):
        self.original_link = original_link
        self.protocol = protocol
        self.server = server
        self.port = port
        self.remarks = remarks
        self.delay_ms = delay_ms
        self.status = status
        self.country = country
        self.params = params or {}

    def to_dict(self) -> Dict:
        return {
            "original_link": self.original_link,
            "protocol": self.protocol,
            "server": self.server,
            "port": self.port,
            "remarks": self.remarks,
            "delay_ms": self.delay_ms,
            "status": self.status,
            "country": self.country,
            "params": self.params,
        }

# --- 辅助函数 ---
def infer_country(remarks: str, server: str) -> Optional[str]:
    try:
        country_keywords = {
            "US": "United States",
            "JP": "Japan",
            "SG": "Singapore",
            "HK": "Hong Kong",
            "CN": "China",
            "DE": "Germany",
            "FR": "France",
            "UK": "United Kingdom",
        }
        remarks_lower = remarks.lower()
        server_lower = server.lower()
        for code, name in country_keywords.items():
            if code.lower() in remarks_lower or name.lower() in remarks_lower:
                country = pycountry.countries.get(alpha_2=code)
                return country.name if country else name
        tld = server_lower.split(".")[-1]
        country = pycountry.countries.get(alpha_2=tld.upper())
        return country.name if country else None
    except Exception as e:
        logger.debug(f"推断国家失败: {e}")
        return None

def normalize_link(link: str) -> str:
    try:
        parsed = urlparse(link)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/")
    except Exception:
        return link

def parse_node_info(link: str, history_data: Dict) -> Optional[NodeInfo]:
    try:
        link = link.strip()
        if not link or not PROTOCOL_RE.match(link):
            logger.debug(f"无效链接: {link}")
            return None

        match = NODE_LINK_RE.match(link)
        if not match:
            logger.debug(f"无法识别协议: {link}")
            return None

        protocol = match.group(1).lower()
        remaining_part = match.group(2)
        params = {}
        remarks = f"{protocol.upper()} 节点"

        if "#" in remaining_part:
            remaining_part, remark_part = remaining_part.rsplit("#", 1)
            remarks = unquote(remark_part)

        if protocol in ["vless", "trojan"]:
            if "@" in remaining_part:
                user_info, host_port = remaining_part.split("@", 1)
                params["uuid"] = user_info
            else:
                return None
            if "?" in host_port:
                host_port, query = host_port.split("?", 1)
                params.update({k: v[0] for k, v in parse_qs(query).items()})
            host_match = HOST_PORT_FULL_RE.match(host_port)
            if not host_match:
                return None
            server = host_match.group(1) or host_match.group(2) or host_match.group(3)
            port = int(host_match.group(4))
            params["security"] = params.get("security", "none")
            params["type"] = params.get("type", "tcp")

        elif protocol == "vmess":
            try:
                decoded = base64.b64decode(remaining_part).decode("utf-8")
                vmess_data = json.loads(decoded)
                server = vmess_data.get("add")
                port = int(vmess_data.get("port", 0))
                params = {
                    "uuid": vmess_data.get("id"),
                    "security": vmess_data.get("scy", "auto"),
                    "type": vmess_data.get("net", "tcp"),
                    "host": vmess_data.get("host", ""),
                    "path": vmess_data.get("path", ""),
                    "tls": "tls" if vmess_data.get("tls") == "tls" else "none",
                }
            except Exception:
                return None

        elif protocol == "ss":
            if "@" in remaining_part:
                user_info, host_port = remaining_part.split("@", 1)
                if ":" in user_info:
                    method, password = user_info.split(":", 1)
                    params["method"] = method
                    params["password"] = password
                host_match = HOST_PORT_FULL_RE.match(host_port)
                if not host_match:
                    return None
                server = host_match.group(1) or host_match.group(2) or host_match.group(3)
                port = int(host_match.group(4))
            else:
                return None

        elif protocol in ["hy2", "hysteria2"]:
            parts = remaining_part.split("?", 1)
            host_port = parts[0]
            if len(parts) > 1:
                params.update({k: v[0] for k, v in parse_qs(parts[1]).items()})
            host_match = HOST_PORT_FULL_RE.match(host_port)
            if not host_match:
                return None
            server = host_match.group(1) or host_match.group(2) or host_match.group(3)
            port = int(host_match.group(4))
            params["password"] = params.get("auth", "")

        else:
            return None

        if not (1 <= port <= 65535):
            return None

        node_id = normalize_link(link)
        delay_ms = history_data.get(node_id, {}).get("delay_ms", -1)
        status = history_data.get(node_id, {}).get("status", "Unknown")
        country = infer_country(remarks, server)

        return NodeInfo(
            original_link=link,
            protocol=protocol,
            server=server,
            port=port,
            remarks=remarks,
            delay_ms=delay_ms,
            status=status,
            country=country,
            params=params,
        )
    except Exception as e:
        logger.error(f"解析链接 {link} 失败: {e}")
        return None

async def verify_node(node: NodeInfo) -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(CONFIG["test"]["timeout_seconds"])
        await asyncio.get_event_loop().run_in_executor(
            None, sock.connect, (node.server, node.port)
        )
        if node.params.get("security") == "tls" or node.params.get("tls") == "tls":
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sni = node.params.get("sni") or node.params.get("host") or node.server
            wrapped_socket = context.wrap_socket(sock, server_hostname=sni)
            await asyncio.get_event_loop().run_in_executor(
                None, wrapped_socket.do_handshake
            )
            wrapped_socket.close()
        sock.close()
        node.status = "Successful"
        return True
    except Exception as e:
        logger.warning(f"验证节点 {node.remarks} 失败: {e}")
        node.status = "Failed"
        return False
    finally:
        if "wrapped_socket" in locals():
            wrapped_socket.close()
        sock.close()

async def read_sub_txt() -> List[str]:
    try:
        sub_file = CONFIG["input"]["sub_file"]
        if not os.path.exists(sub_file):
            logger.error(f"输入文件 {sub_file} 不存在")
            return []
        async with aiofiles.open(sub_file, "r", encoding="utf-8") as f:
            content = await f.read()
            links = [line.strip() for line in content.split("\n") if line.strip() and not line.startswith("#")]
            logger.info(f"从 {sub_file} 读取到 {len(links)} 条节点链接")
            return links
    except Exception as e:
        logger.error(f"读取 {sub_file} 失败: {e}")
        return []

async def read_history() -> Dict:
    try:
        history_file = CONFIG["input"]["history_file"]
        if not os.path.exists(history_file):
            logger.warning(f"历史文件 {history_file} 不存在")
            return {}
        async with aiofiles.open(history_file, "r", encoding="utf-8") as f:
            content = await f.read()
            if content:
                return json.loads(content)
            logger.warning(f"历史文件 {history_file} 为空")
            return {}
    except Exception as e:
        logger.error(f"读取 {history_file} 失败: {e}")
        return {}

async def process_nodes(links: List[str], history_data: Dict) -> List[NodeInfo]:
    semaphore = asyncio.Semaphore(CONFIG["test"]["max_concurrent"])
    async def verify_with_semaphore(node: NodeInfo) -> NodeInfo:
        async with semaphore:
            await verify_node(node)
            return node

    nodes = []
    for link in tqdm_asyncio(links, desc="解析节点", unit="节点"):
        node_info = parse_node_info(link, history_data)
        if node_info:
            nodes.append(node_info)

    if not nodes:
        logger.warning("没有有效节点")
        return []

    verified_nodes = []
    tasks = [verify_with_semaphore(node) for node in nodes]
    for future in tqdm_asyncio.as_completed(tasks, desc="验证节点", unit="节点"):
        node = await future
        if node.status == "Successful":
            verified_nodes.append(node)

    return verified_nodes

def generate_clash_config(nodes: List[NodeInfo]) -> Dict:
    proxies = []
    for node in nodes:
        proxy = {
            "name": node.remarks,
            "server": node.server,
            "port": node.port,
            "type": node.protocol,
        }
        if node.protocol == "vless":
            proxy.update({
                "uuid": node.params.get("uuid"),
                "network": node.params.get("type", "tcp"),
                "tls": node.params.get("security") == "tls",
                "sni": node.params.get("sni", node.server),
            })
        elif node.protocol == "vmess":
            proxy.update({
                "uuid": node.params.get("uuid"),
                "alterId": 0,
                "cipher": node.params.get("security", "auto"),
                "network": node.params.get("type", "tcp"),
                "tls": node.params.get("tls") == "tls",
                "sni": node.params.get("host", node.server),
            })
        elif node.protocol == "trojan":
            proxy.update({
                "password": node.params.get("uuid"),
                "network": node.params.get("type", "tcp"),
                "sni": node.params.get("sni", node.server),
            })
        elif node.protocol == "ss":
            proxy.update({
                "cipher": node.params.get("method"),
                "password": node.params.get("password"),
            })
        elif node.protocol in ["hy2", "hysteria2"]:
            proxy.update({
                "password": node.params.get("password"),
                "sni": node.params.get("sni", node.server),
            })
        proxies.append(proxy)

    # 动态分组
    countries = {node.country for node in nodes if node.country}
    proxy_groups = [
        {"name": "Auto", "type": "select", "proxies": [node.remarks for node in nodes]},
        {"name": "LowLatency", "type": "select", "proxies": [node.remarks for node in nodes if node.delay_ms > 0 and node.delay_ms < 200]},
    ]
    for country in countries:
        proxy_groups.append({
            "name": country,
            "type": "select",
            "proxies": [node.remarks for node in nodes if node.country == country],
        })

    return {
        "proxies": proxies,
        "proxy-groups": proxy_groups,
        "rules": ["MATCH,Auto"],
    }

def generate_v2ray_config(nodes: List[NodeInfo]) -> Dict:
    outbounds = []
    for node in nodes:
        outbound = {
            "tag": node.remarks,
            "protocol": node.protocol,
            "settings": {},
        }
        if node.protocol in ["vless", "vmess"]:
            outbound["settings"] = {
                "vnext": [{
                    "address": node.server,
                    "port": node.port,
                    "users": [{"id": node.params.get("uuid"), "security": node.params.get("security", "auto")}],
                }]
            }
        elif node.protocol == "trojan":
            outbound["settings"] = {
                "servers": [{"address": node.server, "port": node.port, "password": node.params.get("uuid")}]
            }
        elif node.protocol == "ss":
            outbound["settings"] = {
                "servers": [{"address": node.server, "port": node.port, "method": node.params.get("method"), "password": node.params.get("password")}]
            }
        outbounds.append(outbound)
    return {"outbounds": outbounds}

def generate_quantumult_config(nodes: List[NodeInfo]) -> str:
    lines = []
    for node in nodes:
        if node.protocol == "ss":
            line = f"shadowsocks={node.server}:{node.port},{node.params.get('method')},{node.params.get('password')},tag={node.remarks}"
            lines.append(line)
        elif node.protocol in ["vless", "trojan"]:
            line = f"trojan={node.server}:{node.port},password={node.params.get('uuid')},sni={node.params.get('sni', node.server)},tag={node.remarks}"
            lines.append(line)
    return "\n".join(lines)

async def save_outputs(nodes: List[NodeInfo], output_format: str):
    os.makedirs(CONFIG["output"]["dir"], exist_ok=True)
    checksums = {}

    async def save_file(content: str, filename: str):
        try:
            async with aiofiles.open(filename, "w", encoding="utf-8") as f:
                await f.write(content)
            with open(filename, "rb") as f:
                checksums[filename] = hashlib.sha256(f.read()).hexdigest()
            logger.info(f"已保存到 {filename}")
        except Exception as e:
            logger.error(f"保存 {filename} 失败: {e}")

    tasks = []
    if output_format in ["json", "all"]:
        tasks.append(save_file(
            json.dumps([node.to_dict() for node in nodes], indent=2, ensure_ascii=False),
            os.path.join(CONFIG["output"]["dir"], CONFIG["output"]["json_file"])
        ))
    if output_format in ["clash", "all"]:
        tasks.append(save_file(
            yaml.dump(generate_clash_config(nodes), allow_unicode=True, sort_keys=False),
            os.path.join(CONFIG["output"]["dir"], CONFIG["output"]["clash_file"])
        ))
    if output_format in ["v2ray", "all"]:
        tasks.append(save_file(
            json.dumps(generate_v2ray_config(nodes), indent=2, ensure_ascii=False),
            os.path.join(CONFIG["output"]["dir"], CONFIG["output"]["v2ray_file"])
        ))
    if output_format in ["quantumult", "all"]:
        tasks.append(save_file(
            generate_quantumult_config(nodes),
            os.path.join(CONFIG["output"]["dir"], CONFIG["output"]["quantumult_file"])
        ))
    if output_format in ["base64", "all"]:
        links = [node.original_link for node in nodes]
        base64_content = base64.b64encode("\n".join(links).encode("utf-8")).decode("utf-8")
        tasks.append(save_file(
            base64_content,
            os.path.join(CONFIG["output"]["dir"], CONFIG["output"]["base64_file"])
        ))

    await asyncio.gather(*tasks)

    # 保存校验和
    checksum_file = os.path.join(CONFIG["output"]["dir"], CONFIG["output"]["checksum_file"])
    try:
        async with aiofiles.open(checksum_file, "w", encoding="utf-8") as f:
            for filename, checksum in checksums.items():
                await f.write(f"{checksum}  {os.path.basename(filename)}\n")
        logger.info(f"已保存校验和到 {checksum_file}")
    except Exception as e:
        logger.error(f"保存校验和失败: {e}")

async def main():
    start_time = time.time()
    logger.info("开始处理节点数据")

    links = await read_sub_txt()
    history_data = await read_history()
    if not links:
        logger.warning("没有有效节点链接，退出")
        await save_outputs([], CONFIG["output_format"])
        return

    nodes = await process_nodes(links, history_data)
    logger.info(f"有效节点数: {len(nodes)}")

    await save_outputs(nodes, CONFIG["output_format"])

    logger.info(f"处理完成，总耗时: {time.time() - start_time:.2f} 秒")

if __name__ == "__main__":
    asyncio.run(main())
