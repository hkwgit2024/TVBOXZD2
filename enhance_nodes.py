import asyncio
import json
import logging
import os
import re
import socket
import ssl
import time
import hashlib
from pathlib import Path
import aiofiles
from tqdm.asyncio import tqdm_asyncio
from typing import List, Dict, Optional
from urllib.parse import urlparse, unquote
import pycountry
import yaml

# --- 配置 ---
CONFIG_FILE = "config.yaml"
DEFAULT_CONFIG = {
    "input": {
        "sub_file": "data/sub.txt",
        "history_file": "data/history_results.json",
    },
    "output": {
        "dir": "data/",
        "nodes_file": "enhanced_nodes.txt",
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
}

def load_config() -> Dict:
    """加载配置文件，合并默认配置和自定义配置"""
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
    ):
        self.original_link = original_link
        self.protocol = protocol
        self.server = server
        self.port = port
        self.remarks = remarks
        self.delay_ms = delay_ms
        self.status = status
        self.country = country

    def to_string(self) -> str:
        """生成明文格式：链接 | 备注 | 延迟 | 状态 | 国家"""
        return (
            f"{self.original_link} | Remarks: {self.remarks} | Delay: {self.delay_ms:.2f}ms | "
            f"Status: {self.status} | Country: {self.country or 'Unknown'}"
        )

# --- 辅助函数 ---
def infer_country(remarks: str, server: str) -> Optional[str]:
    """根据备注或服务器域名推断国家/地区"""
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
    """规范化链接，用于匹配历史记录"""
    try:
        parsed = urlparse(link)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/")
    except Exception:
        return link

def parse_node_info(link: str, history_data: Dict) -> Optional[NodeInfo]:
    """解析节点链接，提取信息并结合历史数据"""
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
        remarks = f"{protocol.upper()} 节点"

        if "#" in remaining_part:
            remaining_part, remark_part = remaining_part.rsplit("#", 1)
            remarks = unquote(remark_part)

        host_port_str = remaining_part.split("?")[0] if "?" in remaining_part else remaining_part
        if "@" in host_port_str:
            _, host_port_str = host_port_str.split("@", 1)

        host_match = HOST_PORT_FULL_RE.match(host_port_str)
        if not host_match:
            logger.debug(f"无法解析主机:端口: {host_port_str}")
            return None

        server = host_match.group(1) or host_match.group(2) or host_match.group(3)
        port = int(host_match.group(4))
        if not (1 <= port <= 65535):
            logger.debug(f"端口无效: {port}")
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
        )
    except Exception as e:
        logger.error(f"解析链接 {link} 失败: {e}")
        return None

async def verify_node(node: NodeInfo) -> bool:
    """验证节点连接性"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(CONFIG["test"]["timeout_seconds"])
        await asyncio.get_event_loop().run_in_executor(
            None, sock.connect, (node.server, node.port)
        )
        sock.close()
        node.status = "Successful"
        return True
    except Exception as e:
        logger.warning(f"验证节点 {node.remarks} 失败: {e}")
        node.status = "Failed"
        return False
    finally:
        sock.close()

async def read_sub_txt() -> List[str]:
    """读取 sub.txt 文件"""
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
    """读取历史测试结果"""
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
    """处理节点，解析并验证"""
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

    # 按延迟排序（延迟未知的放在最后）
    return sorted(verified_nodes, key=lambda x: x.delay_ms if x.delay_ms > 0 else float("inf"))

async def save_outputs(nodes: List[NodeInfo]):
    """保存明文节点和校验和"""
    os.makedirs(CONFIG["output"]["dir"], exist_ok=True)
    checksums = {}

    nodes_file = os.path.join(CONFIG["output"]["dir"], CONFIG["output"]["nodes_file"])
    try:
        content = "\n".join(node.to_string() for node in nodes)
        async with aiofiles.open(nodes_file, "w", encoding="utf-8") as f:
            await f.write(content)
        with open(nodes_file, "rb") as f:
            checksums[nodes_file] = hashlib.sha256(f.read()).hexdigest()
        # 验证文件存在
        if os.path.exists(nodes_file):
            logger.info(f"已保存 {len(nodes)} 个节点到 {nodes_file}, 文件存在")
        else:
            logger.error(f"文件 {nodes_file} 未生成")
    except Exception as e:
        logger.error(f"保存 {nodes_file} 失败: {e}")
        print(content)  # 回退到控制台输出

    checksum_file = os.path.join(CONFIG["output"]["dir"], CONFIG["output"]["checksum_file"])
    try:
        async with aiofiles.open(checksum_file, "w", encoding="utf-8") as f:
            for filename, checksum in checksums.items():
                await f.write(f"{checksum}  {os.path.basename(filename)}\n")
        if os.path.exists(checksum_file):
            logger.info(f"已保存校验和到 {checksum_file}, 文件存在")
        else:
            logger.error(f"文件 {checksum_file} 未生成")
    except Exception as e:
        logger.error(f"保存校验和失败: {e}")

async def main():
    """主函数"""
    start_time = time.time()
    logger.info("开始处理节点数据")

    links = await read_sub_txt()
    history_data = await read_history()
    if not links:
        logger.warning("没有有效节点链接，退出")
        await save_outputs([])
        return

    nodes = await process_nodes(links, history_data)
    logger.info(f"有效节点数: {len(nodes)}")

    await save_outputs(nodes)

    # 调试：列出 data 目录内容
    data_dir = CONFIG["output"]["dir"]
    try:
        files = os.listdir(data_dir)
        logger.info(f"data 目录内容: {files}")
    except Exception as e:
        logger.error(f"无法列出 data 目录: {e}")

    logger.info(f"处理完成，总耗时: {time.time() - start_time:.2f} 秒")

if __name__ == "__main__":
    asyncio.run(main())
