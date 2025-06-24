import asyncio
import json
import logging
import os
import re
import socket
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
        "timeout_seconds": float(os.getenv("TEST_TIMEOUT", 2)),
        "max_concurrent": 50,
    },
    "log": {
        "level": os.getenv("LOG_LEVEL", "INFO").upper(),
        "file": "data/logfile.txt",
    },
}

def load_config() -> Dict:
    """加载配置文件，如果不存在则使用默认配置"""
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f)
            # 合并默认配置和用户配置
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
        logging.StreamHandler(), # 同时输出到控制台
    ],
)
logger = logging.getLogger(__name__)

# --- 正则表达式 ---
# 匹配各种协议的链接
PROTOCOL_RE = re.compile(r"^(vless|vmess|trojan|ss|hy2|hysteria2):\/\/[^\s]+$", re.IGNORECASE)
# 提取协议和链接剩余部分
NODE_LINK_RE = re.compile(r"^(vless|vmess|trojan|ss|hy2|hysteria2):\/\/(.*)")
# 解析 host:port 格式，支持 IPv6、IPv4 和域名
HOST_PORT_FULL_RE = re.compile(r"^(?:\[([0-9a-fA-F:]+)\]|([0-9]{1,3}(?:\.[0-9]{1,3}){3})|([a-zA-Z0-9.-]+)):([0-9]+)$")

# --- 数据结构 ---
class NodeInfo:
    """存储节点信息的类"""
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
        """将节点信息格式化为字符串"""
        return (
            f"{self.original_link} | Remarks: {self.remarks} | Delay: {self.delay_ms:.2f}ms | "
            f"Status: {self.status} | Country: {self.country or 'Unknown'}"
        )

# --- 辅助函数 ---
def infer_country(remarks: str, server: str) -> Optional[str]:
    """根据备注和服务器地址推断国家"""
    try:
        country_keywords = {
            "US": "United States", "USA": "United States",
            "JP": "Japan",
            "SG": "Singapore",
            "HK": "Hong Kong",
            "CN": "China",
            "DE": "Germany",
            "FR": "France",
            "UK": "United Kingdom", "GB": "United Kingdom",
            "CA": "Canada",
            "AU": "Australia",
            "KR": "South Korea",
            "TW": "Taiwan",
        }
        remarks_lower = remarks.lower()
        server_lower = server.lower()

        # 优先从备注中匹配国家代码或名称
        for code, name in country_keywords.items():
            if code.lower() in remarks_lower or name.lower() in remarks_lower:
                country = pycountry.countries.get(alpha_2=code)
                return country.name if country else name

        # 尝试从服务器地址的顶级域名 (TLD) 推断
        # 注意：gTLD (如 .com, .org) 不会被识别为国家
        tld_match = re.search(r'\.([a-zA-Z]{2,})$', server_lower)
        if tld_match:
            tld = tld_match.group(1).upper()
            country = pycountry.countries.get(alpha_2=tld)
            if country:
                return country.name

        return None
    except Exception as e:
        logger.debug(f"推断国家失败 ({remarks}, {server}): {e}")
        return None

def normalize_link(link: str) -> str:
    """规范化链接，用于去重"""
    try:
        parsed = urlparse(link)
        # 移除查询参数和片段，只保留协议、网络位置和路径
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/")
    except Exception:
        return link

def parse_node_info(link: str, history_data: Dict) -> Optional[NodeInfo]:
    """解析单个节点链接，提取节点信息"""
    try:
        link = link.strip()
        if not link or not PROTOCOL_RE.match(link):
            logger.debug(f"无效链接格式: {link}")
            return None

        match = NODE_LINK_RE.match(link)
        if not match:
            logger.debug(f"无法识别协议或链接结构: {link}")
            return None

        protocol = match.group(1).lower()
        remaining_part = match.group(2)
        remarks = f"{protocol.upper()} 节点" # 默认备注

        # 提取备注
        if "#" in remaining_part:
            remaining_part, remark_part = remaining_part.rsplit("#", 1)
            remarks = unquote(remark_part)

        # 提取 host:port
        host_port_str = remaining_part.split("?")[0] if "?" in remaining_part else remaining_part
        if "@" in host_port_str: # 移除用户信息部分 (如 Shadowsocks)
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
        # 从历史数据中获取延迟和状态
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
        logger.error(f"解析链接 {link} 失败: {e}", exc_info=True) # 打印详细栈追踪
        return None

async def verify_node(node: NodeInfo) -> bool:
    """异步验证节点的 TCP 可达性"""
    start_time = time.time()
    sock = None # 初始化为 None
    try:
        # 创建 socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(CONFIG["test"]["timeout_seconds"]) # 设置超时

        # 在线程池中执行阻塞的 connect 操作
        await asyncio.get_event_loop().run_in_executor(
            None, sock.connect, (node.server, node.port)
        )
        sock.close() # 连接成功后关闭 socket
        node.status = "Successful"
        node.delay_ms = (time.time() - start_time) * 1000
        logger.debug(f"节点 {node.remarks} 验证成功，延迟: {node.delay_ms:.2f}ms")
        return True
    except Exception as e:
        logger.warning(f"验证节点 {node.remarks} ({node.server}:{node.port}) 失败: {e}")
        node.status = "Failed"
        node.delay_ms = -1
        return False
    finally:
        if sock: # 确保 socket 存在才关闭
            sock.close()

async def read_sub_txt() -> List[str]:
    """异步读取 sub.txt 文件中的订阅链接"""
    try:
        sub_file = CONFIG["input"]["sub_file"]
        if not os.path.exists(sub_file):
            logger.error(f"输入文件 {sub_file} 不存在")
            return []
        async with aiofiles.open(sub_file, "r", encoding="utf-8") as f:
            content = await f.read()
            # 过滤空行和以 # 开头的注释行
            links = [line.strip() for line in content.split("\n") if line.strip() and not line.startswith("#")]
            logger.info(f"从 {sub_file} 读取到 {len(links)} 条节点链接")
            return links
    except Exception as e:
        logger.error(f"读取 {sub_file} 失败: {e}")
        return []

async def read_history() -> Dict:
    """异步读取历史结果文件 history_results.json"""
    try:
        history_file = CONFIG["input"]["history_file"]
        if not os.path.exists(history_file):
            logger.warning(f"历史文件 {history_file} 不存在，将创建空历史记录")
            return {}
        async with aiofiles.open(history_file, "r", encoding="utf-8") as f:
            content = await f.read()
            if content:
                return json.loads(content)
            logger.warning(f"历史文件 {history_file} 为空")
            return {}
    except json.JSONDecodeError as e:
        logger.error(f"历史文件 {history_file} 内容无效 (非JSON格式): {e}")
        return {}
    except Exception as e:
        logger.error(f"读取 {history_file} 失败: {e}")
        return {}

async def process_nodes(links: List[str], history_data: Dict) -> List[NodeInfo]:
    """处理节点：解析、去重、验证并排序"""
    semaphore = asyncio.Semaphore(CONFIG["test"]["max_concurrent"]) # 控制并发量
    parsed_nodes_count = 0
    valid_nodes_count = 0
    seen_links = set() # 用于去重

    async def verify_with_semaphore(node: NodeInfo) -> NodeInfo:
        """带信号量控制的节点验证"""
        async with semaphore:
            await verify_node(node)
            return node

    nodes_to_verify = []
    # 第一阶段：解析和去重
    for link in tqdm_asyncio(links, desc="解析节点", unit="节点"):
        parsed_nodes_count += 1
        node_info = parse_node_info(link, history_data)
        if node_info and node_info.original_link not in seen_links:
            nodes_to_verify.append(node_info)
            seen_links.add(node_info.original_link)
            valid_nodes_count += 1
        else:
            if not node_info:
                logger.debug(f"跳过无效链接: {link}")
            else:
                logger.debug(f"跳过重复节点: {link}")

    logger.info(f"解析完成: 总计 {parsed_nodes_count} 条链接，有效节点 {valid_nodes_count} 个")

    if not nodes_to_verify:
        logger.warning("没有有效节点可供验证")
        return []

    verified_nodes = []
    tasks = [verify_with_semaphore(node) for node in nodes_to_verify]
    # 第二阶段：并发验证节点
    for future in tqdm_asyncio.as_completed(tasks, desc="验证节点", unit="节点"):
        node = await future
        if node.status == "Successful":
            verified_nodes.append(node)

    logger.info(f"验证完成: 成功节点 {len(verified_nodes)} 个")

    # 根据延迟排序，-1 的延迟排在最后
    return sorted(verified_nodes, key=lambda x: x.delay_ms if x.delay_ms > 0 else float("inf"))

async def save_outputs(nodes: List[NodeInfo]):
    """异步保存处理后的节点和校验和文件"""
    Path(CONFIG["output"]["dir"]).mkdir(parents=True, exist_ok=True) # 确保输出目录存在

    checksums = {}

    nodes_file = os.path.join(CONFIG["output"]["dir"], CONFIG["output"]["nodes_file"])
    try:
        content = "\n".join(node.to_string() for node in nodes)
        async with aiofiles.open(nodes_file, "w", encoding="utf-8") as f:
            await f.write(content)
        # 计算校验和，需要同步读取文件
        with open(nodes_file, "rb") as f:
            checksums[nodes_file] = hashlib.sha256(f.read()).hexdigest()
        
        # 验证文件是否实际生成
        if os.path.exists(nodes_file):
            logger.info(f"已保存 {len(nodes)} 个节点到 {nodes_file}, 大小: {os.path.getsize(nodes_file)} 字节")
        else:
            logger.error(f"文件 {nodes_file} 未生成")
    except Exception as e:
        logger.error(f"保存 {nodes_file} 失败: {e}")
        logger.error(f"无法写入内容到 {nodes_file}: {content[:200]}...") # 打印部分内容帮助调试

    checksum_file = os.path.join(CONFIG["output"]["dir"], CONFIG["output"]["checksum_file"])
    try:
        async with aiofiles.open(checksum_file, "w", encoding="utf-8") as f:
            for filename, checksum in checksums.items():
                await f.write(f"{checksum}  {os.path.basename(filename)}\n") # 注意两个空格
        
        # 验证文件是否实际生成
        if os.path.exists(checksum_file):
            logger.info(f"已保存校验和到 {checksum_file}, 大小: {os.path.getsize(checksum_file)} 字节")
        else:
            logger.error(f"文件 {checksum_file} 未生成")
    except Exception as e:
        logger.error(f"保存校验和失败: {e}")

async def main():
    """主函数，执行节点处理流程"""
    start_time = time.time()
    logger.info("开始处理节点数据")

    links = await read_sub_txt()
    history_data = await read_history()
    
    if not links:
        logger.warning("没有有效节点链接，生成空文件并退出")
        await save_outputs([]) # 即使没有链接也生成空文件，保持输出一致性
        return

    nodes = await process_nodes(links, history_data)
    logger.info(f"最终有效节点数: {len(nodes)}")

    await save_outputs(nodes)

    data_dir = CONFIG["output"]["dir"]
    try:
        # 列出并记录 data 目录下的文件信息，方便调试
        files = os.listdir(data_dir)
        logger.info(f"data 目录内容: {files}")
        for file in files:
            file_path = os.path.join(data_dir, file)
            if os.path.isfile(file_path):
                logger.info(f"文件 {file} 大小: {os.path.getsize(file_path)} 字节")
    except Exception as e:
        logger.error(f"无法列出 data 目录: {e}")

    logger.info(f"处理完成，总耗时: {time.time() - start_time:.2f} 秒")

if __name__ == "__main__":
    asyncio.run(main())

