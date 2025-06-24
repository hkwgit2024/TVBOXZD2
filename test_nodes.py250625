import httpx
import asyncio
import json
import os
import logging
import re
import time
import aiodns
import aiofiles
import psutil
import socket
import ssl
from urllib.parse import urlparse, unquote, parse_qs
from concurrent.futures import ThreadPoolExecutor

# --- 配置 ---
# 将 SOURCE_URLS 定义为一个列表，支持从多个地址获取节点信息
SOURCE_URLS = [
   #"https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/data/nodes.txt",
   "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/config_all_merged_nodes.txt",
  #"https://raw.githubusercontent.com/qjlxg/hy2/refs/heads/main/configtg.txt",
  # "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/all_nodes.txt",
  # "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/ss.txt",
  # "https://snippet.host/oouyda/raw",
]

DATA_DIR = "data"  # 数据文件存放目录
HISTORY_FILE = os.path.join(DATA_DIR, "history_results.json")  # 历史测试结果文件路径
DNS_CACHE_FILE = os.path.join(DATA_DIR, "dns_cache.json")  # DNS 缓存文件路径
SUCCESSFUL_NODES_OUTPUT_FILE = os.path.join(DATA_DIR, "sub.txt")  # 成功节点输出文件路径
# 从环境变量获取测试超时时间，如果未设置，默认为 2 秒
TEST_TIMEOUT_SECONDS = float(os.getenv("TEST_TIMEOUT", 2))
BATCH_SIZE = 100  # 每次处理的节点数量，用于分批处理以优化性能
DNS_CACHE_EXPIRATION = 2678400  # DNS 缓存有效期：31 天 (单位：秒)
HISTORY_EXPIRATION = 2678400  # 历史记录有效期：31 天 (单位：秒)

# 动态计算最佳并发任务数
def get_optimal_concurrency():
    """
    根据系统的 CPU 核数和可用内存动态调整并发任务数。
    旨在平衡资源利用和避免过度消耗。
    """
    cpu_count = psutil.cpu_count()  # 获取 CPU 逻辑核数
    memory = psutil.virtual_memory()
    available_memory = memory.available / (1024 ** 2)  # 可用内存 (转换为 MB)
    base_concurrency = cpu_count * 50  # 基础并发数：每个 CPU 核分配 50 个任务
    if available_memory < 1000:  # 如果可用内存低于 1GB
        base_concurrency = cpu_count * 20  # 降低并发数以避免内存不足
    return min(base_concurrency, 200)  # 将最大并发数限制在 200，防止任务过多

MAX_CONCURRENT_TASKS = get_optimal_concurrency()  # 设定最大并发任务数

# --- 日志配置 ---
# 从环境变量获取日志级别，如果未设置，默认为 INFO
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()
logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.INFO),
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- 预编译正则表达式 ---
# 用于匹配支持的协议类型
PROTOCOL_RE = re.compile(r"^(vless|vmess|trojan|ss|hy2|hysteria2):\/\/[^\s]+$", re.IGNORECASE)
# 用于从链接中查找端口号
HOST_PORT_RE = re.compile(r"(?:@|:)(\d{1,5})(?:\?|$|#)")
# 用于解析节点链接的协议和剩余部分
NODE_LINK_RE = re.compile(r"^(vless|vmess|trojan|ss|hy2|hysteria2):\/\/(.*)")
# 用于匹配主机名（IP或域名）和端口的完整格式
HOST_PORT_FULL_RE = re.compile(r"^(?:\[([0-9a-fA-F:]+)\]|([0-9]{1,3}(?:\.[0-9]{1,3}){3})|([a-zA-Z0-9.-]+)):([0-9]+)$")
# 用于判断字符串是否为 IP 地址（IPv4或IPv6）
IP_RE = re.compile(r"^(?:\[[0-9a-fA-F:]+\]|[0-9]{1,3}(?:\.[0-9]{1,3}){3})$")

# --- 数据结构 ---
class NodeTestResult:
    """封装单个节点的测试结果，包括节点信息、状态、延迟和错误信息。"""
    def __init__(self, node_info, status, delay_ms=-1, error_message=""):
        self.node_info = node_info
        self.status = status
        self.delay_ms = delay_ms
        self.error_message = error_message

# --- 全局变量 ---
history_results = {}  # 存储节点历史测试结果的字典
dns_cache = {}  # 存储 DNS 解析缓存的字典

# --- 辅助函数 ---
def normalize_link(link):
    """
    规范化节点链接，通过移除查询参数和片段，创建一个更稳定的历史记录键。
    这样，链接的次要变化不会导致重复的历史记录条目。
    """
    try:
        parsed = urlparse(link)
        # 保留协议、网络位置（主机:端口）和路径
        base_link = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        return base_link.rstrip('/')  # 移除末尾的斜杠（如果存在）
    except Exception as e:
        logger.warning(f"规范化链接 '{link}' 失败: {e}")
        return link  # 规范化失败时返回原始链接

async def bulk_dns_lookup(hostnames):
    """
    执行批量 DNS 查询。优先使用 DNS 缓存中的结果，对未缓存或已过期的主机名进行实际解析。
    支持并发解析和 IPv6 回退。
    """
    resolver = aiodns.DNSResolver(nameservers=["8.8.8.8", "1.1.1.1"])  # 使用 Google 和 Cloudflare 的公共 DNS
    results = {}  # 存储解析结果
    current_time = int(time.time())
    cache_hits = 0  # 统计缓存命中次数

    to_resolve = []  # 需要进行实际 DNS 解析的主机名列表
    for hostname in hostnames:
        if hostname in dns_cache and current_time - dns_cache[hostname]["timestamp"] < DNS_CACHE_EXPIRATION:
            results[hostname] = dns_cache[hostname]["ip"]
            cache_hits += 1
        else:
            to_resolve.append(hostname)

    if to_resolve:
        # 为所有待解析的主机名创建异步任务
        tasks = [resolver.query(hostname, 'A') for hostname in to_resolve]
        # 并发执行这些任务，并捕获可能发生的异常
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        for hostname, response in zip(to_resolve, responses):
            if isinstance(response, Exception):  # 如果 IPv4 解析失败
                try:
                    # 尝试进行 IPv6 解析
                    response = await resolver.query(hostname, 'AAAA')
                    if response:
                        ip = response[0].host
                        results[hostname] = ip
                        dns_cache[hostname] = {"ip": ip, "timestamp": current_time}
                        logger.debug(f"已将 {hostname} 解析到 IPv6: {ip}")
                except Exception as e:
                    logger.debug(f"DNS 解析 {hostname} 失败: {e}")
                continue  # 继续处理下一个主机名
            if response:  # 如果 IPv4 解析成功
                ip = response[0].host
                results[hostname] = ip
                dns_cache[hostname] = {"ip": ip, "timestamp": current_time}
                logger.debug(f"已将 {hostname} 解析到 IPv4: {ip}")

    logger.info(f"DNS 查询总结: 总共 {len(hostnames)} 个，缓存命中 {cache_hits} 个 ({cache_hits/len(hostnames)*100:.2f}%)，成功解析 {len(results)} 个。")
    return results

async def load_history():
    """
    异步加载历史测试结果。
    如果历史文件不存在或内容无效，则初始化一个空的字典。
    """
    global history_results
    if os.path.exists(HISTORY_FILE):
        try:
            async with aiofiles.open(HISTORY_FILE, "r", encoding="utf-8") as f:
                content = await f.read()
                if content:  # 确保文件不为空
                    history_results = json.loads(content)
                else:
                    logger.warning("历史文件为空，正在初始化一个空的记录。")
                    history_results = {}
            logger.info(f"历史结果已加载: {len(history_results)} 条记录。")
        except json.JSONDecodeError as e:
            logger.warning(f"历史结果文件损坏或 JSON 无效，正在重新初始化: {e}")
            history_results = {}
        except Exception as e:
            logger.error(f"加载历史文件时出错: {e}")
            history_results = {}
    else:
        logger.info("未找到历史结果文件，将创建一个新的。")

async def save_history():
    """
    异步保存历史测试结果。
    在保存之前，会根据 `HISTORY_EXPIRATION` 清理掉过期的记录。
    """
    current_time = int(time.time())
    # 过滤掉超过有效期的历史记录
    cleaned_history = {
        node_id: data for node_id, data in history_results.items()
        if current_time - data.get("timestamp", 0) < HISTORY_EXPIRATION
    }
    os.makedirs(DATA_DIR, exist_ok=True)  # 确保数据目录存在
    async with aiofiles.open(HISTORY_FILE, "w", encoding="utf-8") as f:
        await f.write(json.dumps(cleaned_history, indent=2, ensure_ascii=False))
    logger.info(f"历史结果已保存: 清理后保留 {len(cleaned_history)} 条记录。")

async def load_dns_cache():
    """
    异步加载 DNS 缓存。
    如果 DNS 缓存文件不存在或内容无效，则初始化一个空的字典。
    """
    global dns_cache
    if os.path.exists(DNS_CACHE_FILE):
        try:
            async with aiofiles.open(DNS_CACHE_FILE, "r", encoding="utf-8") as f:
                content = await f.read()
                if content:  # 确保文件不为空
                    dns_cache = json.loads(content)
                else:
                    logger.warning("DNS 缓存文件为空，正在初始化一个空的缓存。")
                    dns_cache = {}
            logger.info(f"DNS 缓存已加载: {len(dns_cache)} 条记录。")
        except json.JSONDecodeError as e:
            logger.warning(f"DNS 缓存文件损坏或 JSON 无效，正在重新初始化: {e}")
            dns_cache = {}
        except Exception as e:
            logger.error(f"加载 DNS 缓存文件时出错: {e}")
            dns_cache = {}
    else:
        logger.info("未找到 DNS 缓存文件，将创建一个新的。")

async def save_dns_cache():
    """
    异步保存 DNS 缓存。
    在保存之前，会根据 `DNS_CACHE_EXPIRATION` 清理掉过期的记录。
    """
    current_time = int(time.time())
    # 过滤掉超过有效期的 DNS 缓存记录
    cleaned_cache = {
        host: data for host, data in dns_cache.items()
        if current_time - data.get("timestamp", 0) < DNS_CACHE_EXPIRATION
    }
    os.makedirs(DATA_DIR, exist_ok=True)  # 确保数据目录存在
    async with aiofiles.open(DNS_CACHE_FILE, "w", encoding="utf-8") as f:
        await f.write(json.dumps(cleaned_cache, indent=2, ensure_ascii=False))
    logger.info(f"DNS 缓存已保存并清理过期记录: {len(cleaned_cache)} 条记录。")

async def fetch_ss_txt(url):
    """
    从给定的 URL 获取节点列表的文本内容。
    使用 httpx 异步客户端进行请求，并设置超时时间。
    """
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=15) as client:
            response = await client.get(url)
            response.raise_for_status()  # 如果 HTTP 状态码表示错误，则抛出异常
            return response.text
    except httpx.RequestError as e:
        logger.error(f"从 {url} 获取节点列表失败: {e}")
        return None
    except Exception as e:
        logger.error(f"从 {url} 获取节点列表时发生未知错误: {e}")
        return None

def prefilter_links(links):
    """
    根据基本格式（如协议匹配和端口存在）预过滤无效的节点链接。
    有助于减少后续解析和测试的负担。
    """
    valid_links = []
    for link in links:
        link = link.strip()
        if not link:  # 跳过空行
            continue
        if not PROTOCOL_RE.match(link):
            logger.debug(f"过滤无效链接 (协议不匹配): {link}")
            continue
        if not HOST_PORT_RE.search(link):
            logger.debug(f"过滤无效链接 (缺少端口): {link}")
            continue
        valid_links.append(link)
    logger.info(f"预过滤完成: 原始链接 {len(links)} 条，保留 {len(valid_links)} 条。")
    return valid_links

def parse_node_info(link):
    """
    从给定的节点链接中解析出关键信息，如协议、服务器、端口、备注等。
    支持 VLESS, VMESS, Trojan, SS, Hysteria2 等协议。
    """
    node_info = {'original_link': link}
    try:
        link = link.strip()
        if not link:
            return None

        match = NODE_LINK_RE.match(link)
        if not match:
            logger.debug(f"链接协议无法识别: {link}")
            return None

        protocol = match.group(1).lower()
        remaining_part = match.group(2)
        node_info['protocol'] = protocol

        # 解析备注信息
        if '#' in remaining_part:
            remaining_part, remarks = remaining_part.rsplit('#', 1)
            node_info['remarks'] = unquote(remarks)
        else:
            node_info['remarks'] = f"{protocol.upper()} 节点"

        # 根据协议类型进行不同的解析
        if protocol in ['vless', 'vmess', 'trojan', 'ss']:
            # 这些协议通常格式为 <用户信息>@<主机>:<端口>?<查询参数>#<备注>
            if '@' in remaining_part:
                user_info_part, host_port_part = remaining_part.split('@', 1)
            else:
                user_info_part = ""  # SS 协议可能不含用户信息
                host_port_part = remaining_part

            if '?' in host_port_part:
                host_port_str, query_str = host_port_part.split('?', 1)
                query_params = parse_qs(query_str)
            else:
                host_port_str = host_port_part
                query_params = {}

            host_match = HOST_PORT_FULL_RE.match(host_port_str)
            if host_match:
                node_info['server'] = host_match.group(1) or host_match.group(2) or host_match.group(3)
                node_info['port'] = int(host_match.group(4))
                if not (1 <= node_info['port'] <= 65535):
                    logger.debug(f"端口号无效 (范围 1-65535): {node_info['port']} 在 {link} 中")
                    return None
            else:
                logger.debug(f"无法从 {link} 中的 {host_port_str} 解析主机:端口")
                return None

            for key, values in query_params.items():
                node_info[key] = values[0]  # 对于重复的键，只取第一个值

        elif protocol in ['hy2', 'hysteria2']:
            # Hysteria2 格式: hy2://<主机>:<端口>?<查询参数>#<备注>
            parts = remaining_part.split('?', 1)
            host_port_str = parts[0]
            query_params = parse_qs(parts[1]) if len(parts) > 1 else {}

            host_match = HOST_PORT_FULL_RE.match(host_port_str)
            if host_match:
                node_info['server'] = host_match.group(1) or host_match.group(2) or host_match.group(3)
                node_info['port'] = int(host_match.group(4))
                if not (1 <= node_info['port'] <= 65535):
                    logger.debug(f"端口号无效 (范围 1-65535): {node_info['port']} 在 {link} 中")
                    return None
            else:
                logger.debug(f"无法从 {link} 中的 {host_port_str} 解析 hy2 主机:端口")
                return None
            for key, values in query_params.items():
                node_info[key] = values[0]

        else:
            logger.warning(f"不支持的协议类型: {protocol} 用于链接 {link}")
            return None

        # 判断服务器是域名还是 IP 地址
        if not IP_RE.match(node_info['server']):
            node_info['is_domain'] = True
        else:
            node_info['is_domain'] = False
            node_info['resolved_ip'] = node_info['server']  # 如果是 IP，则已解析

        return node_info

    except Exception as e:
        logger.error(f"解析节点链接 '{link}' 时出错: {e}", exc_info=False)  # 避免为每个解析错误打印完整回溯
        return None

async def check_node(node_info):
    """
    测试单个节点的连接性。
    首先检查历史缓存，如果最近已测试过且结果有效，则直接使用缓存结果。
    对于不同协议（Hysteria2 使用 UDP，其他使用 TCP），执行相应的连接测试。
    """
    node_id = normalize_link(node_info['original_link'])  # 使用规范化链接作为历史记录的键
    current_time = time.time()

    # 检查历史缓存中的最近测试结果
    if node_id in history_results:
        record = history_results[node_id]
        # 如果最近成功 (5分钟内)，则直接使用缓存结果
        if record['status'] == 'Successful' and current_time - record['timestamp'] < 300:
            logger.debug(f"使用 {node_info['remarks']} 的缓存成功结果。")
            return NodeTestResult(node_info, 'Successful', record['delay_ms'])
        # 如果最近失败 (在 HISTORY_EXPIRATION 期限内)，则跳过重新检查
        elif record['status'] == 'Failed' and current_time - record['timestamp'] < HISTORY_EXPIRATION:
            logger.debug(f"跳过最近失败的节点: {node_info['remarks']}")
            return NodeTestResult(node_info, 'Failed', -1, record['error_message'])

    protocol = node_info.get('protocol')
    remarks = node_info.get('remarks', 'N/A')
    server = node_info.get('server')
    port = node_info.get('port')
    target_host = node_info.get('resolved_ip')  # 使用预解析的 IP 地址

    if not all([server, port, target_host]):
        return NodeTestResult(node_info, "Failed", -1, "信息不完整或 DNS 解析失败")

    test_start_time = time.monotonic()  # 记录测试开始时间
    error_message = ""
    sock = None
    wrapped_socket = None

    try:
        # 如果是 Hysteria2 协议，使用 UDP 进行测试
        if protocol in ['hy2', 'hysteria2']:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # 创建 UDP 套接字
                sock.settimeout(TEST_TIMEOUT_SECONDS)  # 设置超时
                sock.connect((target_host, port))  # 尝试连接
                sock.sendall(b'ping')  # 发送一个小的 UDP 数据包
                # 对于基本的 UDP 可达性检查，通常不需要等待响应，只需确认发送成功
                logger.debug(f"UDP 端口 {target_host}:{port} 似乎可达。")
                test_end_time = time.monotonic()
                delay = (test_end_time - test_start_time) * 1000
                return NodeTestResult(node_info, "Successful", delay)
            except socket.timeout:
                error_message = "UDP 连接超时"
            except ConnectionRefusedError:
                error_message = "UDP 连接被拒绝"
            except Exception as e:
                error_message = f"UDP 测试错误: {e}"
            finally:
                if sock:
                    sock.close()
            return NodeTestResult(node_info, "Failed", -1, error_message)

        # 对于其他协议 (VLESS, VMESS, Trojan, SS)，假定使用 TCP 进行测试
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # 创建 TCP 套接字
            sock.settimeout(TEST_TIMEOUT_SECONDS)  # 设置超时
            # 在单独的线程中执行阻塞的 connect 操作，以避免阻塞 asyncio 事件循环
            await asyncio.get_event_loop().run_in_executor(
                None, sock.connect, (target_host, port)
            )

            # 如果节点配置了 TLS 安全，则执行 TLS 握手
            if node_info.get('security') == 'tls':
                context = ssl.create_default_context()
                context.check_hostname = False  # 关闭主机名检查，我们只关注连接性
                context.verify_mode = ssl.CERT_NONE  # 禁用证书验证，提高兼容性
                # 获取 SNI 主机名，优先使用 'sni'，其次 'host'，最后是服务器地址
                sni_hostname = node_info.get('sni') or node_info.get('host') or node_info['server']
                wrapped_socket = context.wrap_socket(sock, server_hostname=sni_hostname)
                # 在单独的线程中执行阻塞的 TLS 握手操作
                await asyncio.get_event_loop().run_in_executor(
                    None, wrapped_socket.do_handshake
                )
            test_end_time = time.monotonic()
            delay = (test_end_time - test_start_time) * 1000
            logger.info(f"测试节点 {remarks} ({target_host}:{port}) - 状态: 成功, 延迟: {delay:.2f}ms")
            return NodeTestResult(node_info, "Successful", delay)

        except socket.timeout:
            error_message = "TCP 连接超时"
        except ConnectionRefusedError:
            error_message = "TCP 连接被拒绝"
        except ssl.SSLError as e:
            error_message = f"TLS 握手错误: {e}"
        except Exception as e:
            error_message = f"TCP/TLS 测试中发生意外错误: {e}"
        finally:
            if wrapped_socket:
                wrapped_socket.close()
            if sock:
                sock.close()

    except Exception as e:  # 捕获测试过程中可能发生的任何高级别错误
        error_message = f"节点检查时发生严重错误: {e}"
    finally:  # 确保无论如何，套接字都会被关闭
        if wrapped_socket:
            wrapped_socket.close()
        if sock:
            sock.close()

    logger.warning(f"测试节点 {remarks} ({target_host}:{port}) - 状态: 失败, 延迟: -1ms, 错误: {error_message}")
    return NodeTestResult(node_info, "Failed", -1, error_message)

async def test_nodes_in_batches(nodes, batch_size=BATCH_SIZE):
    """
    分批测试节点，并使用 asyncio.Semaphore 限制并发任务数量。
    提供批处理进度反馈。
    """
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_TASKS)  # 创建并发信号量
    async def test_node_with_semaphore(node):
        async with semaphore:  # 在进入协程前获取信号量，离开时释放
            return await check_node(node)

    all_results = []
    tasks = [test_node_with_semaphore(node) for node in nodes]  # 预先创建所有测试任务

    # 循环处理任务批次，并打印进度
    for i in range(0, len(tasks), batch_size):
        batch_tasks = tasks[i:i + batch_size]
        batch_results = await asyncio.gather(*batch_tasks)  # 并发执行当前批次的任务
        all_results.extend(batch_results)
        logger.info(f"已完成批次 {i // batch_size + 1}/{len(tasks) // batch_size + 1}。目前已处理 {len(all_results)}/{len(nodes)} 个节点。")

    return all_results

def generate_summary(test_results):
    """
    生成节点测试的统计摘要。
    包括总数、成功数、成功率、平均延迟和失败原因统计。
    """
    successful_nodes = [r for r in test_results if r.status == "Successful"]
    success_count = len(successful_nodes)
    total_count = len(test_results)
    success_rate = (success_count / total_count * 100) if total_count else 0
    # 计算成功节点的平均延迟
    avg_delay = sum(r.delay_ms for r in successful_nodes) / success_count if success_count else 0

    # 统计各种失败原因的出现次数
    failure_reasons = {}
    for r in test_results:
        if r.status == "Failed":
            reason = r.error_message if r.error_message else "未知错误"
            failure_reasons[reason] = failure_reasons.get(reason, 0) + 1

    summary = {
        "总测试节点数": total_count,
        "成功节点数": success_count,
        "成功率": f"{success_rate:.2f}%",
        "平均延迟 (ms)": f"{avg_delay:.2f}",
        "失败原因统计": failure_reasons
    }
    return summary

async def main():
    """
    主函数：协调整个节点测试和数据处理流程。
    包括加载历史、获取多来源节点、解析、DNS 解析、测试、保存结果和打印摘要。
    """
    start_time = time.time()  # 记录工作流开始时间
    os.makedirs(DATA_DIR, exist_ok=True)  # 确保数据目录存在

    await load_history()  # 加载历史测试结果
    await load_dns_cache()  # 加载 DNS 缓存

    all_links = []
    # 遍历所有配置的来源 URL，抓取并合并所有节点的链接
    for url in SOURCE_URLS:
        logger.info(f"正在从以下地址获取节点列表: {url}")
        ss_txt_content = await fetch_ss_txt(url)
        if ss_txt_content:
            all_links.extend(ss_txt_content.strip().split('\n'))
        else:
            logger.warning(f"未能从 {url} 获取内容或内容为空，跳过。")

    if not all_links:
        logger.error("未从任何来源获取到有效的节点链接，退出。")
        async with aiofiles.open(SUCCESSFUL_NODES_OUTPUT_FILE, "w", encoding="utf-8") as f:
            await f.write("# 未找到或测试到任何有效节点。\n")
        # **在退出前打印最终成功节点数，确保 GitHub Actions 捕获到 0**
        print(f"最终成功节点数: 0")
        return

    links = all_links  # 将合并后的所有链接赋值给 links 变量
    logger.info(f"已从所有来源收集到 {len(links)} 条原始链接。")

    filtered_links = prefilter_links(links)
    if not filtered_links:
        logger.info("预过滤后没有留下任何有效链接，退出。")
        async with aiofiles.open(SUCCESSFUL_NODES_OUTPUT_FILE, "w", encoding="utf-8") as f:
            await f.write("# 预过滤后未找到有效节点。\n")
        # **在退出前打印最终成功节点数，确保 GitHub Actions 捕获到 0**
        print(f"最终成功节点数: 0")
        return

    # 解析所有节点信息，并收集需要进行 DNS 解析的域名
    parsed_nodes = []
    hostnames_to_resolve = set()
    for link in filtered_links:
        node_info = parse_node_info(link)
        if node_info:
            parsed_nodes.append(node_info)
            if node_info['is_domain']:
                hostnames_to_resolve.add(node_info['server'])
    logger.info(f"已成功解析 {len(parsed_nodes)} 个节点信息。")

    # 执行批量 DNS 解析
    resolved_ips = await bulk_dns_lookup(list(hostnames_to_resolve))

    # 将解析到的 IP 地址填充回节点信息，并筛选出可测试的节点
    nodes_for_testing = []
    for node in parsed_nodes:
        if node['is_domain']:
            resolved_ip = resolved_ips.get(node['server'])
            if resolved_ip:
                node['resolved_ip'] = resolved_ip
                nodes_for_testing.append(node)
            else:
                logger.warning(f"无法解析域名 {node['server']}，跳过节点: {node.get('remarks', 'N/A')}")
        else:  # 如果已经是 IP 地址，直接添加
            nodes_for_testing.append(node)

    if not nodes_for_testing:
        logger.info("经过解析和 DNS 查找后，没有留下任何可测试的节点。")
        async with aiofiles.open(SUCCESSFUL_NODES_OUTPUT_FILE, "w", encoding="utf-8") as f:
            await f.write("# 未找到任何可测试节点。\n")
        # **在退出前打印最终成功节点数，确保 GitHub Actions 捕获到 0**
        print(f"最终成功节点数: 0")
        return

    logger.info(f"准备测试 {len(nodes_for_testing)} 个节点。最大并发数: {MAX_CONCURRENT_TASKS}")
    test_results = await test_nodes_in_batches(nodes_for_testing)

    # 更新历史记录：将本次测试的结果存入历史记录
    current_timestamp = int(time.time())
    for result in test_results:
        node_id = normalize_link(result.node_info['original_link'])
        history_results[node_id] = {
            "status": result.status,
            "delay_ms": result.delay_ms,
            "error_message": result.error_message,
            "timestamp": current_timestamp
        }

    # 筛选出测试成功的节点，并按延迟进行排序（延迟越低越优先）
    successful_nodes = sorted([r for r in test_results if r.status == "Successful"], key=lambda x: x.delay_ms)

    # 将成功节点链接写入 sub.txt 文件
    os.makedirs(DATA_DIR, exist_ok=True)
    async with aiofiles.open(SUCCESSFUL_NODES_OUTPUT_FILE, "w", encoding="utf-8") as f:
        if successful_nodes:
            for result in successful_nodes:
                await f.write(f"{result.node_info['original_link']}\n")
            logger.info(f"已将 {len(successful_nodes)} 个成功节点写入 {SUCCESSFUL_NODES_OUTPUT_FILE}。")
        else:
            await f.write("# 没有找到可用的节点。\n")
            logger.warning("没有找到可用的节点，sub.txt 将为空。")

    # 保存更新后的历史记录和 DNS 缓存
    await save_history()
    await save_dns_cache()

    end_time = time.time()
    total_duration = end_time - start_time
    logger.info(f"所有节点测试完成。总耗时: {total_duration:.2f} 秒。")

    # 生成并打印测试结果摘要
    summary = generate_summary(test_results)
    logger.info("\n--- 测试结果摘要 ---")
    for key, value in summary.items():
        if isinstance(value, dict):
            logger.info(f"{key}:")
            for sub_key, sub_value in value.items():
                logger.info(f"  - {sub_key}: {sub_value}")
        else:
            logger.info(f"{key}: {value}")

    # **重要：打印最终成功节点的数量到标准输出**
    # GitHub Actions 可以捕获到这个输出，并在工作流概览中显示
    print(f"最终成功节点数: {len(successful_nodes)}")

if __name__ == "__main__":
    asyncio.run(main())
