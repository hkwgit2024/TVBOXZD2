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
SS_TXT_URL = "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/ss.txt"
DATA_DIR = "data"
HISTORY_FILE = os.path.join(DATA_DIR, "history_results.json")
DNS_CACHE_FILE = os.path.join(DATA_DIR, "dns_cache.json")
SUCCESSFUL_NODES_OUTPUT_FILE = os.path.join(DATA_DIR, "sub.txt")
TEST_TIMEOUT_SECONDS = float(os.getenv("TEST_TIMEOUT", 2))  # 默认 2 秒
BATCH_SIZE = 100  # 每批处理节点数，增大以减少调度开销
DNS_CACHE_EXPIRATION = 2678400  # 31 天
HISTORY_EXPIRATION = 604800  # 历史记录 7 天

# 动态设置最大并发数
def get_optimal_concurrency():
    cpu_count = psutil.cpu_count()
    memory = psutil.virtual_memory()
    available_memory = memory.available / (1024 ** 2)  # MB
    base_concurrency = cpu_count * 50
    if available_memory < 1000:
        base_concurrency = cpu_count * 20
    return min(base_concurrency, 200)

MAX_CONCURRENT_TASKS = get_optimal_concurrency()

# --- 日志配置 ---
logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
if os.getenv('DEBUG_LOG') == 'true':
    logging.getLogger().setLevel(logging.DEBUG)

# --- 预编译正则表达式 ---
PROTOCOL_RE = re.compile(r"^(vless|vmess|trojan|ss|hy2|hysteria2):\/\/[^\s]+$", re.IGNORECASE)
HOST_PORT_RE = re.compile(r"(?:@|:)(\d{1,5})(?:\?|$|#)")
NODE_LINK_RE = re.compile(r"^(vless|vmess|trojan|ss|hy2|hysteria2):\/\/(.*)")
HOST_PORT_FULL_RE = re.compile(r"^(?:\[([0-9a-fA-F:]+)\]|([0-9]{1,3}(?:\.[0-9]{1,3}){3})|([a-zA-Z0-9.-]+)):([0-9]+)$")
IP_RE = re.compile(r"^(?:\[[0-9a-fA-F:]+\]|[0-9]{1,3}(?:\.[0-9]{1,3}){3})$")

# --- 数据结构 ---
class NodeTestResult:
    def __init__(self, node_info, status, delay_ms=-1, error_message=""):
        self.node_info = node_info
        self.status = status
        self.delay_ms = delay_ms
        self.error_message = error_message

# --- 全局变量 ---
history_results = {}
dns_cache = {}

# --- 辅助函数 ---
def normalize_link(link):
    """规范化节点链接，忽略次要参数"""
    try:
        parsed = urlparse(link)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    except:
        return link

async def bulk_dns_lookup(hostnames):
    """批量 DNS 解析，优先使用缓存"""
    resolver = aiodns.DNSResolver(nameservers=["8.8.8.8", "1.1.1.1"])
    results = {}
    current_time = int(time.time())
    cache_hits = 0

    to_resolve = []
    for hostname in hostnames:
        if hostname in dns_cache and current_time - dns_cache[hostname]["timestamp"] < DNS_CACHE_EXPIRATION:
            results[hostname] = dns_cache[hostname]["ip"]
            cache_hits += 1
        else:
            to_resolve.append(hostname)

    if to_resolve:
        tasks = [resolver.query(hostname, 'A') for hostname in to_resolve]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        for hostname, response in zip(to_resolve, responses):
            if isinstance(response, Exception):
                try:
                    response = await resolver.query(hostname, 'AAAA')  # 尝试 IPv6
                    ip = response[0].host
                    results[hostname] = ip
                    dns_cache[hostname] = {"ip": ip, "timestamp": current_time}
                except Exception as e:
                    logger.debug(f"DNS 解析失败 {hostname}: {e}")
                continue
            if response:
                ip = response[0].host
                results[hostname] = ip
                dns_cache[hostname] = {"ip": ip, "timestamp": current_time}

    logger.info(f"DNS 解析: {len(hostnames)} 个域名，缓存命中 {cache_hits} ({cache_hits/len(hostnames)*100:.2f}%)，成功 {len(results)}")
    return results

async def load_history():
    """异步加载历史结果"""
    global history_results
    if os.path.exists(HISTORY_FILE):
        try:
            async with aiofiles.open(HISTORY_FILE, "r", encoding="utf-8") as f:
                history_results = json.loads(await f.read())
            logger.info(f"历史结果加载成功: {len(history_results)} 条记录")
        except json.JSONDecodeError as e:
            logger.warning(f"历史结果文件损坏或为空，重新创建: {e}")
            history_results = {}
    else:
        logger.info("历史结果文件不存在，将创建新文件")

async def save_history():
    """异步保存历史结果，清理过期记录"""
    current_time = int(time.time())
    cleaned_history = {
        node_id: data for node_id, data in history_results.items()
        if current_time - data.get("timestamp", 0) < HISTORY_EXPIRATION
    }
    os.makedirs(DATA_DIR, exist_ok=True)
    async with aiofiles.open(HISTORY_FILE, "w", encoding="utf-8") as f:
        await f.write(json.dumps(cleaned_history, indent=2, ensure_ascii=False))
    logger.info(f"历史结果已保存: {len(cleaned_history)} 条记录")

async def load_dns_cache():
    """异步加载 DNS 缓存"""
    global dns_cache
    if os.path.exists(DNS_CACHE_FILE):
        try:
            async with aiofiles.open(DNS_CACHE_FILE, "r", encoding="utf-8") as f:
                dns_cache = json.loads(await f.read())
            logger.info(f"DNS 缓存加载成功: {len(dns_cache)} 条记录")
        except json.JSONDecodeError as e:
            logger.warning(f"DNS 缓存文件损坏或为空，重新创建: {e}")
            dns_cache = {}
    else:
        logger.info("DNS 缓存文件不存在，将创建新文件")

async def save_dns_cache():
    """异步保存 DNS 缓存"""
    current_time = int(time.time())
    cleaned_cache = {
        host: data for host, data in dns_cache.items()
        if current_time - data.get("timestamp", 0) < DNS_CACHE_EXPIRATION
    }
    os.makedirs(DATA_DIR, exist_ok=True)
    async with aiofiles.open(DNS_CACHE_FILE, "w", encoding="utf-8") as f:
        await f.write(json.dumps(cleaned_cache, indent=2, ensure_ascii=False))
    logger.info("DNS 缓存已保存并清理过期记录")

async def fetch_ss_txt(url):
    """获取节点列表"""
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
            response = await client.get(url)
            response.raise_for_status()
            return response.text
    except httpx.RequestError as e:
        logger.error(f"获取节点列表失败: {url} - {e}")
        return None
    except Exception as e:
        logger.error(f"获取节点列表时发生未知错误: {url} - {e}")
        return None

def prefilter_links(links):
    """预过滤无效节点链接"""
    valid_links = []
    for link in links:
        link = link.strip()
        if not link:
            continue
        if not PROTOCOL_RE.match(link):
            logger.debug(f"过滤无效链接（协议不匹配）: {link}")
            continue
        if not HOST_PORT_RE.search(link):
            logger.debug(f"过滤无效链接（缺少端口）: {link}")
            continue
        valid_links.append(link)
    logger.info(f"预过滤完成：原始 {len(links)} 条链接，保留 {len(valid_links)} 条")
    return valid_links

def parse_node_info(link):
    """解析节点信息"""
    node_info = {'original_link': link}
    try:
        link = link.strip()
        if not link:
            return None

        match = NODE_LINK_RE.match(link)
        if not match:
            logger.debug(f"无法识别协议: {link}")
            return None

        protocol = match.group(1).lower()
        remaining_part = match.group(2)
        node_info['protocol'] = protocol

        if '#' in remaining_part:
            remaining_part, remarks = remaining_part.rsplit('#', 1)
            node_info['remarks'] = unquote(remarks)
        else:
            node_info['remarks'] = f"{protocol.upper()} Node"

        if protocol in ['vless', 'vmess', 'trojan', 'ss']:
            if '@' in remaining_part:
                user_info_part, host_port_part = remaining_part.split('@', 1)
            else:
                user_info_part = ""
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
                    logger.debug(f"端口号无效（范围 1-65535）: {node_info['port']} in {link}")
                    return None
            else:
                logger.debug(f"无法解析 host:port: {host_port_str} in {link}")
                return None

            for key, values in query_params.items():
                node_info[key] = values[0]

        elif protocol in ['hy2', 'hysteria2']:
            parts = remaining_part.split('?', 1)
            host_port_str = parts[0]
            query_params = parse_qs(parts[1]) if len(parts) > 1 else {}

            host_match = HOST_PORT_FULL_RE.match(host_port_str)
            if host_match:
                node_info['server'] = host_match.group(1) or host_match.group(2) or host_match.group(3)
                node_info['port'] = int(host_match.group(4))
                if not (1 <= node_info['port'] <= 65535):
                    logger.debug(f"端口号无效（范围 1-65535）: {node_info['port']} in {link}")
                    return None
            else:
                logger.debug(f"无法解析 hy2 host:port: {host_port_str} in {link}")
                return None
            for key, values in query_params.items():
                node_info[key] = values[0]

        else:
            logger.warning(f"不支持的协议类型: {protocol} for link {link}")
            return None

        if not IP_RE.match(node_info['server']):
            node_info['is_domain'] = True
        else:
            node_info['is_domain'] = False
            node_info['resolved_ip'] = node_info['server']

        return node_info

    except Exception as e:
        logger.error(f"解析节点链接时发生错误: {link} - {e}")
        return None

async def check_node(node_info):
    """测试节点连通性"""
    node_id = node_info['original_link']
    current_time = time.time()
    if node_id in history_results:
        record = history_results[node_id]
        if record['status'] == 'Successful' and current_time - record['timestamp'] < 300:
            logger.debug(f"使用缓存结果: {node_info['remarks']}")
            return NodeTestResult(node_info, 'Successful', record['delay_ms'])
        elif record['status'] == 'Failed' and current_time - record['timestamp'] < HISTORY_EXPIRATION:
            logger.debug(f"跳过历史失败节点: {node_info['remarks']}")
            return NodeTestResult(node_info, 'Failed', -1, record['error_message'])

    protocol = node_info.get('protocol')
    remarks = node_info.get('remarks', 'N/A')
    server = node_info.get('server')
    port = node_info.get('port')
    target_host = node_info.get('resolved_ip')

    if not all([server, port, target_host]):
        return NodeTestResult(node_info, "Failed", -1, "信息不完整或DNS解析失败")

    test_start_time = time.monotonic()
    error_message = ""
    sock = None
    wrapped_socket = None

    try:
        if protocol in ['hy2', 'hysteria2']:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(TEST_TIMEOUT_SECONDS)
                sock.connect((target_host, port))
                sock.sendall(b'ping')
                logger.info(f"UDP 端口 {target_host}:{port} 可达")
                test_end_time = time.monotonic()
                delay = (test_end_time - test_start_time) * 1000
                return NodeTestResult(node_info, "Successful", delay)
            except socket.timeout:
                error_message = "UDP Connection Timeout"
            except ConnectionRefusedError:
                error_message = "UDP Connection Refused"
            except Exception as e:
                error_message = f"UDP Test Error: {e}"
            finally:
                if sock:
                    sock.close()
            return NodeTestResult(node_info, "Failed", -1, error_message)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TEST_TIMEOUT_SECONDS)
            await asyncio.get_event_loop().run_in_executor(
                None, sock.connect, (target_host, port)
            )

            if node_info.get('security') == 'tls':
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sni_hostname = node_info.get('sni') or node_info.get('host') or node_info['server']
                wrapped_socket = context.wrap_socket(sock, server_hostname=sni_hostname)
                await asyncio.get_event_loop().run_in_executor(
                    None, wrapped_socket.do_handshake
                )
            test_end_time = time.monotonic()
            delay = (test_end_time - test_start_time) * 1000
            logger.info(f"测试 {remarks} ({target_host}:{port}) - 状态: Successful, 延迟: {delay:.2f}ms")
            return NodeTestResult(node_info, "Successful", delay)

        except socket.timeout:
            error_message = "TCP Connection Timeout"
        except ConnectionRefusedError:
            error_message = "TCP Connection Refused"
        except ssl.SSLError as e:
            error_message = f"TLS Handshake Error: {e}"
        except Exception as e:
            error_message = f"Unexpected error during TCP/TLS test: {e}"
        finally:
            if wrapped_socket:
                wrapped_socket.close()
            if sock:
                sock.close()

    except Exception as e:
        error_message = f"Critical error during node check: {e}"
    finally:
        if wrapped_socket:
            wrapped_socket.close()
        if sock:
            sock.close()

    logger.warning(f"测试 {remarks} ({target_host}:{port}) - 状态: Failed, 延迟: -1ms, 错误: {error_message}")
    return NodeTestResult(node_info, "Failed", -1, error_message)

async def test_nodes_in_batches(nodes, batch_size=BATCH_SIZE):
    """分批测试节点"""
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_TASKS)
    async def test_node_with_semaphore(node):
        async with semaphore:
            return await check_node(node)

    results = []
    for i in range(0, len(nodes), batch_size):
        batch = nodes[i:i + batch_size]
        batch_results = await asyncio.gather(*(test_node_with_semaphore(node) for node in batch))
        results.extend(batch_results)
        logger.info(f"完成批次 {i // batch_size + 1}/{len(nodes) // batch_size + 1}")
    return results

def generate_summary(test_results):
    """生成测试总结"""
    successful_nodes = [r for r in test_results if r.status == "Successful"]
    success_count = len(successful_nodes)
    total_count = len(test_results)
    success_rate = (success_count / total_count * 100) if total_count else 0
    avg_delay = sum(r.delay_ms for r in successful_nodes) / success_count if success_count else -1
    logger.info(f"测试总结：成功 {success_count}/{total_count} ({success_rate:.2f}%)，平均延迟 {avg_delay:.2f}ms")

async def main():
    """主函数"""
    start_time = time.time()
    os.makedirs(DATA_DIR, exist_ok=True)
    await load_history()
    await load_dns_cache()

    ss_txt_content = await fetch_ss_txt(SS_TXT_URL)
    if not ss_txt_content:
        logger.error("无法获取节点列表或列表为空，退出")
        async with aiofiles.open(SUCCESSFUL_NODES_OUTPUT_FILE, "w", encoding="utf-8") as f:
            await f.write("# No valid nodes found or tested.\n")
        return

    links = ss_txt_content.strip().split('\n')
    filtered_links = prefilter_links(links)
    if not filtered_links:
        logger.warning("预过滤后无有效链接，退出")
        async with aiofiles.open(SUCCESSFUL_NODES_OUTPUT_FILE, "w", encoding="utf-8") as f:
            await f.write("# No valid nodes found or tested.\n")
        return

    loop = asyncio.get_event_loop()
    with ThreadPoolExecutor() as executor:
        parsed_nodes = await loop.run_in_executor(
            executor,
            lambda: [parse_node_info(link) for link in filtered_links if parse_node_info(link)]
        )
    total_parsed_nodes = len(parsed_nodes)
    logger.info(f"总计解析到 {total_parsed_nodes} 个节点")

    if not parsed_nodes:
        logger.warning("未解析到任何有效节点，退出")
        async with aiofiles.open(SUCCESSFUL_NODES_OUTPUT_FILE, "w", encoding="utf-8") as f:
            await f.write("# No valid nodes found.\n")
        return

    # 过滤节点
    current_time = time.time()
    failed_nodes = {
        normalize_link(node_id) for node_id, data in history_results.items()
        if data['status'] == 'Failed' and current_time - data['timestamp'] < HISTORY_EXPIRATION
    }
    successful_nodes_set = {
        normalize_link(node_id) for node_id, data in history_results.items()
        if data['status'] == 'Successful' and current_time - data['timestamp'] < HISTORY_EXPIRATION
    }
    priority_nodes = [node for node in parsed_nodes if normalize_link(node['original_link']) in successful_nodes_set]
    other_nodes = [node for node in parsed_nodes if normalize_link(node['original_link']) not in failed_nodes]
    nodes_to_test = priority_nodes + other_nodes
    logger.info(f"过滤后待测试节点: {len(nodes_to_test)}/{total_parsed_nodes} (优先 {len(priority_nodes)} 个成功节点)")

    # 预解析域名
    logger.info("开始预解析域名...")
    domains_to_resolve = {node['server'] for node in nodes_to_test if node.get('is_domain')}
    if domains_to_resolve:
        await bulk_dns_lookup(domains_to_resolve)
    logger.info("域名预解析完成")

    test_results = []
    for node in nodes_to_test:
        if node.get('is_domain'):
            if node['server'] in dns_cache:
                node['resolved_ip'] = dns_cache[node['server']]['ip']
            else:
                test_results.append(NodeTestResult(node, "Failed", -1, "DNS resolution failed"))
                logger.debug(f"跳过 {node.get('remarks')}，因为DNS解析失败")
                continue
        test_results.extend(await test_nodes_in_batches([node]))

    # 保存结果
    successful_nodes = []
    for result in test_results:
        node_id = result.node_info['original_link']
        if result.status == "Successful":
            successful_nodes.append(result.node_info)
            history_results[node_id] = {
                "status": "Successful",
                "delay_ms": result.delay_ms,
                "timestamp": int(time.time())
            }
        else:
            history_results[node_id] = {
                "status": "Failed",
                "error_message": result.error_message,
                "timestamp": int(time.time())
            }

    # 生成总结
    generate_summary(test_results)
    successful_nodes_count = len(successful_nodes)
    failed_nodes_count = len(test_results) - successful_nodes_count
    logger.info(f"测试完成。成功节点数: {successful_nodes_count}, 失败节点数: {failed_nodes_count}")

    # 写入 sub.txt
    async with aiofiles.open(SUCCESSFUL_NODES_OUTPUT_FILE, "w", encoding="utf-8") as f:
        if successful_nodes:
            links = [node['original_link'] for node in successful_nodes]
            await f.write("\n".join(links) + "\n")
            logger.info(f"写入 {len(links)} 个节点到 {SUCCESSFUL_NODES_OUTPUT_FILE}")
        else:
            await f.write("# No valid nodes found.\n")
            logger.info(f"无可用节点，写入空提示到 {SUCCESSFUL_NODES_OUTPUT_FILE}")

    await save_history()
    await save_dns_cache()
    logger.info(f"总耗时: {time.time() - start_time:.2f} 秒")

if __name__ == "__main__":
    asyncio.run(main())
