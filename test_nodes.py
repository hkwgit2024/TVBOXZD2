import httpx
import asyncio
import json
import os
import logging
import re
import time
from urllib.parse import urlparse, unquote, parse_qs
import socket
import ssl # 确保导入 ssl 模块

# --- 配置 ---
SS_TXT_URL = "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/ss.txt"
DATA_DIR = "data"
HISTORY_FILE = os.path.join(DATA_DIR, "history_results.json")
DNS_CACHE_FILE = os.path.join(DATA_DIR, "dns_cache.json")
SUCCESSFUL_NODES_OUTPUT_FILE = os.path.join(DATA_DIR, "sub.txt") # 仅包含成功链接

TEST_TIMEOUT_SECONDS = 5 # 单个节点测试超时时间
MAX_CONCURRENT_TASKS = 200 # 最大并发测试数量
DNS_CACHE_EXPIRATION = 24 * 60 * 60 # DNS 缓存有效期 24 小时 (秒)

# --- 日志配置 ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- 数据结构 ---
class NodeTestResult:
    def __init__(self, node_info, status, delay_ms=-1, error_message=""):
        self.node_info = node_info
        self.status = status
        self.delay_ms = delay_ms
        self.error_message = error_message

# --- 全局 DNS 缓存和历史结果 ---
history_results = {}
dns_cache = {}

# --- 辅助函数 ---
async def load_history():
    global history_results
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                history_results = json.load(f)
            logger.info(f"历史结果加载成功: {len(history_results)} 条记录。")
        except json.JSONDecodeError as e:
            logger.warning(f"历史结果文件损坏或为空，重新创建: {e}")
            history_results = {}
    else:
        logger.info("历史结果文件不存在，将创建新文件。")

async def save_history():
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(history_results, f, indent=2, ensure_ascii=False)
    logger.info("历史结果已保存。")

async def load_dns_cache():
    global dns_cache
    if os.path.exists(DNS_CACHE_FILE):
        try:
            with open(DNS_CACHE_FILE, "r", encoding="utf-8") as f:
                dns_cache = json.load(f)
            logger.info(f"DNS 缓存加载成功: {len(dns_cache)} 条记录。")
        except json.JSONDecodeError as e:
            logger.warning(f"DNS 缓存文件损坏或为空，重新创建: {e}")
            dns_cache = {}
    else:
        logger.info("DNS 缓存文件不存在，将创建新文件。")

async def save_dns_cache():
    current_time = int(time.time())
    cleaned_cache = {
        host: data for host, data in dns_cache.items()
        if current_time - data.get("timestamp", 0) < DNS_CACHE_EXPIRATION
    }
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(DNS_CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cleaned_cache, f, indent=2, ensure_ascii=False)
    logger.info("DNS 缓存已保存并清理过期记录。")

async def dns_lookup(hostname):
    current_time = int(time.time())
    if hostname in dns_cache:
        cached_data = dns_cache[hostname]
        if current_time - cached_data.get("timestamp", 0) < DNS_CACHE_EXPIRATION:
            logger.debug(f"从缓存获取 DNS: {hostname} -> {cached_data['ip']}")
            return cached_data["ip"]
        else:
            logger.info(f"DNS 缓存 {hostname} 已过期，重新查询。")
            del dns_cache[hostname]

    try:
        addr_info = await asyncio.get_event_loop().run_in_executor(
            None, socket.getaddrinfo, hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM
        )
        if addr_info:
            ip_address = addr_info[0][4][0]
            dns_cache[hostname] = {"ip": ip_address, "timestamp": current_time}
            logger.info(f"DNS 解析成功: {hostname} -> {ip_address}")
            return ip_address
        else:
            logger.warning(f"DNS 解析无结果: {hostname}")
            return None
    except socket.gaierror as e:
        logger.error(f"DNS 解析失败 {hostname}: {e}")
        return None
    except Exception as e:
        logger.error(f"DNS 解析时发生未知错误 {hostname}: {e}")
        return None

async def fetch_ss_txt(url):
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

def parse_node_info(link):
    node_info = {'original_link': link}

    try:
        link = link.strip()
        if not link:
            return None

        match = re.match(r"^(vless|vmess|trojan|ss|hy2|hysteria2):\/\/(.*)", link)
        if not match:
            logger.debug(f"无法识别协议: {link}")
            return None

        protocol = match.group(1)
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

            host_match = re.match(r"^(?:\[([0-9a-fA-F:]+)\]|([0-9]{1,3}(?:\.[0-9]{1,3}){3})|([a-zA-Z0-9.-]+)):([0-9]+)$", host_port_str)
            if host_match:
                node_info['server'] = host_match.group(1) or host_match.group(2) or host_match.group(3)
                node_info['port'] = int(host_match.group(4))
            else:
                logger.debug(f"无法解析 host:port: {host_port_str} in {link}")
                return None

            for key, values in query_params.items():
                node_info[key] = values[0]

        elif protocol in ['hy2', 'hysteria2']:
            parts = remaining_part.split('?', 1)
            host_port_str = parts[0]
            if '?' in remaining_part:
                query_params = parse_qs(remaining_part.split('?', 1)[1])
            else:
                query_params = {}

            host_match = re.match(r"^(?:\[([0-9a-fA-F:]+)\]|([0-9]{1,3}(?:\.[0-9]{1,3}){3})|([a-zA-Z0-9.-]+)):([0-9]+)$", host_port_str)
            if host_match:
                node_info['server'] = host_match.group(1) or host_match.group(2) or host_match.group(3)
                node_info['port'] = int(host_match.group(4))
            else:
                logger.debug(f"无法解析 hy2 host:port: {host_port_str} in {link}")
                return None
            for key, values in query_params.items():
                node_info[key] = values[0]

        else:
            logger.warning(f"不支持的协议类型: {protocol} for link {link}")
            return None

        if not re.match(r"^(?:\[[0-9a-fA-F:]+\]|[0-9]{1,3}(?:\.[0-9]{1,3}){3})$", node_info['server']):
            node_info['is_domain'] = True
        else:
            node_info['is_domain'] = False
            node_info['resolved_ip'] = node_info['server']

        return node_info

    except Exception as e:
        logger.error(f"解析节点链接时发生错误: {link} - {e}")
        return None


async def check_node(node_info):
    protocol = node_info.get('protocol')
    remarks = node_info.get('remarks', 'N/A')
    server = node_info.get('server')
    port = node_info.get('port')
    target_host = node_info.get('resolved_ip')

    if not all([server, port, target_host]):
        return NodeTestResult(node_info, "Failed", -1, "信息不完整或DNS解析失败")

    test_start_time = time.monotonic()
    error_message = ""

    try:
        if protocol in ['hy2', 'hysteria2']:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(TEST_TIMEOUT_SECONDS)
                sock.connect((target_host, port))
                sock.sendall(b'ping')
                logger.info(f"UDP 端口 {target_host}:{port} 可达。")
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
                if 'sock' in locals() and sock:
                    sock.close()
            return NodeTestResult(node_info, "Failed", -1, error_message)

        # 对于其他协议 (VLESS, VMESS, Trojan, SS)
        try:
            # 建立 TCP 连接
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TEST_TIMEOUT_SECONDS)
            await asyncio.get_event_loop().run_in_executor(
                None, sock.connect, (target_host, port)
            )

            # 对于 TLS 节点，尝试 SSL/TLS 握手
            if node_info.get('security') == 'tls':
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                sni_hostname = node_info.get('sni') or node_info.get('host') or node_info['server']
                if sni_hostname:
                    logger.debug(f"尝试 TLS 握手，SNI: {sni_hostname}")
                    wrapped_socket = context.wrap_socket(sock, server_hostname=sni_hostname)
                else:
                    wrapped_socket = context.wrap_socket(sock)

                await asyncio.get_event_loop().run_in_executor(
                    None, wrapped_socket.do_handshake
                )
                wrapped_socket.close() # 握手成功后关闭
            else:
                # 对于非 TLS 协议，TCP 连接成功即认为是可达
                pass # 保持 socket 打开，以便 finally 关闭

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
            if 'sock' in locals() and sock:
                sock.close()

    except Exception as e:
        error_message = f"Critical error during node check: {e}"

    logger.warning(f"测试 {remarks} ({target_host}:{port}) - 状态: Failed, 延迟: -1ms, 错误: {error_message}")
    return NodeTestResult(node_info, "Failed", -1, error_message)


async def main():
    os.makedirs(DATA_DIR, exist_ok=True)
    await load_history()
    await load_dns_cache()

    ss_txt_content = await fetch_ss_txt(SS_TXT_URL)
    if not ss_txt_content:
        logger.error("无法获取节点列表或列表为空，退出。")
        # 即使这里退出，也创建空的 sub.txt 文件
        with open(SUCCESSFUL_NODES_OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write("# No valid nodes found or tested.\n")
        return

    links = ss_txt_content.strip().split('\n')
    parsed_nodes = [parse_node_info(link) for link in links if parse_node_info(link)]
    total_parsed_nodes = len(parsed_nodes)
    logger.info(f"总计解析到 {total_parsed_nodes} 个节点。")

    if not parsed_nodes:
        logger.warning("未解析到任何有效节点，退出。")
        with open(SUCCESSFUL_NODES_OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write("# No valid nodes found or tested.\n")
        return

    logger.info("开始预解析域名...")
    domains_to_resolve = set()
    for node in parsed_nodes:
        if node.get('is_domain') and node['server'] not in dns_cache:
            domains_to_resolve.add(node['server'])

    if domains_to_resolve:
        dns_tasks = [dns_lookup(domain) for domain in domains_to_resolve]
        await asyncio.gather(*dns_tasks)
    logger.info("域名预解析完成。")

    # 更新节点的 resolved_ip，并过滤掉 DNS 解析失败的节点
    nodes_to_test = []
    # test_results 用于历史记录和最终统计，即使不生成报告也需要它
    test_results = []
    
    for node in parsed_nodes:
        if node.get('is_domain'):
            if node['server'] in dns_cache:
                node['resolved_ip'] = dns_cache[node['server']]['ip']
                nodes_to_test.append(node)
            else: # DNS 解析失败
                node['resolved_ip'] = None
                test_results.append(NodeTestResult(node, "Failed", -1, "DNS resolution failed"))
                logger.debug(f"跳过 {node.get('remarks')}，因为DNS解析失败。")
        else: # 本身就是IP
            nodes_to_test.append(node)

    logger.info(f"准备测试 {len(nodes_to_test)} 个节点。")

    # 使用 asyncio.Semaphore 控制并发数量
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_TASKS)
    
    async def test_node_with_semaphore(node):
        async with semaphore:
            result = await check_node(node)
            # 将结果添加到 test_results，无论是成功还是失败
            test_results.append(result) 
            return result

    # 创建并运行所有测试任务
    tasks = [test_node_with_semaphore(node) for node in nodes_to_test]
    await asyncio.gather(*tasks)

    # 统计结果并更新历史记录
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
    
    successful_nodes_count = len(successful_nodes)
    failed_nodes_count = len(test_results) - successful_nodes_count

    logger.info(f"测试完成。成功节点数: {successful_nodes_count}, 失败节点数: {failed_nodes_count}")

    # 只将成功节点写入 sub.txt (原始链接)
    with open(SUCCESSFUL_NODES_OUTPUT_FILE, "w", encoding="utf-8") as f:
        if successful_nodes:
            for node in successful_nodes:
                f.write(f"{node['original_link']}\n")
        else:
            f.write("# No valid nodes found.\n") # 如果没有成功节点，也写入一行注释
    logger.info(f"可用节点链接已写入: {SUCCESSFUL_NODES_OUTPUT_FILE}")

    # 保存历史记录和 DNS 缓存
    await save_history()
    await save_dns_cache()

if __name__ == "__main__":
    asyncio.run(main())
