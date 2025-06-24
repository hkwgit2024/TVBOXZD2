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
import subprocess
from urllib.parse import urlparse, unquote, parse_qs
from concurrent.futures import ThreadPoolExecutor
import base64

# --- 配置 ---
# 将 SOURCE_URLS 定义为一个列表，支持从多个地址获取节点信息
SOURCE_URLS = [
    "https://raw.githubusercontent.com/qjlxg/hy2/refs/heads/main/configtg.txt",
]

DATA_DIR = "data"  # 数据文件存放目录
HISTORY_FILE = os.path.join(DATA_DIR, "history_results.json")  # 历史测试结果文件路径
DNS_CACHE_FILE = os.path.join(DATA_DIR, "dns_cache.json")  # DNS 缓存文件路径
SUCCESSFUL_NODES_OUTPUT_FILE = os.path.join(DATA_DIR, "sub.txt")  # 成功节点输出文件路径

# 从环境变量获取测试超时时间，默认 5 秒
TEST_TIMEOUT_SECONDS = float(os.getenv("TEST_TIMEOUT", 5))
BATCH_SIZE = 100  # 每次处理的节点数量，用于分批处理以优化性能
DNS_CACHE_EXPIRATION = 2678400  # DNS 缓存有效期：31 天 (单位：秒)
HISTORY_EXPIRATION = 2678400  # 历史记录有效期：31 天 (单位：秒)

# --- 代理客户端配置 ---
# Xray 可执行文件路径，从环境变量获取，默认为当前目录下的 xray
XRAY_PATH = os.getenv("XRAY_PATH", "./xray")
XRAY_CONFIG_FILE = os.path.join(DATA_DIR, "xray_config.json")  # Xray 临时配置文件
LOCAL_PROXY_PORT = 10800  # Xray 监听的本地 SOCKS5 端口

# 测试代理是否成功的外部网址，使用无内容的快速响应地址
TEST_PROXY_URL = "http://www.gstatic.com/generate_204"

# --- 日志配置 ---
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()
logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.INFO),
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- 预编译正则表达式 ---
PROTOCOL_RE = re.compile(r"^(vless|vmess|trojan|ss|hy2|hysteria2):\/\/[^\s]+$", re.IGNORECASE)
HOST_PORT_RE = re.compile(r"(?:@|:)(\d{1,5})(?:\?|$|#)")
NODE_LINK_RE = re.compile(r"^(vless|vmess|trojan|ss|hy2|hysteria2):\/\/(.*)")
HOST_PORT_FULL_RE = re.compile(r"^(?:\[([0-9a-fA-F:]+)\]|([0-9]{1,3}(?:\.[0-9]{1,3}){3})|([a-zA-Z0-9.-]+)):([0-9]+)$")
IP_RE = re.compile(r"^(?:\[[0-9a-fA-F:]+\]|[0-9]{1,3}(?:\.[0-9]{1,3}){3})$")

# --- 数据结构 ---
class NodeTestResult:
    """封装单个节点的测试结果"""
    def __init__(self, node_info, status, delay_ms=-1, error_message=""):
        self.node_info = node_info
        self.status = status
        self.delay_ms = delay_ms
        self.error_message = error_message

# --- 全局变量 ---
history_results = {}  # 存储节点历史测试结果
dns_cache = {}  # 存储 DNS 解析缓存
xray_process = None  # Xray 子进程对象

# --- 辅助函数 ---
def normalize_link(link):
    """规范化节点链接，移除查询参数和片段以生成稳定键"""
    try:
        parsed = urlparse(link)
        base_link = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        return base_link.rstrip('/')
    except Exception as e:
        logger.warning(f"规范化链接 '{link}' 失败: {e}")
        return link

async def bulk_dns_lookup(hostnames):
    """执行批量 DNS 查询，支持缓存和 IPv6 回退"""
    resolver = aiodns.DNSResolver(nameservers=["223.5.5.5", "114.114.114.114", "8.8.8.8"])
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
        async def _resolve_single(h):
            try:
                resp = await resolver.query(h, 'A')
                return h, resp[0].host
            except Exception:
                try:
                    resp = await resolver.query(h, 'AAAA')
                    return h, resp[0].host
                except Exception as e:
                    logger.debug(f"DNS 解析 {h} 失败: {e}")
                    return h, None

        tasks = [_resolve_single(hostname) for hostname in to_resolve]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        for hostname, result in responses:
            if result:
                results[hostname] = result
                dns_cache[hostname] = {"ip": result, "timestamp": current_time}
                logger.debug(f"已将 {hostname} 解析到 IP: {result}")

    logger.info(f"DNS 查询: 总共 {len(hostnames)} 个，缓存命中 {cache_hits} 个，成功解析 {len([k for k, v in results.items() if v])} 个")
    return results

async def load_history():
    """异步加载历史测试结果"""
    global history_results
    if os.path.exists(HISTORY_FILE):
        try:
            async with aiofiles.open(HISTORY_FILE, "r", encoding="utf-8") as f:
                content = await f.read()
                history_results = json.loads(content) if content else {}
            logger.info(f"历史结果已加载: {len(history_results)} 条记录")
        except Exception as e:
            logger.warning(f"加载历史文件失败: {e}")
            history_results = {}
    else:
        logger.info("未找到历史结果文件，初始化为空")

async def save_history():
    """异步保存历史测试结果，清理过期记录"""
    current_time = int(time.time())
    cleaned_history = {k: v for k, v in history_results.items() if current_time - v.get("timestamp", 0) < HISTORY_EXPIRATION}
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
                content = await f.read()
                dns_cache = json.loads(content) if content else {}
            logger.info(f"DNS 缓存已加载: {len(dns_cache)} 条记录")
        except Exception as e:
            logger.warning(f"加载 DNS 缓存失败: {e}")
            dns_cache = {}
    else:
        logger.info("未找到 DNS 缓存文件，初始化为空")

async def save_dns_cache():
    """异步保存 DNS 缓存，清理过期记录"""
    current_time = int(time.time())
    cleaned_cache = {k: v for k, v in dns_cache.items() if current_time - v.get("timestamp", 0) < DNS_CACHE_EXPIRATION}
    os.makedirs(DATA_DIR, exist_ok=True)
    async with aiofiles.open(DNS_CACHE_FILE, "w", encoding="utf-8") as f:
        await f.write(json.dumps(cleaned_cache, indent=2, ensure_ascii=False))
    logger.info(f"DNS 缓存已保存: {len(cleaned_cache)} 条记录")

async def fetch_ss_txt(url):
    """从指定 URL 获取节点列表文本"""
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=15) as client:
            response = await client.get(url)
            response.raise_for_status()
            return response.text
    except Exception as e:
        logger.error(f"从 {url} 获取节点列表失败: {e}")
        return None

def prefilter_links(links):
    """预过滤无效节点链接"""
    valid_links = [link.strip() for link in links if link.strip() and PROTOCOL_RE.match(link) and HOST_PORT_RE.search(link)]
    logger.info(f"预过滤: 原始 {len(links)} 条，保留 {len(valid_links)} 条")
    return valid_links

def parse_node_info(link):
    """解析节点链接信息"""
    node_info = {'original_link': link}
    try:
        match = NODE_LINK_RE.match(link.strip())
        if not match:
            logger.debug(f"无效协议: {link}")
            return None

        protocol = match.group(1).lower()
        remaining_part = match.group(2)
        node_info['protocol'] = protocol
        node_info['remarks'] = unquote(remaining_part.rsplit('#', 1)[1]) if '#' in remaining_part else f"{protocol.upper()} 节点"

        if protocol in ['vless', 'trojan']:
            user_info_part, host_port_part = remaining_part.split('@', 1) if '@' in remaining_part else ("", remaining_part)
            node_info['user_info_part'] = user_info_part
            host_port_str, query_params = (host_port_part.split('?', 1) if '?' in host_port_part else (host_port_part, {}))
            query_params = parse_qs(query_params) if isinstance(query_params, str) else query_params

            host_match = HOST_PORT_FULL_RE.match(host_port_str)
            if host_match:
                node_info['server'] = host_match.group(1) or host_match.group(2) or host_match.group(3)
                node_info['port'] = int(host_match.group(4))
                if not (1 <= node_info['port'] <= 65535):
                    return None
            else:
                return None

            for key, values in query_params.items():
                node_info[key] = values[0]

        elif protocol == 'vmess':
            encoded_part = remaining_part.split('#')[0]
            decoded_str = base64.b64decode(encoded_part + '=' * (-len(encoded_part) % 4)).decode('utf-8', 'ignore')
            node_info['user_info_part'] = decoded_str
            vmess_data = json.loads(decoded_str)
            node_info['server'] = vmess_data['add']
            node_info['port'] = int(vmess_data['port'])
            node_info.update(vmess_data)

        elif protocol == 'ss':
            encoded_part = remaining_part.split('#')[0].split('/?')[0]
            decoded_str = base64.b64decode(encoded_part + '=' * (-len(encoded_part) % 4)).decode('utf-8', 'ignore')
            parts = decoded_str.split('@', 1)
            auth_part, host_port_part = parts[0], parts[1]
            method, password = auth_part.split(':', 1)
            node_info['method'] = method
            node_info['password'] = password
            host_match = HOST_PORT_FULL_RE.match(host_port_part)
            if host_match:
                node_info['server'] = host_match.group(1) or host_match.group(2) or host_match.group(3)
                node_info['port'] = int(host_match.group(4))
                if not (1 <= node_info['port'] <= 65535):
                    return None
            else:
                return None

        elif protocol in ['hy2', 'hysteria2']:
            parts = remaining_part.split('?', 1)
            host_port_str = parts[0]
            query_params = parse_qs(parts[1]) if len(parts) > 1 else {}
            host_match = HOST_PORT_FULL_RE.match(host_port_str)
            if host_match:
                node_info['server'] = host_match.group(1) or host_match.group(2) or host_match.group(3)
                node_info['port'] = int(host_match.group(4))
                if not (1 <= node_info['port'] <= 65535):
                    return None
            for key, values in query_params.items():
                node_info[key] = values[0]

        node_info['is_domain'] = not IP_RE.match(node_info['server'])
        node_info['resolved_ip'] = node_info['server'] if not node_info['is_domain'] else None
        return node_info

    except Exception as e:
        logger.debug(f"解析节点链接 '{link}' 失败: {e}")
        return None

async def generate_xray_config(node_info):
    """生成 Xray 配置文件"""
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [{"port": LOCAL_PROXY_PORT, "listen": "127.0.0.1", "protocol": "socks", "settings": {"auth": "noauth", "udp": True}}],
        "outbounds": [{"protocol": node_info['protocol'], "settings": {}, "streamSettings": {"network": "tcp", "security": "none"}, "tag": "proxy"}],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {"type": "field", "outboundTag": "blocked", "ip": ["geoip:private"]},
                {"type": "field", "outboundTag": "direct", "domain": ["geosite:cn"]},
                {"type": "field", "outboundTag": "direct", "ip": ["geoip:cn"]},
                {"type": "field", "outboundTag": "proxy"}
            ]
        }
    }

    outbound = config['outbounds'][0]
    stream_settings = outbound['streamSettings']

    if node_info['protocol'] == 'vless':
        outbound['settings']['vnext'] = [{"address": node_info.get('resolved_ip') or node_info['server'], "port": node_info['port'], "users": [{"id": node_info['user_info_part'].split('@')[0], "level": 8}]}]
        if node_info.get('security') == 'tls' or node_info.get('type') == 'tls':
            stream_settings['security'] = 'tls'
            stream_settings['tlsSettings'] = {"allowInsecure": True, "serverName": node_info.get('sni') or node_info.get('host') or node_info['server']}
        if node_info.get('type') == 'ws':
            stream_settings['network'] = 'ws'
            stream_settings['wsSettings'] = {"path": node_info.get('path', '/'), "headers": {"Host": node_info.get('host', node_info['server'])}}
        elif node_info.get('type') == 'grpc':
            stream_settings['network'] = 'grpc'
            stream_settings['grpcSettings'] = {"serviceName": node_info.get('serviceName', '')}

    elif node_info['protocol'] == 'vmess':
        try:
            vmess_data = json.loads(node_info['user_info_part'])
            outbound['settings']['vnext'] = [{"address": node_info.get('resolved_ip') or node_info['server'], "port": node_info['port'], "users": [{"id": vmess_data['id'], "alterId": int(vmess_data.get('aid', 0)), "level": 8, "security": vmess_data.get('scy', 'auto')}]}]
            if vmess_data.get('tls') == 'tls':
                stream_settings['security'] = 'tls'
                stream_settings['tlsSettings'] = {"allowInsecure": True, "serverName": vmess_data.get('sni') or vmess_data.get('host') or node_info['server']}
            if vmess_data.get('net') == 'ws':
                stream_settings['network'] = 'ws'
                stream_settings['wsSettings'] = {"path": vmess_data.get('path', '/'), "headers": {"Host": vmess_data.get('host', node_info['server'])}}
            elif vmess_data.get('net') == 'grpc':
                stream_settings['network'] = 'grpc'
                stream_settings['grpcSettings'] = {"serviceName": vmess_data.get('path', '')}
        except Exception as e:
            logger.warning(f"解析 VMess 配置失败: {e}")
            return None

    elif node_info['protocol'] == 'trojan':
        outbound['settings']['servers'] = [{"address": node_info.get('resolved_ip') or node_info['server'], "port": node_info['port'], "password": node_info['user_info_part']}]
        stream_settings['security'] = 'tls'
        stream_settings['tlsSettings'] = {"allowInsecure": True, "serverName": node_info.get('sni') or node_info.get('host') or node_info['server']}
        if node_info.get('type') == 'ws':
            stream_settings['network'] = 'ws'
            stream_settings['wsSettings'] = {"path": node_info.get('path', '/'), "headers": {"Host": node_info.get('host', node_info['server'])}}
        elif node_info.get('type') == 'grpc':
            stream_settings['network'] = 'grpc'
            stream_settings['grpcSettings'] = {"serviceName": node_info.get('serviceName', '')}

    elif node_info['protocol'] == 'ss':
        outbound['protocol'] = 'shadowsocks'
        outbound['settings'] = {"servers": [{"address": node_info.get('resolved_ip') or node_info['server'], "port": node_info['port'], "method": node_info['method'], "password": node_info['password']}]}
        if node_info.get('plugin') == 'obfs':
            stream_settings['network'] = 'tcp'
            stream_settings['tcpSettings'] = {"header": {"type": "http", "request": {"path": [node_info.get('path', '/')], "headers": {"Host": [node_info.get('host', node_info['server'])]}}}}
        elif node_info.get('plugin') == 'v2ray-plugin':
            stream_settings['network'] = 'ws'
            plugin_opts = parse_qs(node_info.get('plugin_opts', ''))
            stream_settings['wsSettings'] = {"path": plugin_opts.get('path', ['/'])[0], "headers": {"Host": plugin_opts.get('host', [node_info['server']])[0]}}
            if 'tls' in node_info.get('plugin_opts', ''):
                stream_settings['security'] = 'tls'
                stream_settings['tlsSettings'] = {"allowInsecure": True, "serverName": node_info.get('sni') or node_info.get('host') or node_info['server']}
        else:
            del config['outbounds'][0]['streamSettings']

    elif node_info['protocol'] in ['hy2', 'hysteria2']:
        logger.warning(f"Xray 不支持 {node_info['protocol']}，跳过配置生成")
        return None

    config['outbounds'].append({"protocol": "freedom", "tag": "direct"})
    config['outbounds'].append({"protocol": "blackhole", "tag": "blocked"})

    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        async with aiofiles.open(XRAY_CONFIG_FILE, "w", encoding="utf-8") as f:
            await f.write(json.dumps(config, indent=2, ensure_ascii=False))
        return XRAY_CONFIG_FILE
    except Exception as e:
        logger.error(f"写入 Xray 配置文件失败: {e}")
        return None

async def start_proxy_subprocess():
    """启动 Xray 子进程"""
    global xray_process
    if not os.path.isfile(XRAY_PATH) or not os.access(XRAY_PATH, os.X_OK):
        logger.error(f"Xray 可执行文件 '{XRAY_PATH}' 不存在或无执行权限")
        return False

    if xray_process and xray_process.poll() is None:
        logger.debug("Xray 进程已在运行")
        return True

    try:
        xray_process = await asyncio.create_subprocess_exec(
            XRAY_PATH, "-c", XRAY_CONFIG_FILE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        await asyncio.sleep(0.5)
        if await is_port_in_use(LOCAL_PROXY_PORT):
            logger.info(f"Xray 已监听端口 {LOCAL_PROXY_PORT}")
            return True
        logger.error(f"Xray 未监听端口 {LOCAL_PROXY_PORT}")
        stdout, stderr = await xray_process.communicate()
        if stdout: logger.debug(f"Xray stdout: {stdout.decode()}")
        if stderr: logger.error(f"Xray stderr: {stderr.decode()}")
        return False
    except Exception as e:
        logger.error(f"启动 Xray 失败: {e}")
        return False

async def stop_proxy_subprocess():
    """停止 Xray 子进程"""
    global xray_process
    if xray_process and xray_process.poll() is None:
        try:
            xray_process.terminate()
            await asyncio.wait_for(xray_process.wait(), timeout=2)
            logger.info("Xray 进程已终止")
        except asyncio.TimeoutError:
            xray_process.kill()
            await xray_process.wait()
            logger.warning("Xray 进程强制终止")
        xray_process = None

async def is_port_in_use(port):
    """检查端口是否被占用"""
    try:
        async with aiofiles.socket.socket(aiofiles.socket.AF_INET, aiofiles.socket.SOCK_STREAM) as s:
            await s.bind(("127.0.0.1", port))
            return False
    except OSError:
        return True

async def check_node(node_info):
    """测试单个节点连接性"""
    node_id = normalize_link(node_info['original_link'])
    current_time = time.time()

    if node_id in history_results:
        record = history_results[node_id]
        if record['status'] == 'Successful' and current_time - record['timestamp'] < 300:
            return NodeTestResult(node_info, 'Successful', record['delay_ms'])
        if record['status'] == 'Failed' and current_time - record['timestamp'] < HISTORY_EXPIRATION:
            return NodeTestResult(node_info, 'Failed', -1, record['error_message'])

    remarks = node_info.get('remarks', 'N/A')
    server = node_info.get('server')
    port = node_info.get('port')
    target_host = node_info.get('resolved_ip') or server

    if not all([server, port, target_host]):
        return NodeTestResult(node_info, "Failed", -1, "信息不完整或 DNS 解析失败")

    if node_info['protocol'] in ['hy2', 'hysteria2']:
        test_start_time = time.monotonic()
        try:
            async with aiofiles.socket.socket(aiofiles.socket.AF_INET, aiofiles.socket.SOCK_DGRAM) as sock:
                sock.settimeout(TEST_TIMEOUT_SECONDS)
                await sock.connect((target_host, port))
                await sock.sendto(b'ping', (target_host, port))
                try:
                    await sock.recvfrom(1024)
                except socket.timeout:
                    pass
                delay = (time.monotonic() - test_start_time) * 1000
                logger.info(f"节点 {remarks} ({target_host}:{port}) 成功 (UDP 探测), 延迟: {delay:.2f}ms")
                return NodeTestResult(node_info, "Successful", delay)
        except Exception as e:
            logger.warning(f"节点 {remarks} ({target_host}:{port}) 失败 (UDP 探测): {e}")
            return NodeTestResult(node_info, "Failed", -1, str(e))

    proxy_config_path = await generate_xray_config(node_info)
    if not proxy_config_path:
        return NodeTestResult(node_info, "Failed", -1, "无法生成 Xray 配置")

    await stop_proxy_subprocess()
    if not await start_proxy_subprocess():
        return NodeTestResult(node_info, "Failed", -1, "Xray 启动失败")

    proxy_url = f"socks5://127.0.0.1:{LOCAL_PROXY_PORT}"
    test_start_time = time.monotonic()
    try:
        async with httpx.AsyncClient(proxies={"all://": proxy_url}, timeout=TEST_TIMEOUT_SECONDS) as client:
            response = await client.get(TEST_PROXY_URL, follow_redirects=True)
            response.raise_for_status()
            if response.status_code == 204:
                delay = (time.monotonic() - test_start_time) * 1000
                logger.info(f"节点 {remarks} ({server}:{port}) 成功 (代理测试), 延迟: {delay:.2f}ms")
                return NodeTestResult(node_info, "Successful", delay)
            return NodeTestResult(node_info, "Failed", -1, f"HTTP 状态码: {response.status_code}")
    except Exception as e:
        logger.warning(f"节点 {remarks} ({server}:{port}) 失败 (代理测试): {e}")
        return NodeTestResult(node_info, "Failed", -1, str(e))

async def test_nodes_in_batches(nodes, batch_size=BATCH_SIZE):
    """分批测试节点"""
    semaphore = asyncio.Semaphore(get_optimal_concurrency())
    async def test_node_with_semaphore(node):
        async with semaphore:
            return await check_node(node)

    all_results = []
    total_batches = (len(nodes) + batch_size - 1) // batch_size
    for i in range(0, len(nodes), batch_size):
        batch_results = await asyncio.gather(*(test_node_with_semaphore(node) for node in nodes[i:i + batch_size]))
        all_results.extend(batch_results)
        logger.info(f"完成批次 {i // batch_size + 1}/{total_batches}，已处理 {len(all_results)}/{len(nodes)} 节点")
        await stop_proxy_subprocess()

    return all_results

def get_optimal_concurrency():
    """动态计算最佳并发任务数"""
    cpu_count = psutil.cpu_count()
    memory = psutil.virtual_memory()
    available_memory = memory.available / (1024 ** 2)
    base_concurrency = cpu_count * 10
    if available_memory < 1000:
        base_concurrency = cpu_count * 5
    return min(base_concurrency, 50)

def generate_summary(test_results):
    """生成测试结果摘要"""
    successful_nodes = [r for r in test_results if r.status == "Successful"]
    success_count = len(successful_nodes)
    total_count = len(test_results)
    success_rate = (success_count / total_count * 100) if total_count else 0
    avg_delay = sum(r.delay_ms for r in successful_nodes) / success_count if success_count else 0
    failure_reasons = {}
    for r in test_results:
        if r.status == "Failed":
            reason = r.error_message or "未知错误"
            failure_reasons[reason] = failure_reasons.get(reason, 0) + 1

    return {
        "总测试节点数": total_count,
        "成功节点数": success_count,
        "成功率": f"{success_rate:.2f}%",
        "平均延迟 (ms)": f"{avg_delay:.2f}",
        "失败原因统计": failure_reasons
    }

async def main():
    """主函数"""
    start_time = time.time()
    os.makedirs(DATA_DIR, exist_ok=True)
    await load_history()
    await load_dns_cache()

    all_links = []
    for url in SOURCE_URLS:
        logger.info(f"获取节点列表: {url}")
        content = await fetch_ss_txt(url)
        if content:
            all_links.extend(content.strip().split('\n'))

    if not all_links:
        logger.error("未获取到有效节点链接")
        async with aiofiles.open(SUCCESSFUL_NODES_OUTPUT_FILE, "w", encoding="utf-8") as f:
            await f.write("# 未找到有效节点\n")
        print("最终成功节点数: 0")
        return

    filtered_links = prefilter_links(all_links)
    if not filtered_links:
        logger.info("预过滤后无有效链接")
        async with aiofiles.open(SUCCESSFUL_NODES_OUTPUT_FILE, "w", encoding="utf-8") as f:
            await f.write("# 预过滤后无有效节点\n")
        print("最终成功节点数: 0")
        return

    parsed_nodes = [node_info for link in filtered_links if (node_info := parse_node_info(link))]
    hostnames_to_resolve = {node['server'] for node in parsed_nodes if node['is_domain']}
    resolved_ips = await bulk_dns_lookup(hostnames_to_resolve)

    nodes_for_testing = []
    for node in parsed_nodes:
        if node['is_domain']:
            if resolved_ip := resolved_ips.get(node['server']):
                node['resolved_ip'] = resolved_ip
                nodes_for_testing.append(node)
        else:
            nodes_for_testing.append(node)

    if not nodes_for_testing:
        logger.info("无有效节点可测试")
        async with aiofiles.open(SUCCESSFUL_NODES_OUTPUT_FILE, "w", encoding="utf-8") as f:
            await f.write("# 无有效节点\n")
        print("最终成功节点数: 0")
        return

    logger.info(f"开始测试 {len(nodes_for_testing)} 个节点")
    test_results = await test_nodes_in_batches(nodes_for_testing)
    await stop_proxy_subprocess()

    current_timestamp = int(time.time())
    for result in test_results:
        history_results[normalize_link(result.node_info['original_link'])] = {
            "status": result.status,
            "delay_ms": result.delay_ms,
            "error_message": result.error_message,
            "timestamp": current_timestamp
        }

    successful_nodes = sorted([r for r in test_results if r.status == "Successful"], key=lambda x: x.delay_ms)
    async with aiofiles.open(SUCCESSFUL_NODES_OUTPUT_FILE, "w", encoding="utf-8") as f:
        if successful_nodes:
            for result in successful_nodes:
                await f.write(f"{result.node_info['original_link']}\n")
        else:
            await f.write("# 无可用节点\n")

    await save_history()
    await save_dns_cache()

    summary = generate_summary(test_results)
    logger.info("\n--- 测试结果摘要 ---")
    for key, value in summary.items():
        if isinstance(value, dict):
            logger.info(f"{key}:")
            for sub_key, sub_value in value.items():
                logger.info(f"  - {sub_key}: {sub_value}")
        else:
            logger.info(f"{key}: {value}")

    print(f"最终成功节点数: {len(successful_nodes)}")
    logger.info(f"总耗时: {time.time() - start_time:.2f} 秒")

if __name__ == "__main__":
    asyncio.run(main())
