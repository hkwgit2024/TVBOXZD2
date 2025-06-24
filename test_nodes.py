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
   # "https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/data/nodes.txt",
   # "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/config_all_merged_nodes.txt",
   "https://raw.githubusercontent.com/qjlxg/hy2/refs/heads/main/configtg.txt",
  #  "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/all_nodes.txt",
  #  "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/ss.txt",
   # "https://snippet.host/oouyda/raw",
]

DATA_DIR = "data"  # 数据文件存放目录
HISTORY_FILE = os.path.join(DATA_DIR, "history_results.json")  # 历史测试结果文件路径
DNS_CACHE_FILE = os.path.join(DATA_DIR, "dns_cache.json")  # DNS 缓存文件路径
SUCCESSFUL_NODES_OUTPUT_FILE = os.path.join(DATA_DIR, "sub.txt")  # 成功节点输出文件路径
# 从环境变量获取测试超时时间，如果未设置，默认为 5 秒 (增加超时时间)
TEST_TIMEOUT_SECONDS = float(os.getenv("TEST_TIMEOUT", 5))
BATCH_SIZE = 100  # 每次处理的节点数量，用于分批处理以优化性能
DNS_CACHE_EXPIRATION = 2678400  # DNS 缓存有效期：31 天 (单位：秒)
HISTORY_EXPIRATION = 2678400  # 历史记录有效期：31 天 (单位：秒)

# --- 代理客户端配置 ---
# 请根据实际情况修改此处
# 例如：XRAY_PATH = "/path/to/your/xray" 或 "./xray.exe"
# 请确保该路径下的文件存在且有执行权限
# 优先从环境变量获取 XRAY_PATH
XRAY_PATH = os.getenv("XRAY_PATH", "./xray") # 你的 Xray 可执行文件路径
XRAY_CONFIG_FILE = os.path.join(DATA_DIR, "xray_config.json") # Xray 临时配置文件
LOCAL_PROXY_PORT = 10800 # Xray 监听的本地 SOCKS5 端口

# 用于测试代理是否成功的外部网址
# 推荐使用无内容、响应快的地址，如 Google 的 204 或 Cloudflare 的 Captive Portal
TEST_PROXY_URL = "http://www.gstatic.com/generate_204"
# TEST_PROXY_URL = "http://cp.cloudflare.com/" # 备用测试地址

# 动态计算最佳并发任务数
def get_optimal_concurrency():
    """
    根据系统的 CPU 核数和可用内存动态调整并发任务数。
    旨在平衡资源利用和避免过度消耗。
    """
    cpu_count = psutil.cpu_count()  # 获取 CPU 逻辑核数
    memory = psutil.virtual_memory()
    available_memory = memory.available / (1024 ** 2)  # 可用内存 (转换为 MB)
    base_concurrency = cpu_count * 20  # 降低基础并发数，因为真实代理测试更耗资源
    if available_memory < 1000:  # 如果可用内存低于 1GB
        base_concurrency = cpu_count * 10  # 再次降低并发数以避免内存不足
    return min(base_concurrency, 50)  # 将最大并发数限制在 50，防止任务过多，避免对系统造成过大压力

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
xray_process = None # Xray 子进程对象

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
    # 鉴于当前在中国，使用公共 DNS 可能不稳定。可以尝试用国内可用的 DNS 或直接通过系统 DNS (如果可行)
    resolver = aiodns.DNSResolver(nameservers=["223.5.5.5", "114.114.114.114", "8.8.8.8"])  # 添加阿里和电信 DNS
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
        tasks = []
        for hostname in to_resolve:
            # 尝试先解析 A 记录，如果失败，再尝试 AAAA 记录
            async def _resolve_single(h):
                try:
                    resp = await resolver.query(h, 'A')
                    return h, resp[0].host
                except Exception:
                    try:
                        resp = await resolver.query(h, 'AAAA')
                        return h, resp[0].host
                    except Exception as e:
                        return h, e
            tasks.append(_resolve_single(hostname))

        responses = await asyncio.gather(*tasks, return_exceptions=True)

        for hostname, result in zip(to_resolve, responses):
            if isinstance(result, str): # 解析成功，result是IP地址
                ip = result
                results[hostname] = ip
                dns_cache[hostname] = {"ip": ip, "timestamp": current_time}
                logger.debug(f"已将 {hostname} 解析到 IP: {ip}")
            else: # 解析失败，result是异常
                logger.debug(f"DNS 解析 {hostname} 失败: {result}")

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
        if protocol in ['vless', 'vmess', 'trojan']:
            # 这些协议通常格式为 <用户信息>@<主机>:<端口>?<查询参数>#<备注>
            if '@' in remaining_part:
                user_info_part, host_port_part = remaining_part.split('@', 1)
                node_info['user_info_part'] = user_info_part # 存储用户信息部分，用于生成 Xray 配置
            else:
                user_info_part = ""  # VMess, VLESS 有时也可能没有明确的 @ 分隔符，需要从 URI 直接解析
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

        elif protocol == 'ss':
            # SS 链接格式: ss://<base64(method:password@server:port)>#<remarks>
            # 或 ss://<method>:<password>@<server>:<port>#<remarks> (较少见)
            try:
                # 尝试解析 base64 编码的部分
                encoded_part = remaining_part.split('#')[0].split('/?')[0] # 移除备注和查询参数
                # SS 链接可能没有填充，需要手动填充
                if len(encoded_part) % 4 != 0:
                    encoded_part += '=' * (4 - len(encoded_part) % 4)

                decoded_str = base64.b64decode(encoded_part).decode('utf-8', 'ignore')
                # 假设 decoded_str 格式为 method:password@server:port
                parts = decoded_str.split('@', 1)
                auth_part = parts[0]
                host_port_part = parts[1]

                method, password = auth_part.split(':', 1)
                node_info['method'] = method
                node_info['password'] = password

                host_match = HOST_PORT_FULL_RE.match(host_port_part)
                if host_match:
                    node_info['server'] = host_match.group(1) or host_match.group(2) or host_match.group(3)
                    node_info['port'] = int(host_match.group(4))
                    if not (1 <= node_info['port'] <= 65535):
                        logger.debug(f"端口号无效 (范围 1-65535): {node_info['port']} 在 {link} 中")
                        return None
                else:
                    logger.debug(f"无法从 {link} 中的 {host_port_part} 解析 SS 主机:端口")
                    return None

            except Exception as e:
                logger.warning(f"解析 Shadowsocks 链接 '{link}' 失败: {e}")
                return None

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

# --- 新增的 Xray/sing-box 相关函数 ---
async def generate_xray_config(node_info):
    """
    根据节点信息生成一个临时的 Xray 配置文件。
    这是一个简化示例，你需要根据 Xray 的实际配置格式进行详细实现。
    """
    config = {
        "log": {
            "loglevel": "warning"
        },
        "inbounds": [
            {
                "port": LOCAL_PROXY_PORT,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {
                    "auth": "noauth",
                    "udp": True,
                    "ip": "127.0.0.1"
                }
            }
        ],
        "outbounds": [
            {
                "protocol": node_info['protocol'],
                "settings": {},
                "streamSettings": {
                    "network": "tcp", # 默认 tcp
                    "security": "none" # 默认无安全
                }
            }
        ],
        "routing": { # 确保路由规则正确
            "domainStrategy": "AsIs",
            "rules": [
                {"type": "field", "outboundTag": "blocked", "ip": ["geoip:private"]},
                {"type": "field", "outboundTag": "direct", "domain": ["geosite:cn"]},
                {"type": "field", "outboundTag": "direct", "ip": ["geoip:cn"]},
                {"type": "field", "outboundTag": "proxy"} # 确保通过代理出口
            ]
        }
    }

    outbound = config['outbounds'][0]
    stream_settings = outbound['streamSettings']

    # 通用设置：服务器地址和端口
    outbound['settings']['vnext'] = [{
        "address": node_info.get('resolved_ip') or node_info.get('server'), # 使用解析后的IP
        "port": node_info.get('port'),
        "users": [] # 根据协议添加用户
    }]

    # 根据协议类型填充详细配置
    if node_info['protocol'] == 'vless':
        user_id = node_info['user_info_part'].split('@')[0]
        outbound['settings']['vnext'][0]['users'].append({"id": user_id, "level": 8})
        
        # TLS 设置
        if node_info.get('security') == 'tls' or node_info.get('type') == 'tls': # type='tls' for some links
            stream_settings['security'] = 'tls'
            tls_settings = {"allowInsecure": True} # 测试时允许不安全证书
            if node_info.get('sni'):
                tls_settings['serverName'] = node_info['sni']
            elif node_info.get('host'):
                tls_settings['serverName'] = node_info['host']
            else:
                tls_settings['serverName'] = node_info['server'] # Fallback to server address
            stream_settings['tlsSettings'] = tls_settings

        # 传输协议设置 (ws, grpc 等)
        if node_info.get('type') == 'ws':
            stream_settings['network'] = 'ws'
            stream_settings['wsSettings'] = {"path": node_info.get('path', '/'), "headers": {"Host": node_info.get('host', node_info['server'])}}
        elif node_info.get('type') == 'grpc':
            stream_settings['network'] = 'grpc'
            stream_settings['grpcSettings'] = {"serviceName": node_info.get('serviceName', '')}

    elif node_info['protocol'] == 'vmess':
        # VMess 链接的 user_info_part 是直接的 JSON 字符串（经过 base64 解码和 URL 解码）
        try:
            decoded_vmess = json.loads(node_info['user_info_part'])

            outbound['settings']['vnext'][0]['users'].append({
                "id": decoded_vmess['id'],
                "alterId": decoded_vmess.get('aid', 0),
                "level": 8,
                "security": decoded_vmess.get('scy', 'auto') # e.g. "auto"
            })
            # 处理传输协议 (network)
            if decoded_vmess.get('net'):
                stream_settings['network'] = decoded_vmess['net']
            
            # TLS 设置
            if decoded_vmess.get('tls') == 'tls':
                stream_settings['security'] = 'tls'
                tls_settings = {"allowInsecure": True}
                if decoded_vmess.get('sni'):
                    tls_settings['serverName'] = decoded_vmess['sni']
                elif decoded_vmess.get('host'):
                    tls_settings['serverName'] = decoded_vmess['host']
                else:
                    tls_settings['serverName'] = node_info['server']
                stream_settings['tlsSettings'] = tls_settings

            # ws, http, h2, quic, grpc
            if decoded_vmess['net'] == 'ws':
                stream_settings['wsSettings'] = {"path": decoded_vmess.get('path', '/'), "headers": {"Host": decoded_vmess.get('host', node_info['server'])}}
            elif decoded_vmess['net'] == 'h2': # H2 for VMess implies TLS
                stream_settings['httpSettings'] = {"host": decoded_vmess.get('host', node_info['server'])}
            elif decoded_vmess['net'] == 'grpc':
                stream_settings['grpcSettings'] = {"serviceName": decoded_vmess.get('path', '')}
        except Exception as e:
            logger.warning(f"解析 VMess 用户信息失败: {e}")
            return None # 无法生成有效配置

    elif node_info['protocol'] == 'trojan':
        password = node_info['user_info_part'] # Trojan 的 user_info_part 是密码
        outbound['settings']['servers'] = [{
            "address": node_info.get('resolved_ip') or node_info.get('server'),
            "port": node_info.get('port'),
            "password": password
        }]
        stream_settings['security'] = 'tls' # Trojan 强制 TLS
        tls_settings = {"allowInsecure": True}
        if node_info.get('sni'):
            tls_settings['serverName'] = node_info['sni']
        elif node_info.get('host'):
            tls_settings['serverName'] = node_info['host']
        else:
            tls_settings['serverName'] = node_info['server']
        stream_settings['tlsSettings'] = tls_settings

        # ws, grpc 传输协议 (部分 Trojan 客户端支持)
        if node_info.get('type') == 'ws':
            stream_settings['network'] = 'ws'
            stream_settings['wsSettings'] = {"path": node_info.get('path', '/'), "headers": {"Host": node_info.get('host', node_info['server'])}}
        elif node_info.get('type') == 'grpc':
            stream_settings['network'] = 'grpc'
            stream_settings['grpcSettings'] = {"serviceName": node_info.get('serviceName', '')}

    elif node_info['protocol'] == 'ss':
        outbound['protocol'] = 'shadowsocks' # 修正协议名
        outbound['settings'] = {
            "servers": [
                {
                    "address": node_info.get('resolved_ip') or node_info.get('server'),
                    "port": node_info.get('port'),
                    "method": node_info.get('method'),
                    "password": node_info.get('password')
                }
            ]
        }
        # SS 通常没有 streamSettings，除非是 SS-OBFS/TLS，这里简化处理
        # 如果是 SS with TLS/obfs, 需要在 streamSettings 中添加相应配置
        if node_info.get('plugin') == 'obfs' and node_info.get('plugin_opts'):
            stream_settings['network'] = 'tcp'
            stream_settings['security'] = 'none' # Obfs is not TLS
            # Xray 的 obfs 配置方式复杂，这里只是一个示例。
            # 可能需要更复杂的逻辑来解析 plugin_opts。
            stream_settings['tcpSettings'] = {
                "header": {
                    "type": "http",
                    "request": {
                        "path": [node_info.get('path', '/')],
                        "headers": {
                            "Host": [node_info.get('host', node_info['server'])]
                        }
                    }
                }
            }
        elif node_info.get('plugin') == 'v2ray-plugin' and node_info.get('plugin_opts'):
            # v2ray-plugin 通常与 ws 和 tls 结合
            stream_settings['network'] = 'ws'
            if 'tls' in node_info.get('plugin_opts', ''):
                stream_settings['security'] = 'tls'
                tls_settings = {"allowInsecure": True}
                if node_info.get('sni'):
                    tls_settings['serverName'] = node_info['sni']
                elif node_info.get('host'):
                    tls_settings['serverName'] = node_info['host']
                else:
                    tls_settings['serverName'] = node_info['server']
                stream_settings['tlsSettings'] = tls_settings
            
            # 解析 v2ray-plugin 的 path 和 host
            plugin_opts_parsed = parse_qs(node_info.get('plugin_opts', ''))
            ws_path = plugin_opts_parsed.get('path', ['/'])[0]
            ws_host = plugin_opts_parsed.get('host', [node_info['server']])[0]
            stream_settings['wsSettings'] = {"path": ws_path, "headers": {"Host": ws_host}}
        else:
             del config['outbounds'][0]['streamSettings'] # 默认 SS 不用 streamSettings

    elif node_info['protocol'] in ['hy2', 'hysteria2']:
        # Xray 不支持 Hysteria2，返回 None
        logger.warning(f"Xray 无法直接测试 {node_info['protocol']} 协议，跳过实际代理测试。")
        return None 

    config['outbounds'].append({"protocol": "freedom", "tag": "direct"})
    config['outbounds'].append({"protocol": "blackhole", "tag": "blocked"})
    config['outbounds'][0]['tag'] = "proxy" # 为主代理出口添加tag


    # 将生成的配置写入文件
    try:
        os.makedirs(DATA_DIR, exist_ok=True) # 确保数据目录存在
        async with aiofiles.open(XRAY_CONFIG_FILE, "w", encoding="utf-8") as f:
            await f.write(json.dumps(config, indent=2, ensure_ascii=False))
        return XRAY_CONFIG_FILE
    except Exception as e:
        logger.error(f"写入 Xray 配置文件失败: {e}")
        return None

async def start_proxy_subprocess():
    """
    启动 Xray/sing-box 子进程，并等待其就绪。
    这是一个简化实现，实际可能需要更复杂的日志解析来判断何时就绪。
    """
    global xray_process
    if not os.path.exists(XRAY_PATH):
        logger.error(f"Xray 可执行文件 '{XRAY_PATH}' 不存在。请下载并配置正确路径。")
        return False

    if xray_process and xray_process.poll() is None: # 进程已在运行
        logger.debug("Xray 进程已在运行。")
        return True

    try:
        # 使用 -c 参数指定配置文件
        xray_process = await asyncio.create_subprocess_exec(
            XRAY_PATH, "-c", XRAY_CONFIG_FILE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        logger.info(f"启动 Xray 进程: {XRAY_PATH} -c {XRAY_CONFIG_FILE}")

        # 等待 Xray 启动并监听端口，这可能需要解析日志输出
        # 最简单的等待方式是短暂停顿，实际应更健壮
        await asyncio.sleep(0.5) # 给 Xray 0.5秒启动时间
        
        # 检查本地端口是否被监听 (更可靠的检查)
        for _ in range(5): # 尝试5次
            if await is_port_in_use(LOCAL_PROXY_PORT):
                logger.info(f"Xray 已成功启动并监听端口 {LOCAL_PROXY_PORT}。")
                return True
            await asyncio.sleep(0.1)
        
        logger.error(f"Xray 启动后未在 {LOCAL_PROXY_PORT} 监听，可能启动失败。")
        stdout, stderr = await xray_process.communicate()
        if stdout: logger.debug(f"Xray stdout: {stdout.decode()}")
        if stderr: logger.error(f"Xray stderr: {stderr.decode()}")
        return False

    except FileNotFoundError:
        logger.error(f"Xray 可执行文件 '{XRAY_PATH}' 未找到。请检查路径和权限。")
        return False
    except Exception as e:
        logger.error(f"启动 Xray 进程失败: {e}")
        return False

async def stop_proxy_subprocess():
    """
    停止 Xray/sing-box 子进程。
    """
    global xray_process
    if xray_process and xray_process.poll() is None:
        logger.info("终止 Xray 进程...")
        try:
            xray_process.terminate()
            await asyncio.wait_for(xray_process.wait(), timeout=2) # 等待进程结束
            logger.info("Xray 进程已终止。")
        except asyncio.TimeoutError:
            logger.warning("Xray 进程终止超时，强制杀死。")
            xray_process.kill()
            await xray_process.wait()
        xray_process = None
    elif xray_process:
        logger.debug("Xray 进程已停止或不存在。")
        xray_process = None

async def is_port_in_use(port):
    """检查一个端口是否正在被使用 (监听状态)。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", port))
        # Port is free, close and return False
        s.close()
        return False
    except OSError as e:
        if "Address already in use" in str(e):
            return True # Port is in use
        else:
            raise # Other OSError
    finally:
        s.close()


async def check_node(node_info):
    """
    测试单个节点的连接性，现在将通过外部代理客户端进行实际代理测试。
    """
    node_id = normalize_link(node_info['original_link'])
    current_time = time.time()

    # 检查历史缓存
    if node_id in history_results:
        record = history_results[node_id]
        if record['status'] == 'Successful' and current_time - record['timestamp'] < 300: # 5分钟内成功的才用缓存
            logger.debug(f"使用 {node_info['remarks']} 的缓存成功结果。")
            return NodeTestResult(node_info, 'Successful', record['delay_ms'])
        elif record['status'] == 'Failed' and current_time - record['timestamp'] < HISTORY_EXPIRATION: # 失败节点在有效期内不重复测试
            logger.debug(f"跳过最近失败的节点: {node_info['remarks']}")
            return NodeTestResult(node_info, 'Failed', -1, record['error_message'])

    remarks = node_info.get('remarks', 'N/A')
    server = node_info.get('server')
    port = node_info.get('port')
    target_host = node_info.get('resolved_ip') # 优先使用解析后的 IP

    if not all([server, port, target_host]):
        return NodeTestResult(node_info, "Failed", -1, "信息不完整或 DNS 解析失败")

    # 对于 Hysteria2，Xray 核心通常不直接支持，所以我们暂时保留简单的 TCP/UDP 探测
    if node_info['protocol'] in ['hy2', 'hysteria2']:
        logger.warning(f"协议 {node_info['protocol']} 不受 Xray 直接支持，执行基本 TCP/UDP 探测。")
        test_start_time = time.monotonic()
        error_message = ""
        sock = None
        wrapped_socket = None
        try:
            # Hysteria2 是 UDP 协议，这里做 UDP 端口可达性测试
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(TEST_TIMEOUT_SECONDS)
            sock.connect((target_host, port))
            # 尝试发送一个小的 UDP 包，不保证协议层面的握手成功
            sock.sendto(b'ping', (target_host, port))
            
            # 对于 UDP，recvfrom 会阻塞直到收到数据，或者超时
            # 如果 Hysteria2 服务器有响应，这里会收到
            try:
                sock.recvfrom(1024) # 尝试接收响应
            except socket.timeout:
                pass # 即使没有收到响应，只要能发送数据也认为端口可达

            test_end_time = time.monotonic()
            delay = (test_end_time - test_start_time) * 1000
            logger.info(f"测试节点 {remarks} ({target_host}:{port}) - 状态: 成功 (基本探测), 延迟: {delay:.2f}ms")
            return NodeTestResult(node_info, "Successful", delay)
        except socket.timeout:
            error_message = "连接超时 (基本探测)"
        except ConnectionRefusedError:
            error_message = "连接被拒绝 (基本探测)"
        except Exception as e:
            error_message = f"基本探测中发生意外错误: {e}"
        finally:
            if sock: sock.close()
        logger.warning(f"测试节点 {remarks} ({target_host}:{port}) - 状态: 失败 (基本探测), 错误: {error_message}")
        return NodeTestResult(node_info, "Failed", -1, error_message)


    # 对于支持 Xray 的协议，进行实际代理测试
    proxy_config_path = await generate_xray_config(node_info)
    if not proxy_config_path:
        return NodeTestResult(node_info, "Failed", -1, "无法生成 Xray 配置或协议不支持")

    # 在执行每个节点测试前，确保 Xray 进程启动并使用新的配置
    await stop_proxy_subprocess() # 停止旧的进程
    if not await start_proxy_subprocess(): # 启动新的进程
        return NodeTestResult(node_info, "Failed", -1, "Xray 客户端启动失败")

    # 执行通过 Xray 的代理测试
    proxy_url = f"socks5://127.0.0.1:{LOCAL_PROXY_PORT}"
    test_start_time = time.monotonic()
    try:
        async with httpx.AsyncClient(proxies={"http://": proxy_url, "https://": proxy_url}, timeout=TEST_TIMEOUT_SECONDS) as client:
            response = await client.get(TEST_PROXY_URL, follow_redirects=True)
            response.raise_for_status() # 检查 HTTP 状态码是否为 2xx
            
            # 对于 gstatic.com/generate_204，返回 204 是成功
            if response.status_code == 204:
                test_end_time = time.monotonic()
                delay = (test_end_time - test_start_time) * 1000
                logger.info(f"测试节点 {remarks} ({server}:{port}) - 状态: 成功 (代理测试), 延迟: {delay:.2f}ms")
                return NodeTestResult(node_info, "Successful", delay)
            else:
                error_message = f"代理测试 HTTP 状态码非预期: {response.status_code}"

    except httpx.RequestError as e:
        error_message = f"通过代理请求失败: {e}"
    except Exception as e:
        error_message = f"代理测试中发生意外错误: {e}"
    finally:
        pass # Xray 进程在 test_nodes_in_batches 中统一停止

    logger.warning(f"测试节点 {remarks} ({server}:{port}) - 状态: 失败 (代理测试), 错误: {error_message}")
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
    total_batches = (len(tasks) + batch_size - 1) // batch_size
    for i in range(0, len(tasks), batch_size):
        batch_tasks = tasks[i:i + batch_size]
        batch_results = await asyncio.gather(*batch_tasks)  # 并发执行当前批次的任务
        all_results.extend(batch_results)
        logger.info(f"已完成批次 {i // batch_size + 1}/{total_batches}。目前已处理 {len(all_results)}/{len(nodes)} 个节点。")
        # 每次批次处理完，停止Xray进程，确保配置被刷新
        await stop_proxy_subprocess()


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

    # 停止所有 Xray 进程，确保清理
    await stop_proxy_subprocess()


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
