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
import socket # 导入标准的 socket 模块
import ssl
import subprocess
from urllib.parse import urlparse, unquote, parse_qs
from concurrent.futures import ThreadPoolExecutor
import base64
from functools import partial # 用于 partial 函数

# --- 配置 ---
SOURCE_URLS = [
    "https://raw.githubusercontent.com/qjlxg/hy2/refs/heads/main/configtg.txt",
]

DATA_DIR = "data"
HISTORY_FILE = os.path.join(DATA_DIR, "history_results.json")
DNS_CACHE_FILE = os.path.join(DATA_DIR, "dns_cache.json")
SUCCESSFUL_NODES_OUTPUT_FILE = os.path.join(DATA_DIR, "sub.txt")
SUCCESS_COUNT_FILE = os.path.join(DATA_DIR, "success_count.txt")  # 新增：保存成功节点数

TEST_TIMEOUT_SECONDS = float(os.getenv("TEST_TIMEOUT", 15))
BATCH_SIZE = 100
DNS_CACHE_EXPIRATION = 2678400  # 31 天
HISTORY_EXPIRATION = 2678400  # 31 天

XRAY_PATH = os.getenv("XRAY_PATH", "./xray")
XRAY_CONFIG_FILE = os.path.join(DATA_DIR, "xray_config.json")
LOCAL_PROXY_PORT = 10800
TEST_PROXY_URL = "http://www.gstatic.com/generate_204"

# --- 日志配置 ---
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()
logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.INFO),
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler(os.path.join(DATA_DIR, "test_nodes.log")),  # 保存日志到文件
                        logging.StreamHandler()
                    ])
logger = logging.getLogger(__name__)

# --- 正则表达式 ---
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
xray_process = None # 定义为全局变量

# --- 辅助函数 ---
def normalize_link(link):
    """规范化节点链接，用于历史记录和缓存的键"""
    try:
        parsed = urlparse(link)
        base_link = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        return base_link.rstrip('/')
    except Exception as e:
        logger.warning(f"规范化链接 '{link}' 失败: {e}")
        return link

async def bulk_dns_lookup(hostnames):
    """批量进行 DNS 查询，并利用缓存"""
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
            """解析单个主机名，尝试 A 记录，然后 AAAA 记录"""
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
    """加载历史测试结果"""
    global history_results
    os.makedirs(DATA_DIR, exist_ok=True)
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
    """保存历史测试结果，并清理过期记录"""
    current_time = int(time.time())
    cleaned_history = {k: v for k, v in history_results.items() if current_time - v.get("timestamp", 0) < HISTORY_EXPIRATION}
    os.makedirs(DATA_DIR, exist_ok=True)
    async with aiofiles.open(HISTORY_FILE, "w", encoding="utf-8") as f:
        await f.write(json.dumps(cleaned_history, indent=2, ensure_ascii=False))
    logger.info(f"历史结果已保存: {len(cleaned_history)} 条记录")

async def load_dns_cache():
    """加载 DNS 缓存"""
    global dns_cache
    os.makedirs(DATA_DIR, exist_ok=True)
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
    """保存 DNS 缓存，并清理过期记录"""
    current_time = int(time.time())
    cleaned_cache = {k: v for k, v in dns_cache.items() if current_time - v.get("timestamp", 0) < DNS_CACHE_EXPIRATION}
    os.makedirs(DATA_DIR, exist_ok=True)
    async with aiofiles.open(DNS_CACHE_FILE, "w", encoding="utf-8") as f:
        await f.write(json.dumps(cleaned_cache, indent=2, ensure_ascii=False))
    logger.info(f"DNS 缓存已保存: {len(cleaned_cache)} 条记录")

async def fetch_ss_txt(url):
    """从给定 URL 获取节点列表内容"""
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=15) as client:
            response = await client.get(url)
            response.raise_for_status()
            return response.text
    except Exception as e:
        logger.error(f"从 {url} 获取节点列表失败: {e}")
        return None

def prefilter_links(links):
    """预过滤链接，只保留符合协议和基本格式的链接"""
    valid_links = [link.strip() for link in links if link.strip() and PROTOCOL_RE.match(link) and HOST_PORT_RE.search(link)]
    logger.info(f"预过滤: 原始 {len(links)} 条，保留 {len(valid_links)} 条")
    return valid_links

def parse_node_info(link):
    """解析节点链接，提取节点信息"""
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
            # 确保 Base64 字符串有正确的填充
            decoded_str = base64.b64decode(encoded_part + '=' * (-len(encoded_part) % 4)).decode('utf-8', 'ignore')
            node_info['user_info_part'] = decoded_str
            vmess_data = json.loads(decoded_str)
            node_info['server'] = vmess_data['add']
            node_info['port'] = int(vmess_data['port'])
            node_info.update(vmess_data)

        elif protocol == 'ss':
            try:
                encoded_part = remaining_part.split('#')[0].split('/?')[0]
                # 修复 Base64 填充
                encoded_part += '=' * (-len(encoded_part) % 4)
                decoded_str = base64.b64decode(encoded_part, validate=True).decode('utf-8', 'ignore')
                parts = decoded_str.split('@', 1)
                if len(parts) != 2:
                    logger.debug(f"无效 Shadowsocks 格式: {link}")
                    return None
                auth_part, host_port_part = parts
                method_password = auth_part.split(':', 1)
                if len(method_password) != 2:
                    logger.debug(f"无效 Shadowsocks 认证格式: {link}")
                    return None
                method, password = method_password
                node_info['method'] = method
                node_info['password'] = password
                host_match = HOST_PORT_FULL_RE.match(host_port_part)
                if host_match:
                    node_info['server'] = host_match.group(1) or host_match.group(2) or host_match.group(3)
                    node_info['port'] = int(host_match.group(4))
                    if not (1 <= node_info['port'] <= 65535):
                        return None
                else:
                    logger.debug(f"无效 Shadowsocks 主机端口格式: {link}")
                    return None
            except Exception as e:
                logger.debug(f"解析 Shadowsocks 链接 '{link}' 失败: {e}")
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
    """根据节点信息生成 Xray 配置文件"""
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

    # 添加 Geo 数据路径
    if os.getenv("XRAY_GEOIP_PATH") and os.path.exists(os.getenv("XRAY_GEOIP_PATH")):
        config["routing"]["geoip"] = {"path": os.getenv("XRAY_GEOIP_PATH")}
    else:
        logger.warning("GeoIP 数据文件未找到，可能影响路由规则")
    if os.getenv("XRAY_GEOSITE_PATH") and os.path.exists(os.getenv("XRAY_GEOSITE_PATH")):
        config["routing"]["geosite"] = {"path": os.getenv("XRAY_GEOSITE_PATH")}
    else:
        logger.warning("GeoSite 数据文件未找到，可能影响路由规则")

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
            # 如果没有插件，则移除 streamSettings，Xray Shadowsocks 通常不需要
            del config['outbounds'][0]['streamSettings']

    elif node_info['protocol'] in ['hy2', 'hysteria2']:
        logger.warning(f"Xray 不支持 {node_info['protocol']}，跳过配置生成")
        return None # Xray 不支持，返回 None

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
    # 修复：如果 GeoIP 或 GeoSite 数据文件缺失，立即返回 False
    if not (os.getenv("XRAY_GEOIP_PATH") and os.path.exists(os.getenv("XRAY_GEOIP_PATH")) and
            os.getenv("XRAY_GEOSITE_PATH") and os.path.exists(os.getenv("XRAY_GEOSITE_PATH"))):
        logger.error("GeoIP 或 GeoSite 数据文件缺失。请确保已设置 XRAY_GEOIP_PATH 和 XRAY_GEOSITE_PATH 环境变量，并且文件存在。")
        return False

    # 检查 Xray 进程是否已在运行 (使用 returncode 检查)
    if xray_process is not None and xray_process.returncode is None: # 修复：使用 returncode 代替 poll()
        logger.debug("Xray 进程已在运行")
        return True

    try:
        xray_process = await asyncio.create_subprocess_exec(
            XRAY_PATH, "-c", XRAY_CONFIG_FILE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        await asyncio.sleep(0.5) # 稍微等待 Xray 启动
        # is_port_in_use 返回 True 表示端口被占用，也就是 Xray 成功监听了。
        # 所以这里 if not await is_port_in_use(...) 表示 Xray 未能成功监听端口。
        if not await is_port_in_use(LOCAL_PROXY_PORT): 
            logger.error(f"Xray 未监听端口 {LOCAL_PROXY_PORT} (端口可能被占用或Xray启动失败)")
            # 尝试获取 Xray 的输出，帮助调试
            stdout, stderr = await xray_process.communicate()
            if stdout: logger.debug(f"Xray stdout: {stdout.decode()}")
            if stderr: logger.error(f"Xray stderr: {stderr.decode()}")
            return False
        logger.info(f"Xray 已监听端口 {LOCAL_PROXY_PORT}")
        return True
    except Exception as e:
        logger.error(f"启动 Xray 失败: {e}")
        return False

async def stop_proxy_subprocess():
    """停止 Xray 子进程"""
    global xray_process
    # 检查 xray_process 是否存在且仍在运行 (使用 returncode 检查)
    if xray_process is not None and xray_process.returncode is None: # 修复：使用 returncode 代替 poll()
        logger.debug("尝试终止 Xray 进程...")
        try:
            xray_process.terminate()
            await asyncio.wait_for(xray_process.wait(), timeout=2)
            logger.info("Xray 进程已终止")
        except asyncio.TimeoutError:
            xray_process.kill()
            await xray_process.wait()
            logger.warning("Xray 进程强制终止")
        except Exception as e:
            logger.error(f"终止 Xray 进程失败: {e}")
        finally:
            xray_process = None
    elif xray_process is not None:
        logger.debug("Xray 进程已停止或未启动。")
        xray_process = None


async def _check_port_sync(port):
    """
    同步检查端口是否在使用。
    此函数将在单独的线程中运行。
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            # 设置 SO_REUSEADDR 允许重新绑定，避免 TIME_WAIT 状态问题
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", port))
            # 如果绑定成功，说明此端口当前未被其他进程占用
            return False # 端口未被占用
        except OSError as e:
            # 如果绑定失败（如 Address already in use），说明端口已被占用
            logger.debug(f"端口 {port} 占用检测失败: {e}")
            return True # 端口已被占用

async def is_port_in_use(port):
    """
    异步检查端口是否在使用。
    通过将同步的 socket.bind 操作放入线程池来避免阻塞 asyncio 事件循环。
    """
    loop = asyncio.get_running_loop()
    # 使用 partial 来传递参数给 _check_port_sync
    return await loop.run_in_executor(None, partial(_check_port_sync, port))


async def check_node(node_info):
    """测试单个节点的可达性"""
    node_id = normalize_link(node_info['original_link'])
    current_time = time.time()

    # 优先使用历史结果 (5分钟内成功的节点直接返回成功，失败的节点在过期时间内跳过)
    if node_id in history_results:
        record = history_results[node_id]
        if record['status'] == 'Successful' and current_time - record['timestamp'] < 300: # 5分钟内有效
            logger.info(f"节点 {node_info.get('remarks', 'N/A')} (来自缓存) 成功, 延迟: {record['delay_ms']:.2f}ms")
            return NodeTestResult(node_info, 'Successful', record['delay_ms'])
        # 失败的节点在 HISTORY_EXPIRATION 内，则跳过再次测试
        if record['status'] == 'Failed' and current_time - record['timestamp'] < HISTORY_EXPIRATION:
            logger.debug(f"节点 {node_info.get('remarks', 'N/A')} (来自缓存) 失败, 错误: {record['error_message']}")
            return NodeTestResult(node_info, 'Failed', -1, record['error_message'])


    remarks = node_info.get('remarks', 'N/A')
    server = node_info.get('server')
    port = node_info.get('port')
    target_host = node_info.get('resolved_ip') or server

    if not all([server, port, target_host]):
        logger.warning(f"节点 {remarks} 信息不完整或 DNS 解析失败")
        return NodeTestResult(node_info, "Failed", -1, "信息不完整或 DNS 解析失败")

    # 特殊处理 Hysteria2 节点（UDP 探测）
    if node_info['protocol'] in ['hy2', 'hysteria2']:
        test_start_time = time.monotonic()
        try:
            # 这里的 socket 操作是同步的，但通常不会阻塞太久，如果需要严格异步，同样可以放 executor
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(TEST_TIMEOUT_SECONDS)
            await asyncio.get_running_loop().sock_connect(sock, (target_host, port)) # 异步连接
            sock.sendto(b'ping', (target_host, port))
            try:
                await asyncio.get_running_loop().sock_recv(sock, 1024) # 异步接收
            except socket.timeout:
                pass # 超时也算成功（UDP探测通常不强制接收回复）
            delay = (time.monotonic() - test_start_time) * 1000
            logger.info(f"节点 {remarks} ({target_host}:{port}) 成功 (UDP 探测), 延迟: {delay:.2f}ms")
            return NodeTestResult(node_info, "Successful", delay)
        except Exception as e:
            logger.warning(f"节点 {remarks} ({target_host}:{port}) 失败 (UDP 探测): {e}")
            return NodeTestResult(node_info, "Failed", -1, str(e))
        finally:
            sock.close() # 确保关闭套接字

    # 对于 Xray 支持的协议，生成配置并启动 Xray 进行代理测试
    proxy_config_path = await generate_xray_config(node_info)
    if not proxy_config_path:
        logger.warning(f"节点 {remarks} 无法生成 Xray 配置，跳过测试")
        return NodeTestResult(node_info, "Failed", -1, "无法生成 Xray 配置")

    # 停止旧的 Xray 进程，确保每次测试都是干净的环境
    await stop_proxy_subprocess()
    # 启动新的 Xray 进程
    if not await start_proxy_subprocess():
        logger.warning(f"节点 {remarks} Xray 启动失败，跳过测试")
        return NodeTestResult(node_info, "Failed", -1, "Xray 启动失败")

    proxy_url = f"socks5://127.0.0.1:{LOCAL_PROXY_PORT}"
    test_start_time = time.monotonic()
    try:
        async with httpx.AsyncClient(proxies={"all://": proxy_url}, timeout=TEST_TIMEOUT_SECONDS) as client:
            response = await client.get(TEST_PROXY_URL, follow_redirects=True)
            response.raise_for_status() # 检查 HTTP 状态码
            if response.status_code == 204:
                delay = (time.monotonic() - test_start_time) * 1000
                logger.info(f"节点 {remarks} ({server}:{port}) 成功 (代理测试), 延迟: {delay:.2f}ms")
                return NodeTestResult(node_info, "Successful", delay)
            else:
                logger.warning(f"节点 {remarks} ({server}:{port}) 失败 (HTTP 状态码: {response.status_code})")
                return NodeTestResult(node_info, "Failed", -1, f"HTTP 状态码: {response.status_code}")
    except httpx.TimeoutException as e:
        logger.warning(f"节点 {remarks} ({server}:{port}) 测试超时: {e}")
        return NodeTestResult(node_info, "Failed", -1, f"连接超时: {e}")
    except httpx.ConnectError as e:
        logger.warning(f"节点 {remarks} ({server}:{port}) 连接失败: {e}")
        return NodeTestResult(node_info, "Failed", -1, f"连接错误: {e}")
    except Exception as e:
        logger.warning(f"节点 {remarks} ({server}:{port}) 失败 (代理测试): {e}")
        return NodeTestResult(node_info, "Failed", -1, str(e))
    finally:
        # 无论测试结果如何，都尝试停止 Xray 进程，确保不影响下一个节点
        await stop_proxy_subprocess()


async def test_nodes_in_batches(nodes, batch_size=BATCH_SIZE):
    """分批次并发测试节点"""
    semaphore = asyncio.Semaphore(get_optimal_concurrency())
    async def test_node_with_semaphore(node):
        async with semaphore:
            return await check_node(node)

    all_results = []
    total_batches = (len(nodes) + batch_size - 1) // batch_size
    for i in range(0, len(nodes), batch_size):
        logger.info(f"开始测试批次 {i // batch_size + 1}/{total_batches}...")
        batch_results = await asyncio.gather(*(test_node_with_semaphore(node) for node in nodes[i:i + batch_size]))
        all_results.extend(batch_results)
        logger.info(f"批次 {i // batch_size + 1}/{total_batches} 完成，已处理 {len(all_results)}/{len(nodes)} 节点")
        # 批次之间停止 Xray 进程，确保每次测试都是独立干净的环境
        await stop_proxy_subprocess()


    return all_results

def get_optimal_concurrency():
    """根据 CPU 和内存计算最佳并发数"""
    cpu_count = psutil.cpu_count(logical=False) or 1 # 获取物理 CPU 核心数
    memory = psutil.virtual_memory()
    available_memory = memory.available / (1024 ** 2) # MB
    
    # 基础并发数，考虑 CPU 核心数
    base_concurrency = cpu_count * 5 
    
    # 根据可用内存调整并发数，避免内存溢出
    if available_memory < 500: # 小于 500MB 可用内存
        base_concurrency = max(1, cpu_count) # 至少 1
    elif available_memory < 1000: # 小于 1GB 可用内存
        base_concurrency = cpu_count * 2
    elif available_memory < 2000: # 小于 2GB 可用内存
        base_concurrency = cpu_count * 3
    else: # 大于 2GB 可用内存
        base_concurrency = cpu_count * 4 # 保持在一个合理的范围内
        
    # 限制最大并发数，避免对系统造成过大压力
    return min(base_concurrency, 30) # 建议最大并发数不超过30-50，具体取决于服务器性能

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
    """主函数，协调节点获取、测试和结果保存"""
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
        async with aiofiles.open(SUCCESS_COUNT_FILE, "w", encoding="utf-8") as f:
            await f.write("0")
        print("最终成功节点数: 0")
        return

    filtered_links = prefilter_links(all_links)
    if not filtered_links:
        logger.info("预过滤后无有效链接")
        async with aiofiles.open(SUCCESSFUL_NODES_OUTPUT_FILE, "w", encoding="utf-8") as f:
            await f.write("# 预过滤后无有效节点\n")
        async with aiofiles.open(SUCCESS_COUNT_FILE, "w", encoding="utf-8") as f:
            await f.write("0")
        print("最终成功节点数: 0")
        return

    parsed_nodes = []
    for link in filtered_links:
        node_info = parse_node_info(link)
        if node_info:
            parsed_nodes.append(node_info)
        else:
            logger.debug(f"跳过无效节点: {link}")

    hostnames_to_resolve = {node['server'] for node in parsed_nodes if node['is_domain']}
    resolved_ips = await bulk_dns_lookup(hostnames_to_resolve)

    nodes_for_testing = []
    for node in parsed_nodes:
        if node['is_domain']:
            if resolved_ip := resolved_ips.get(node['server']):
                node['resolved_ip'] = resolved_ip
                nodes_for_testing.append(node)
            else:
                logger.warning(f"节点 {node.get('remarks', node['server'])} DNS 解析失败，跳过测试")
        else:
            nodes_for_testing.append(node)

    if not nodes_for_testing:
        logger.info("无有效节点可测试")
        async with aiofiles.open(SUCCESSFUL_NODES_OUTPUT_FILE, "w", encoding="utf-8") as f:
            await f.write("# 无有效节点\n")
        async with aiofiles.open(SUCCESS_COUNT_FILE, "w", encoding="utf-8") as f:
            await f.write("0")
        print("最终成功节点数: 0")
        return

    logger.info(f"开始测试 {len(nodes_for_testing)} 个节点")
    test_results = await test_nodes_in_batches(nodes_for_testing)
    await stop_proxy_subprocess() # 确保所有测试完成后停止Xray进程

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

    async with aiofiles.open(SUCCESS_COUNT_FILE, "w", encoding="utf-8") as f:
        await f.write(str(len(successful_nodes)))

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
    try:
        asyncio.run(main())
    except Exception as e:
        logger.error(f"脚本执行失败: {e}", exc_info=True) # 打印完整的异常信息
        async def write_error_files():
            os.makedirs(DATA_DIR, exist_ok=True)
            async with aiofiles.open(SUCCESSFUL_NODES_OUTPUT_FILE, "w", encoding="utf-8") as f:
                await f.write("# 脚本执行失败\n")
            async with aiofiles.open(SUCCESS_COUNT_FILE, "w", encoding="utf-8") as f:
                await f.write("0")
        asyncio.run(write_error_files()) # 确保在异常发生时也能写入文件
        print("最终成功节点数: 0")
        # 不需要 re-raise e，因为我们已经处理了错误并记录了
