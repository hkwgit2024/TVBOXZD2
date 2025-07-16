import httpx
import asyncio
import re
import os
import csv
import hashlib
from urllib.parse import urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
import yaml
import base64
import json
import ipaddress
import dns.resolver
import platform
import random
import datetime
import aiofiles
import logging
from playwright.async_api import async_playwright, Playwright

# --- 配置常量 ---
OUTPUT_DIR = "data"  # 输出目录
CACHE_DIR = "cache"  # 缓存目录
CACHE_EXPIRATION_HOURS = 24  # 缓存过期时间（小时）
MAX_CONCURRENT_REQUESTS = 3  # 降低并发数，避免搜索引擎反爬，适配 Playwright 资源消耗
REQUEST_TIMEOUT_SECONDS = 30  # 单次请求超时时间
RETRY_ATTEMPTS = 1  # 失败重试1次

# 最终输出的统一节点文件
FINAL_NODE_OUTPUT_FILE = os.path.join(OUTPUT_DIR, "jy.txt")

# 配置日志
logger = logging.getLogger('proxy_scraper')
logger.setLevel(logging.INFO)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
file_handler = logging.FileHandler('proxy_scraper.log', encoding='utf-8')
file_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
file_handler.setFormatter(formatter)
logger.addHandler(console_handler)
logger.addHandler(file_handler)

# 用户代理列表
USER_AGENTS = {
    "desktop": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    ],
    "mobile": [
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Android 14; Mobile; rv:126.0) Gecko/126.0 Firefox/126.0",
        "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
    ],
    "tablet": [
        "Mozilla/5.0 (iPad; CPU OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 12; SM-T510) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    ],
    "harmonyos": [
        "Mozilla/5.0 (Linux; U; Android 10; zh-cn; HarmonyOS) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.105 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; U; Android 10; zh-cn; PCT-AL10) AppleWebKit/537.36 (KHTML like Gecko) Chrome/83.0.4103.106 Mobile Safari/537.36",
    ]
}

# 节点协议正则表达式 (增强和更新)
NODE_REGEXES = {
    "hysteria2": r"hysteria2:\/\/(?P<id>[a-zA-Z0-9\-_.~%]+:[a-zA-Z0-9\-_.~%]+@)?(?P<host>[a-zA-Z0-9\-\.]+)(?::(?P<port>\d+))?\/?\?.*",
    "vmess": r"vmess:\/\/(?P<data>[a-zA-Z0-9+\/=]+)",
    "trojan": r"trojan:\/\/(?P<password>[a-zA-Z0-9\-_.~%]+)@(?P<host>[a-zA-Z0-9\-\.]+):(?P<port>\d+)(?:\/\?.*)?",
    "ss": r"ss:\/\/(?P<method_password>[a-zA-Z0-9+\/=]+)@(?P<host>[a-zA-Z0-9\-\.]+):(?P<port>\d+)(?:#(?P<name>.*))?",
    "ssr": r"ssr:\/\/(?P<data>[a-zA-Z0-9+\/=]+)",
    "vless": r"vless:\/\/(?P<uuid>[a-zA-Z0-9\-]+)@(?P<host>[a-zA-Z0-9\-\.]+):(?P<port>\d+)\?(?:.*&)?type=(?P<type>[a-zA-Z0-9]+)(?:&security=(?P<security>[a-zA-Z0-9]+))?.*",
    "tuic": r"tuic:\/\/(?P<uuid>[a-zA-Z0-9\-]+):(?P<password>[a-zA-Z0-9\-_.~%]+)@(?P<host>[a-zA-Z0-9\-\.]+):(?P<port>\d+)\?(?:.*&)?(?:udp_relay=(?P<udp_relay>[^&]*))?", # TUIC 协议
    "wg": r"wg:\/\/(?P<data>[a-zA-Z0-9+\/=]+)", # WireGuard (通常是Base64编码的配置)
}

# 搜索引擎配置
SEARCH_ENGINES = [
    {"name": "Google", "base_url": "https://www.google.com/search?q=", "param": "&start="},
    {"name": "Bing", "base_url": "https://www.bing.com/search?q=", "param": "&first="},
]
SEARCH_PROTOCOLS = list(NODE_REGEXES.keys()) # 使用所有定义的协议作为搜索关键词
SEARCH_PAGES_PER_PROTOCOL = 2 # 每个协议搜索的页数（每页约10个结果），根据需求调整
RESULTS_PER_PAGE = 10 # 搜索引擎每页结果数

# --- 缓存处理函数 (保持不变) ---
def generate_cache_key(url):
    """生成 URL 的缓存键"""
    return hashlib.md5(url.encode('utf-8')).hexdigest() + ".cache"

def get_cache_path(url):
    """获取缓存文件路径"""
    return os.path.join(CACHE_DIR, generate_cache_key(url))

async def read_cache(url):
    """读取缓存内容"""
    cache_path = get_cache_path(url)
    if not os.path.exists(cache_path):
        logger.debug(f"缓存文件不存在: {cache_path}")
        return None
    
    mod_time = datetime.datetime.fromtimestamp(os.path.getmtime(cache_path))
    if datetime.datetime.now() - mod_time > datetime.timedelta(hours=CACHE_EXPIRATION_HOURS):
        logger.info(f"缓存 '{url}' 已过期。")
        try:
            os.remove(cache_path)
        except Exception as e:
            logger.warning(f"删除过期缓存 '{cache_path}' 失败: {e}")
        return None
    
    try:
        async with asyncio.Lock():
            async with aiofiles.open(cache_path, 'r', encoding='utf-8') as f:
                logger.info(f"从缓存读取 '{url}'。")
                return await f.read()
    except Exception as e:
        logger.error(f"读取缓存 '{url}' 失败: {e}")
        return None

async def write_cache(url, content):
    """写入缓存内容"""
    cache_path = get_cache_path(url)
    os.makedirs(CACHE_DIR, exist_ok=True)
    try:
        async with asyncio.Lock():
            async with aiofiles.open(cache_path, 'w', encoding='utf-8') as f:
                await f.write(content)
        logger.info(f"内容已写入缓存 '{url}'。")
    except Exception as e:
        logger.error(f"写入缓存 '{url}' 失败: {e}")

# --- 网络请求相关函数 (保持不变) ---
def get_random_headers():
    """随机选择用户代理"""
    device_type = random.choice(list(USER_AGENTS.keys()))
    return {"User-Agent": random.choice(USER_AGENTS[device_type])}

async def fetch_url(url, http_client, playwright_instance: Playwright):
    """尝试获取 URL 内容，先用 httpx，若失败则用 Playwright，支持重试"""
    # 尝试将 URL 规范化，确保有 scheme
    parsed_url = urlparse(url)
    if not parsed_url.scheme:
        # 优先尝试 HTTPS，因为现在很多网站都强制 HTTPS
        full_url_https = f"https://{url}"
        full_url_http = f"http://{url}"
    else:
        full_url_https = url
        full_url_http = url.replace("https://", "http://", 1) # 尝试降级到 HTTP

    cached_content = await read_cache(url)
    if cached_content:
        return cached_content
        
    content = None
    
    # 尝试 httpx 获取 HTTPS
    for attempt in range(RETRY_ATTEMPTS):
        try:
            async with asyncio.timeout(REQUEST_TIMEOUT_SECONDS):
                headers = get_random_headers()
                logger.info(f"尝试用 httpx 从 {full_url_https} 获取内容 (第 {attempt + 1} 次)...")
                response = await http_client.get(full_url_https, timeout=REQUEST_TIMEOUT_SECONDS, headers=headers)
                response.raise_for_status()
                content = response.text
                logger.info(f"httpx 成功从 {full_url_https} 获取内容。")
                break
        except asyncio.TimeoutError:
            logger.warning(f"httpx 从 {full_url_https} 获取超时 (第 {attempt + 1} 次)。")
        except httpx.HTTPStatusError as e:
            logger.warning(f"httpx 从 {full_url_https} 获取失败 (HTTP 错误: {e.response.status_code}, 第 {attempt + 1} 次)。")
        except httpx.RequestError as e:
            logger.warning(f"httpx 从 {full_url_https} 获取失败 (请求错误: {e}, 第 {attempt + 1} 次)。")
        except Exception as e:
            logger.error(f"httpx 从 {full_url_https} 获取时发生未知错误: {e} (第 {attempt + 1} 次)。", exc_info=True)

    # 如果 HTTPS 失败，尝试 httpx 获取 HTTP
    if content is None:
        for attempt in range(RETRY_ATTEMPTS):
            try:
                async with asyncio.timeout(REQUEST_TIMEOUT_SECONDS):
                    headers = get_random_headers()
                    logger.info(f"尝试用 httpx 从 {full_url_http} 获取内容 (第 {attempt + 1} 次)...")
                    response = await http_client.get(full_url_http, timeout=REQUEST_TIMEOUT_SECONDS, headers=headers)
                    response.raise_for_status()
                    content = response.text
                    logger.info(f"httpx 成功从 {full_url_http} 获取内容。")
                    break
            except asyncio.TimeoutError:
                logger.warning(f"httpx 从 {full_url_http} 获取超时 (第 {attempt + 1} 次)。")
            except httpx.HTTPStatusError as e:
                logger.warning(f"httpx 从 {full_url_http} 获取失败 (HTTP 错误: {e.response.status_code}, 第 {attempt + 1} 次)。")
            except httpx.RequestError as e:
                logger.warning(f"httpx 从 {full_url_http} 获取失败 (请求错误: {e}, 第 {attempt + 1} 次)。")
            except Exception as e:
                logger.error(f"httpx 从 {full_url_http} 获取时发生未知错误: {e} (第 {attempt + 1} 次)。", exc_info=True)
            
    # 如果 httpx 失败，尝试 Playwright
    if content is None:
        for attempt in range(RETRY_ATTEMPTS):
            logger.info(f"httpx 未能获取 {url} 内容，尝试使用 Playwright (第 {attempt + 1} 次)...")
            browser = None
            try:
                # Playwright 尝试 HTTPS
                async with asyncio.timeout(REQUEST_TIMEOUT_SECONDS * 2):  # Playwright 可能需要更长时间
                    browser = await playwright_instance.chromium.launch()
                    page = await browser.new_page()
                    await page.set_extra_http_headers(get_random_headers())
                    
                    full_url_pw = full_url_https # 优先尝试 HTTPS
                    try:
                        await page.goto(full_url_pw, timeout=30000, wait_until='networkidle')
                        content = await page.content()
                        logger.info(f"Playwright 成功从 {full_url_pw} 获取内容。")
                        break
                    except Exception as e:
                        logger.warning(f"Playwright 从 {full_url_pw} 获取失败: {e} (第 {attempt + 1} 次)。尝试 HTTP。")
                        # 尝试 Playwright HTTP
                        full_url_pw = full_url_http
                        await page.goto(full_url_pw, timeout=30000, wait_until='networkidle')
                        content = await page.content()
                        logger.info(f"Playwright 成功从 {full_url_pw} 获取内容。")
                        break
            except asyncio.TimeoutError:
                logger.warning(f"Playwright 从 {url} 获取超时 (第 {attempt + 1} 次)。")
            except Exception as e:
                logger.error(f"Playwright 从 {url} 获取时发生未知错误: {e} (第 {attempt + 1} 次)。", exc_info=True)
            finally:
                if browser:
                    try:
                        await browser.close()
                    except Exception as e:
                        logger.warning(f"关闭 Playwright 浏览器失败: {e}")

    if content:
        await write_cache(url, content)
    else:
        logger.error(f"经过 {RETRY_ATTEMPTS} 次尝试，未能获取 {url} 的内容，跳过。")
    return content

# --- DNS 解析函数 (保持不变) ---
async def check_dns_resolution(url):
    """检查域名是否能解析到有效 IP 地址"""
    # 提取域名部分
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname or parsed_url.path.split('/')[0] # 兼容只有路径的情况
    if not hostname:
        logger.warning(f"无法从 '{url}' 提取有效域名进行 DNS 解析。")
        return False
        
    if is_valid_ip(hostname): # 如果已经是 IP 地址，则直接通过
        return True

    try:
        async with asyncio.timeout(REQUEST_TIMEOUT_SECONDS):
            answers = await asyncio.to_thread(dns.resolver.resolve, hostname, 'A')
            if answers:
                logger.info(f"域名 '{hostname}' 解析成功，IP: {[str(a) for a in answers]}")
                return True
            else:
                logger.warning(f"域名 '{hostname}' 未能解析到 IP 地址。")
                return False
    except asyncio.TimeoutError:
        logger.warning(f"DNS 解析 '{hostname}' 超时。")
        return False
    except dns.resolver.NXDOMAIN:
        logger.warning(f"域名 '{hostname}' 不存在 (NXDOMAIN)。")
        return False
    except dns.resolver.NoAnswer:
        logger.warning(f"域名 '{hostname}' 没有可用的 A 记录。")
        return False
    except dns.resolver.NoNameservers as e:
        logger.warning(f"DNS 解析 '{hostname}' 失败: 所有名称服务器都未能应答 ({e})。")
        return False
    except Exception as e:
        logger.error(f"DNS 解析 '{hostname}' 时发生未知错误: {e}", exc_info=True)
        return False

# --- 节点验证函数 (保持不变) ---
def is_valid_ip(address):
    """验证是否为有效 IP 地址"""
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

def validate_node(protocol, data):
    """验证节点数据有效性 (增强验证逻辑)"""
    # logger.debug(f"正在验证 {protocol} 节点数据: {data}") # 过多日志，仅在调试时开启
    try:
        if protocol == "hysteria2":
            if not all(k in data for k in ['host', 'port']): return False
            if not data['host'] or not data['port'] or not data['port'].isdigit(): return False
            if not (re.match(r"^[a-zA-Z0-9\-\.]+$", data['host']) or is_valid_ip(data['host'])): return False
            if not (1 <= int(data['port']) <= 65535): return False
            return True
        elif protocol == "vmess":
            # 尝试解码，如果解码失败或不是有效JSON，则返回False
            try:
                decoded = base64.b64decode(data.get('data', '') + '=' * (4 - len(data.get('data', '')) % 4)).decode('utf-8', errors='ignore')
                json_data = json.loads(decoded)
            except Exception:
                return False
            
            if not all(k in json_data for k in ['add', 'port', 'id']): return False
            if not json_data['add'] or not json_data['port'] or not json_data['id']: return False
            if not (re.match(r"^[a-zA-Z0-9\-\.]+$", json_data['add']) or is_valid_ip(json_data['add'])): return False
            if not isinstance(json_data['port'], (int, str)): return False # 端口可以是字符串
            if not (1 <= int(json_data['port']) <= 65535): return False
            if not re.match(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", json_data['id']): return False
            return True
        elif protocol == "trojan":
            if not all(k in data for k in ['password', 'host', 'port']): return False
            if not data['password'] or not data['host'] or not data['port'] or not data['port'].isdigit(): return False
            if not (re.match(r"^[a-zA-Z0-9\-\.]+$", data['host']) or is_valid_ip(data['host'])): return False
            if not (1 <= int(data['port']) <= 65535): return False
            return True
        elif protocol == "ss":
            if not all(k in data for k in ['method_password', 'host', 'port']): return False
            if not data['method_password'] or not data['host'] or not data['port'] or not data['port'].isdigit(): return False
            try:
                # SS的method_password部分可能需要Base64解码
                decoded_mp = base64.b64decode(data['method_password'] + '=' * (4 - len(data['method_password']) % 4)).decode('utf-8', errors='ignore')
            except Exception:
                return False
            if ':' not in decoded_mp: return False # 确保包含 method:password
            if not (re.match(r"^[a-zA-Z0-9\-\.]+$", data['host']) or is_valid_ip(data['host'])): return False
            if not (1 <= int(data['port']) <= 65535): return False
            return True
        elif protocol == "ssr":
            try:
                decoded = base64.b64decode(data.get('data', '') + '=' * (4 - len(data.get('data', '')) % 4)).decode('utf-8', errors='ignore')
            except Exception:
                return False
            parts = decoded.split(':')
            if len(parts) < 6: return False # server:port:protocol:method:obfs:password_base64
            if not (re.match(r"^[a-zA-Z0-9\-\.]+$", parts[0]) or is_valid_ip(parts[0])): return False # server
            if not parts[1].isdigit() or not (1 <= int(parts[1]) <= 65535): return False # port
            # 协议、加密、混淆和密码可以更宽松，只要存在即可
            return True
        elif protocol == "vless":
            if not all(k in data for k in ['uuid', 'host', 'port', 'type']): return False
            if not data['uuid'] or not data['host'] or not data['port'] or not data['port'].isdigit() or not data['type']: return False
            if not re.match(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", data['uuid']): return False
            if not (re.match(r"^[a-zA-Z0-9\-\.]+$", data['host']) or is_valid_ip(data['host'])): return False
            if not (1 <= int(data['port']) <= 65535): return False
            return True
        elif protocol == "tuic":
            if not all(k in data for k in ['uuid', 'password', 'host', 'port']): return False
            if not data['uuid'] or not data['password'] or not data['host'] or not data['port'] or not data['port'].isdigit(): return False
            if not (re.match(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", data['uuid'])): return False
            if not (re.match(r"^[a-zA-Z0-9\-\.]+$", data['host']) or is_valid_ip(data['host'])): return False
            if not (1 <= int(data['port']) <= 65535): return False
            return True
        elif protocol == "wg":
            # WireGuard 通常是 Base64 编码的完整配置，解码后会有特定格式
            try:
                decoded = base64.b64decode(data.get('data', '') + '=' * (4 - len(data.get('data', '')) % 4)).decode('utf-8', errors='ignore')
                # 简单检查 WireGuard 配置的关键字
                if "PrivateKey" in decoded and "Address" in decoded and "Endpoint" in decoded:
                    return True
            except Exception:
                return False
            return False
        return False
    except Exception as e:
        logger.debug(f"验证节点 {protocol} 失败: {e}")
        return False

# --- 节点规范化与去重函数 (保持不变) ---
def get_node_canonical_fingerprint(node_url: str) -> str | None:
    """生成节点的规范化指纹，用于去重"""
    base_url_no_remark = node_url.split('#', 1)[0]
    try:
        parsed_url = urlparse(base_url_no_remark)
        scheme = parsed_url.scheme
        if not scheme:
            return None

        if scheme == "ss":
            if not parsed_url.netloc:
                return None
            auth_and_host = parsed_url.netloc
            if '@' not in auth_and_host:
                return None
            method_password_encoded, server_port = auth_and_host.split('@', 1)
            try:
                padded_method_password_encoded = method_password_encoded + '=' * (4 - len(method_password_encoded) % 4)
                decoded_method_password = base64.b64decode(padded_method_password_encoded).decode('utf-8', errors='ignore').strip()
                decoded_method_password = decoded_method_password.replace('\n', '').replace('\r', '')
                # 标准化方法和密码的顺序，通常方法在前
                parts = decoded_method_password.split(':', 1)
                method = parts[0]
                password = parts[1] if len(parts) > 1 else ""
                return f"ss://{method}:{password}@{server_port}"
            except Exception:
                return None

        elif scheme == "ssr":
            encoded_params = base_url_no_remark[len("ssr://"):]
            try:
                padded_encoded_params = encoded_params + '=' * (4 - len(encoded_params) % 4)
                decoded_params = base64.b64decode(padded_encoded_params).decode('utf-8', errors='ignore')
                core_params_part = decoded_params.split("/?")[0]
                parts = core_params_part.split(':')
                if len(parts) >= 6:
                    # 解码密码部分并标准化
                    try:
                        password_encoded = parts[5]
                        padded_password_encoded = password_encoded + '=' * (4 - len(password_encoded) % 4)
                        # SSR密码可能使用URL安全Base64变体，需要替换字符
                        decoded_password = base64.b64decode(padded_password_encoded.replace('-', '+').replace('_', '/')).decode('utf-8', errors='ignore')
                        parts[5] = decoded_password.strip()
                    except Exception:
                        pass # 如果密码解码失败，保持原样，但这会影响去重精度
                return f"ssr://{':'.join(parts)}"
            except Exception:
                return None

        elif scheme == "vmess":
            encoded_json = base_url_no_remark[len("vmess://"):]
            try:
                padded_encoded_json = encoded_json + '=' * (4 - len(encoded_json) % 4)
                decoded_json = base64.b64decode(padded_encoded_json).decode('utf-8', errors='ignore')
                vmess_config = json.loads(decoded_json)
                fingerprint_data = {
                    "add": vmess_config.get("add"),
                    "port": vmess_config.get("port"),
                    "id": vmess_config.get("id"),
                }
                # 包含关键的传输配置，如 net, type, tls, host, path, sni 等，按字典序排序
                optional_keys_for_fingerprint = ["net", "type", "security", "path", "host", "tls", "sni", "aid", "fp", "scy"]
                for key in sorted(optional_keys_for_fingerprint):
                    if key in vmess_config and vmess_config[key] is not None:
                        fingerprint_data[key] = vmess_config[key]
                
                return f"vmess://{json.dumps(fingerprint_data, sort_keys=True)}"
            except Exception:
                return None

        elif scheme in ["vless", "trojan", "hysteria2", "tuic"]:
            # 对于这些协议，主机、端口、ID/密码和查询参数是关键
            # 规范化查询参数：排序并重新编码
            query_params_list = parse_qs(parsed_url.query, keep_blank_values=True)
            sorted_query_params = []
            for key in sorted(query_params_list.keys()):
                for value in sorted(query_params_list[key]): # 对值也进行排序，确保一致性
                    sorted_query_params.append((key, value))
            sorted_query_string = urlencode(sorted_query_params)

            canonical_url_parts = [scheme, "://"]
            # 用户信息（如果存在）
            if parsed_url.username:
                canonical_url_parts.append(parsed_url.username)
                if parsed_url.password:
                    canonical_url_parts.append(f":{parsed_url.password}")
                canonical_url_parts.append("@")
            
            canonical_url_parts.append(parsed_url.netloc)
            
            if parsed_url.path:
                canonical_url_parts.append(parsed_url.path)
            if sorted_query_string:
                canonical_url_parts.append("?")
                canonical_url_parts.append(sorted_query_string)
            return "".join(canonical_url_parts)
            
        elif scheme == "wg":
            encoded_data = base_url_no_remark[len("wg://"):]
            try:
                # WireGuard 指纹可以简单地基于其 Base64 编码的配置（假设配置是唯一的）
                # 理论上可以解析内部配置并规范化，但对于去重，原始编码通常足够
                return f"wg://{encoded_data}" 
            except Exception:
                return None
            
        return None
    except Exception as e:
        logger.debug(f"规范化节点 '{node_url}' 失败: {e}")
        return None

# --- 节点解析与提取函数 (保持不变) ---
def extract_nodes_from_text(text_content):
    """从文本中提取代理节点 (增强提取逻辑)"""
    extracted_nodes = set()
    
    # 优先匹配已知协议的节点
    for protocol, regex_pattern in NODE_REGEXES.items():
        for match in re.finditer(regex_pattern, text_content, re.IGNORECASE): # 忽略大小写
            full_uri = match.group(0)
            matched_data = match.groupdict()
            if validate_node(protocol, matched_data):
                extracted_nodes.add(full_uri)

    # 尝试 Base64 解码和递归处理
    # 查找可能包含 Base64 编码数据的块
    # 改进的 Base64 正则表达式，尝试匹配更长的、以 = 结尾的有效 Base64 字符串
    # 并且避免匹配太短的、可能是普通文本的字符串
    base64_candidates = re.findall(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})(?![A-Za-z0-9+/])", text_content)
    for b64_block in sorted(base64_candidates, key=len, reverse=True): # 优先处理长块
        if len(b64_block) > 30 and len(b64_block) % 4 == 0: # 设一个合理的长度阈值
            try:
                decoded_content = base64.b64decode(b64_block).decode('utf-8', errors='ignore')
                # 递归处理解码后的内容
                recursive_nodes = extract_nodes_from_text(decoded_content)
                extracted_nodes.update(recursive_nodes)
            except Exception as e:
                logger.debug(f"Base64 解码或递归处理失败: {e}, 块: {b64_block[:50]}...")
        # 如果是订阅链接，有时会直接是 Base64 编码的订阅内容，长度可能会很长
        elif len(b64_block) > 100: # 对很长的Base64块也尝试一下
            try:
                decoded_content = base64.b64decode(b64_block).decode('utf-8', errors='ignore')
                recursive_nodes = extract_nodes_from_text(decoded_content)
                extracted_nodes.update(recursive_nodes)
            except Exception:
                pass


    # 递归处理嵌套结构 (YAML/JSON)
    def extract_from_nested(data_obj):
        if isinstance(data_obj, dict):
            for key, value in data_obj.items():
                if isinstance(value, str):
                    extracted_nodes.update(extract_nodes_from_text(value))
                elif isinstance(value, (dict, list)):
                    extract_from_nested(value)
        elif isinstance(data_obj, list):
            for item in data_obj:
                if isinstance(item, str):
                    extracted_nodes.update(extract_nodes_from_text(item))
                elif isinstance(item, (dict, list)):
                    extract_from_nested(item)

    try:
        yaml_content = yaml.safe_load(text_content)
        if isinstance(yaml_content, (dict, list)):
            extract_from_nested(yaml_content)
    except yaml.YAMLError as e:
        logger.debug(f"YAML 解析失败: {e}")

    try:
        json_content = json.loads(text_content)
        if isinstance(json_content, (dict, list)):
            extract_from_nested(json_content)
    except json.JSONDecodeError as e:
        logger.debug(f"JSON 解析失败: {e}")

    return extracted_nodes

def parse_and_extract_nodes(content):
    """从 HTML 内容中解析并提取节点 (增强HTML解析范围)"""
    nodes_from_html = set()
    try:
        soup = BeautifulSoup(content, 'html.parser')

        # 优先从常见包含配置的标签中提取
        for tag_name in ['pre', 'code', 'textarea']:
            for tag in soup.find_all(tag_name):
                text_content = tag.get_text(separator='\n', strip=True) # 使用换行符分隔，并去除空白
                if text_content:
                    nodes_from_html.update(extract_nodes_from_text(text_content))

        # 尝试从 <script> 标签中提取 JSON 或其他配置
        for script_tag in soup.find_all('script'):
            script_content = script_tag.string
            if script_content:
                # 尝试解析 JSON 格式的脚本内容
                try:
                    json_data = json.loads(script_content)
                    nodes_from_html.update(extract_nodes_from_text(json.dumps(json_data)))
                except json.JSONDecodeError:
                    # 如果不是标准JSON，也尝试作为普通文本处理
                    nodes_from_html.update(extract_nodes_from_text(script_content))
            
        # 如果以上标签未找到节点，或者为了更全面，检查整个 body 文本
        if not nodes_from_html:
            body_text = soup.body.get_text(separator='\n', strip=True) if soup.body else soup.get_text(separator='\n', strip=True)
            nodes_from_html.update(extract_nodes_from_text(body_text))

    except Exception as e:
        logger.error(f"解析 HTML 内容时发生错误: {e}")
    return nodes_from_html

# --- 新增：搜索引擎结果解析函数 ---
async def search_and_get_urls(protocol_keyword, http_client, playwright_instance: Playwright):
    """
    通过搜索引擎搜索指定协议关键词，并返回结果URL。
    为了提高成功率，可以尝试多个搜索引擎。
    """
    found_urls = set()
    query_string = f'"{protocol_keyword}//" inurl:subscribe OR inurl:config OR inurl:proxy' # 增强搜索关键词
    
    for engine in SEARCH_ENGINES:
        logger.info(f"正在使用 {engine['name']} 搜索 '{protocol_keyword}' 相关页面...")
        for page_num in range(SEARCH_PAGES_PER_PROTOCOL):
            start_param_value = page_num * RESULTS_PER_PAGE # Google: 0, 10, 20... Bing: 1, 11, 21...
            if engine['name'] == "Bing":
                start_param_value += 1 # Bing 的起始参数从 1 开始
            
            search_url = f"{engine['base_url']}{urlencode({'q': query_string})}{engine['param']}{start_param_value}"
            logger.info(f"搜索URL: {search_url}")

            search_result_content = await fetch_url(search_url, http_client, playwright_instance)
            if not search_result_content:
                logger.warning(f"未能获取 {engine['name']} 搜索结果页面，跳过。")
                continue

            try:
                soup = BeautifulSoup(search_result_content, 'html.parser')
                # 针对不同搜索引擎，解析结果链接的CSS选择器可能不同
                if engine['name'] == "Google":
                    # Google 搜索结果链接通常在 <a href="..."> 标签中，class 可能包含 "l" 或 "LC20lb DKV0Md"
                    # 或者更通用地查找所有以 /url?q= 开头的链接
                    for a_tag in soup.find_all('a', href=True):
                        href = a_tag['href']
                        if href.startswith('/url?q=') and not href.startswith('/url?q=/search'):
                            # 提取真实的URL并解码
                            actual_url = parse_qs(urlparse(href).query).get('q', [None])[0]
                            if actual_url and actual_url not in found_urls and urlparse(actual_url).scheme in ['http', 'https']:
                                found_urls.add(actual_url)
                                logger.debug(f"从 Google 搜索结果中找到URL: {actual_url}")
                elif engine['name'] == "Bing":
                    # Bing 搜索结果链接通常在 <a href="..."> 标签中，class 可能是 "b_tcd" 等
                    for h2_tag in soup.find_all('h2'):
                        a_tag = h2_tag.find('a', href=True)
                        if a_tag:
                            href = a_tag['href']
                            if href and href not in found_urls and urlparse(href).scheme in ['http', 'https']:
                                found_urls.add(href)
                                logger.debug(f"从 Bing 搜索结果中找到URL: {href}")
                # 随机延迟，避免被搜索引擎反爬
                await asyncio.sleep(random.uniform(2, 5))
            except Exception as e:
                logger.error(f"解析 {engine['name']} 搜索结果时发生错误: {e}")
    
    logger.info(f"通过搜索关键词 '{protocol_keyword}' 找到了 {len(found_urls)} 个潜在页面。")
    return list(found_urls)


async def process_url_and_extract_nodes(url, http_client, playwright_instance: Playwright, processed_urls, global_unique_nodes_map):
    """
    处理单个 URL，提取节点。
    这个版本不进行递归，因为我们通过搜索引擎获取的是独立的潜在目标页面。
    """
    if url in processed_urls:
        logger.debug(f"URL '{url}' 已经处理过，跳过。")
        return 0

    processed_urls.add(url)
    logger.info(f"正在处理 URL: {url}")
    
    content = await fetch_url(url, http_client, playwright_instance)
    if not content:
        logger.error(f"未能获取 {url} 的内容，跳过节点提取。")
        return 0

    nodes_from_current_url_content = parse_and_extract_nodes(content)
    
    current_url_nodes_count = 0
    # 去重当前 URL 的节点并加入全局唯一节点集合
    for node in nodes_from_current_url_content:
        canonical_fingerprint = get_node_canonical_fingerprint(node)
        if canonical_fingerprint and canonical_fingerprint not in global_unique_nodes_map:
            global_unique_nodes_map[canonical_fingerprint] = node
            current_url_nodes_count += 1
        elif canonical_fingerprint:
            logger.debug(f"节点 '{node[:50]}...' 已存在于全局集合，跳过。")

    logger.info(f"从 {url} 提取了 {current_url_nodes_count} 个新有效节点。")
    return current_url_nodes_count

async def main():
    """主函数，协调抓取和保存过程"""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(CACHE_DIR, exist_ok=True)
    
    all_potential_urls = set()
    processed_urls = set() # 记录已处理的 URL，避免重复访问
    global_unique_nodes_map = {} # 存储所有去重后的节点

    async with async_playwright() as p:
        async with httpx.AsyncClient(http2=True, follow_redirects=True) as http_client:
            # 第一阶段：通过搜索引擎获取潜在 URL
            logger.info("--- 开始通过搜索引擎发现潜在 URL ---")
            search_tasks = []
            for protocol in SEARCH_PROTOCOLS:
                search_tasks.append(search_and_get_urls(protocol, http_client, p))
            
            search_results_lists = await asyncio.gather(*search_tasks, return_exceptions=True)

            for result_list in search_results_lists:
                if isinstance(result_list, Exception):
                    logger.error(f"搜索引擎任务失败: {result_list}")
                    continue
                all_potential_urls.update(result_list)
            
            # DNS 预检查所有潜在 URL
            logger.info(f"--- 发现 {len(all_potential_urls)} 个潜在 URL，开始进行 DNS 解析预检查 ---")
            valid_urls_after_dns = set()
            dns_check_tasks = [check_dns_resolution(url) for url in all_potential_urls]
            dns_results = await asyncio.gather(*dns_check_tasks, return_exceptions=True)

            for i, url in enumerate(list(all_potential_urls)): # 转换为列表以便索引
                if isinstance(dns_results[i], Exception):
                    logger.warning(f"DNS 解析 '{url}' 失败: {dns_results[i]}")
                elif dns_results[i]:
                    valid_urls_after_dns.add(url)
                else:
                    logger.info(f"URL '{url}' DNS 解析失败，已跳过。")
            
            logger.info(f"--- DNS 解析预检查完成。成功解析 {len(valid_urls_after_dns)} 个潜在 URL ---")

            if not valid_urls_after_dns:
                logger.warning("没有可用的有效潜在 URL 进行内容抓取，程序退出。")
                return

            # 第二阶段：并发处理潜在 URL 并提取节点
            logger.info(f"即将开始处理 {len(valid_urls_after_dns)} 个潜在 URL 进行节点提取...")
            semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
            
            async def bounded_process_url_and_extract_nodes(url, http_client, playwright_instance, processed_urls, global_unique_nodes_map, semaphore):
                """封装 URL 处理任务，确保错误不会中断整体运行"""
                try:
                    async with semaphore:
                        return await process_url_and_extract_nodes(url, http_client, playwright_instance, processed_urls, global_unique_nodes_map)
                except Exception as e:
                    logger.error(f"处理 URL {url} 时发生错误: {e}")
                    return 0

            # 将 valid_urls_after_dns 转换为列表以便迭代
            processing_tasks = [bounded_process_url_and_extract_nodes(url, http_client, p, processed_urls, global_unique_nodes_map, semaphore) for url in list(valid_urls_after_dns)]
            
            await asyncio.gather(*processing_tasks, return_exceptions=True)
            
    # --- 最终输出所有去重节点到 data/jy.txt ---
    try:
        if global_unique_nodes_map:
            async with aiofiles.open(FINAL_NODE_OUTPUT_FILE, 'w', encoding='utf-8') as f:
                for node in sorted(global_unique_nodes_map.values()):
                    await f.write(node + '\n')
            logger.info(f"所有 {len(global_unique_nodes_map)} 个唯一节点已成功保存到 {FINAL_NODE_OUTPUT_FILE}。")
        else:
            logger.info(f"未找到任何唯一节点，{FINAL_NODE_OUTPUT_FILE} 文件未生成。")
    except Exception as e:
        logger.error(f"保存节点到 {FINAL_NODE_OUTPUT_FILE} 失败: {e}")

    # 可以选择性地保留 CSV 统计文件，或者移除
    # 为了简化，这里不再生成每个 URL 的独立文件和 CSV，只关注最终的 jy.txt
    
    logger.info("--- 脚本运行结束 ---")

if __name__ == "__main__":
    asyncio.run(main())
