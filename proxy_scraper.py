import httpx
import asyncio
import re
import os
import hashlib
from urllib.parse import urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
import yaml
import base64
import json
import ipaddress
import dns.resolver
import random
import datetime
import aiofiles
import logging
from playwright.async_api import async_playwright, Playwright

# --- 配置常量 ---
OUTPUT_DIR = "data"  # 输出目录
CACHE_DIR = "cache"  # 缓存目录
CACHE_EXPIRATION_HOURS = 24  # 缓存过期时间（小时）
MAX_CONCURRENT_REQUESTS = 5  # 适度提高并发数，但仍需注意资源和反爬
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
# 确保不会重复添加 handler
if not logger.handlers:
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
    "tuic": r"tuic:\/\/(?P<uuid>[a-zA-Z0-9\-]+):(?P<password>[a-zA-Z0-9\-_.~%]+)@(?P<host>[a-zA-Z0-9\-\.]+):(?P<port>\d+)\?(?:.*&)?(?:udp_relay=(?P<udp_relay>[^&]*))?",
    "wg": r"wg:\/\/(?P<data>[a-zA-Z0-9+\/=]+)",
}

# 搜索引擎配置
SEARCH_ENGINES = [
    {"name": "Google", "base_url": "https://www.google.com/search", "query_param": "q", "start_param": "start"},
    {"name": "Bing", "base_url": "https://www.bing.com/search", "query_param": "q", "start_param": "first"},
]
# 使用所有定义的协议作为搜索关键词的基础
SEARCH_PROTOCOLS = list(NODE_REGEXES.keys()) 
# 增强的搜索修饰符，用于提高搜索结果的相关性
SEARCH_MODIFIERS = [
    '"subscribe"', '"订阅"', '"分享"', '"节点"', '"free proxy"', '"机场"', 
    'inurl:subscribe', 'inurl:config', 'inurl:proxy', 'site:github.com', 'site:pages.dev',
    'site:gitee.com', 'site:gitlab.com', 'site:medium.com', 'site:bilibili.com' # 尝试加入一些常见分享平台
]
SEARCH_PAGES_PER_PROTOCOL = 5 # 每个协议搜索的页数（每页约10个结果），增加搜索深度
RESULTS_PER_PAGE = 10 # 搜索引擎每页结果数

# --- 缓存处理函数 ---
def generate_cache_key(url):
    return hashlib.md5(url.encode('utf-8')).hexdigest() + ".cache"

def get_cache_path(url):
    return os.path.join(CACHE_DIR, generate_cache_key(url))

async def read_cache(url):
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
    cache_path = get_cache_path(url)
    os.makedirs(CACHE_DIR, exist_ok=True)
    try:
        async with asyncio.Lock():
            async with aiofiles.open(cache_path, 'w', encoding='utf-8') as f:
                await f.write(content)
        logger.info(f"内容已写入缓存 '{url}'。")
    except Exception as e:
        logger.error(f"写入缓存 '{url}' 失败: {e}")

# --- 网络请求相关函数 ---
def get_random_headers():
    device_type = random.choice(list(USER_AGENTS.keys()))
    return {"User-Agent": random.choice(USER_AGENTS[device_type])}

async def fetch_url(url, http_client, playwright_instance: Playwright):
    parsed_url = urlparse(url)
    if not parsed_url.scheme:
        full_url_https = f"https://{url}"
        full_url_http = f"http://{url}"
    else:
        full_url_https = url
        full_url_http = url.replace("https://", "http://", 1)

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
                async with asyncio.timeout(REQUEST_TIMEOUT_SECONDS * 2):
                    browser = await playwright_instance.chromium.launch()
                    page = await browser.new_page()
                    await page.set_extra_http_headers(get_random_headers())
                    
                    full_url_pw = full_url_https
                    try:
                        await page.goto(full_url_pw, timeout=30000, wait_until='networkidle')
                        content = await page.content()
                        logger.info(f"Playwright 成功从 {full_url_pw} 获取内容。")
                        break
                    except Exception as e:
                        logger.warning(f"Playwright 从 {full_url_pw} 获取失败: {e} (第 {attempt + 1} 次)。尝试 HTTP。")
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

# --- DNS 解析函数 ---
async def check_dns_resolution(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname or parsed_url.path.split('/')[0]
    if not hostname:
        logger.warning(f"无法从 '{url}' 提取有效域名进行 DNS 解析。")
        return False
        
    if is_valid_ip(hostname):
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

# --- 节点验证函数 ---
def is_valid_ip(address):
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

def validate_node(protocol, data):
    try:
        if protocol == "hysteria2":
            if not all(k in data for k in ['host', 'port']): return False
            if not data['host'] or not data['port'] or not data['port'].isdigit(): return False
            if not (re.match(r"^[a-zA-Z0-9\-\.]+$", data['host']) or is_valid_ip(data['host'])): return False
            if not (1 <= int(data['port']) <= 65535): return False
            return True
        elif protocol == "vmess":
            try:
                decoded = base64.b64decode(data.get('data', '') + '=' * (4 - len(data.get('data', '')) % 4)).decode('utf-8', errors='ignore')
                json_data = json.loads(decoded)
            except Exception:
                return False
            
            if not all(k in json_data for k in ['add', 'port', 'id']): return False
            if not json_data['add'] or not json_data['port'] or not json_data['id']: return False
            if not (re.match(r"^[a-zA-Z0-9\-\.]+$", json_data['add']) or is_valid_ip(json_data['add'])): return False
            if not isinstance(json_data['port'], (int, str)): return False
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
                decoded_mp = base64.b64decode(data['method_password'] + '=' * (4 - len(data['method_password']) % 4)).decode('utf-8', errors='ignore')
            except Exception:
                return False
            if ':' not in decoded_mp: return False
            if not (re.match(r"^[a-zA-Z0-9\-\.]+$", data['host']) or is_valid_ip(data['host'])): return False
            if not (1 <= int(data['port']) <= 65535): return False
            return True
        elif protocol == "ssr":
            try:
                decoded = base64.b64decode(data.get('data', '') + '=' * (4 - len(data.get('data', '')) % 4)).decode('utf-8', errors='ignore')
            except Exception:
                return False
            parts = decoded.split(':')
            if len(parts) < 6: return False
            if not (re.match(r"^[a-zA-Z0-9\-\.]+$", parts[0]) or is_valid_ip(parts[0])): return False
            if not parts[1].isdigit() or not (1 <= int(parts[1]) <= 65535): return False
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
            try:
                decoded = base64.b64decode(data.get('data', '') + '=' * (4 - len(data.get('data', '')) % 4)).decode('utf-8', errors='ignore')
                if "PrivateKey" in decoded and "Address" in decoded and "Endpoint" in decoded:
                    return True
            except Exception:
                return False
            return False
        return False
    except Exception as e:
        logger.debug(f"验证节点 {protocol} 失败: {e}")
        return False

# --- 节点规范化与去重函数 ---
def get_node_canonical_fingerprint(node_url: str) -> str | None:
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
                    try:
                        password_encoded = parts[5]
                        padded_password_encoded = password_encoded + '=' * (4 - len(password_encoded) % 4)
                        decoded_password = base64.b64decode(padded_password_encoded.replace('-', '+').replace('_', '/')).decode('utf-8', errors='ignore')
                        parts[5] = decoded_password.strip()
                    except Exception:
                        pass
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
                optional_keys_for_fingerprint = ["net", "type", "security", "path", "host", "tls", "sni", "aid", "fp", "scy"]
                for key in sorted(optional_keys_for_fingerprint):
                    if key in vmess_config and vmess_config[key] is not None:
                        fingerprint_data[key] = vmess_config[key]
                
                return f"vmess://{json.dumps(fingerprint_data, sort_keys=True)}"
            except Exception:
                return None

        elif scheme in ["vless", "trojan", "hysteria2", "tuic"]:
            query_params_list = parse_qs(parsed_url.query, keep_blank_values=True)
            sorted_query_params = []
            for key in sorted(query_params_list.keys()):
                for value in sorted(query_params_list[key]):
                    sorted_query_params.append((key, value))
            sorted_query_string = urlencode(sorted_query_params)

            canonical_url_parts = [scheme, "://"]
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
                return f"wg://{encoded_data}" 
            except Exception:
                return None
            
        return None
    except Exception as e:
        logger.debug(f"规范化节点 '{node_url}' 失败: {e}")
        return None

# --- 节点解析与提取函数 ---
def extract_nodes_from_text(text_content):
    extracted_nodes = set()
    
    for protocol, regex_pattern in NODE_REGEXES.items():
        for match in re.finditer(regex_pattern, text_content, re.IGNORECASE):
            full_uri = match.group(0)
            matched_data = match.groupdict()
            if validate_node(protocol, matched_data):
                extracted_nodes.add(full_uri)

    base64_candidates = re.findall(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})(?![A-Za-z0-9+/])", text_content)
    for b64_block in sorted(base64_candidates, key=len, reverse=True):
        if len(b64_block) > 30 and len(b64_block) % 4 == 0:
            try:
                decoded_content = base64.b64decode(b64_block).decode('utf-8', errors='ignore')
                recursive_nodes = extract_nodes_from_text(decoded_content)
                extracted_nodes.update(recursive_nodes)
            except Exception as e:
                logger.debug(f"Base64 解码或递归处理失败: {e}, 块: {b64_block[:50]}...")
        elif len(b64_block) > 100:
            try:
                decoded_content = base64.b64decode(b64_block).decode('utf-8', errors='ignore')
                recursive_nodes = extract_nodes_from_text(decoded_content)
                extracted_nodes.update(recursive_nodes)
            except Exception:
                pass


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
    nodes_from_html = set()
    try:
        soup = BeautifulSoup(content, 'html.parser')

        for tag_name in ['pre', 'code', 'textarea']:
            for tag in soup.find_all(tag_name):
                text_content = tag.get_text(separator='\n', strip=True)
                if text_content:
                    nodes_from_html.update(extract_nodes_from_text(text_content))

        for script_tag in soup.find_all('script'):
            script_content = script_tag.string
            if script_content:
                try:
                    json_data = json.loads(script_content)
                    nodes_from_html.update(extract_nodes_from_text(json.dumps(json_data)))
                except json.JSONDecodeError:
                    nodes_from_html.update(extract_nodes_from_text(script_content))
            
        if not nodes_from_html:
            body_text = soup.body.get_text(separator='\n', strip=True) if soup.body else soup.get_text(separator='\n', strip=True)
            nodes_from_html.update(extract_nodes_from_text(body_text))

    except Exception as e:
        logger.error(f"解析 HTML 内容时发生错误: {e}")
    return nodes_from_html

# --- 优化后的搜索引擎结果解析函数 ---
async def search_and_get_urls(protocol_keyword, http_client, playwright_instance: Playwright):
    """
    通过搜索引擎搜索指定协议关键词，并返回结果URL。
    整合更多修饰符以提高搜索结果相关性。
    """
    found_urls = set()
    # 组合核心关键词和修饰符
    query_parts = [f'"{protocol_keyword}//"'] + SEARCH_MODIFIERS
    query_string = " ".join(query_parts) # 使用空格连接，搜索引擎会理解为 AND 关系

    logger.info(f"--- 开始搜索关键词: '{query_string}' ---")
    
    for engine in SEARCH_ENGINES:
        logger.info(f"正在使用 {engine['name']} 搜索...")
        for page_num in range(SEARCH_PAGES_PER_PROTOCOL):
            # 计算起始结果的参数值
            start_param_value = page_num * RESULTS_PER_PAGE
            if engine['name'] == "Bing":
                start_param_value = page_num * RESULTS_PER_PAGE + 1 # Bing 的起始参数通常从 1 开始
            
            params = {
                engine['query_param']: query_string,
                engine['start_param']: start_param_value
            }
            search_url = f"{engine['base_url']}?{urlencode(params)}"
            logger.info(f"搜索URL ({engine['name']}, 第 {page_num + 1} 页): {search_url}")

            search_result_content = await fetch_url(search_url, http_client, playwright_instance)
            if not search_result_content:
                logger.warning(f"未能获取 {engine['name']} 搜索结果页面 (第 {page_num + 1} 页)，跳过。")
                continue

            try:
                soup = BeautifulSoup(search_result_content, 'html.parser')
                # 针对不同搜索引擎，解析结果链接的CSS选择器可能不同
                if engine['name'] == "Google":
                    # 查找所有a标签，并过滤出真实的搜索结果链接
                    for a_tag in soup.find_all('a', href=True):
                        href = a_tag['href']
                        if href.startswith('/url?q=') and not href.startswith('/url?q=/search'):
                            actual_url = parse_qs(urlparse(href).query).get('q', [None])[0]
                            if actual_url and actual_url not in found_urls and urlparse(actual_url).scheme in ['http', 'https']:
                                found_urls.add(actual_url)
                                logger.debug(f"从 Google 搜索结果中找到URL: {actual_url}")
                elif engine['name'] == "Bing":
                    # Bing 搜索结果链接通常在 class 为 "b_algo" 的 div 下的 a 标签中
                    for div_tag in soup.find_all('li', class_='b_dataList'): # Bing 的结果通常在 li.b_dataList 或 li.b_algo
                        a_tag = div_tag.find('a', href=True)
                        if a_tag:
                            href = a_tag['href']
                            if href and href not in found_urls and urlparse(href).scheme in ['http', 'https']:
                                found_urls.add(href)
                                logger.debug(f"从 Bing 搜索结果中找到URL: {href}")
                
                # 随机延迟，避免被搜索引擎反爬
                await asyncio.sleep(random.uniform(3, 7)) # 增加延迟范围
            except Exception as e:
                logger.error(f"解析 {engine['name']} 搜索结果时发生错误: {e}")
    
    logger.info(f"通过搜索关键词 '{protocol_keyword}' 找到了 {len(found_urls)} 个潜在页面。")
    return list(found_urls)


async def process_url_and_extract_nodes(url, http_client, playwright_instance: Playwright, processed_urls, global_unique_nodes_map):
    """
    处理单个 URL，提取节点。
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
    processed_urls = set()
    global_unique_nodes_map = {}

    async with async_playwright() as p:
        async with httpx.AsyncClient(http2=True, follow_redirects=True) as http_client:
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
            
            logger.info(f"--- 发现 {len(all_potential_urls)} 个潜在 URL，开始进行 DNS 解析预检查 ---")
            valid_urls_after_dns = set()
            dns_check_tasks = [check_dns_resolution(url) for url in all_potential_urls]
            dns_results = await asyncio.gather(*dns_check_tasks, return_exceptions=True)

            for i, url in enumerate(list(all_potential_urls)):
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

            logger.info(f"即将开始处理 {len(valid_urls_after_dns)} 个潜在 URL 进行节点提取...")
            semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
            
            async def bounded_process_url_and_extract_nodes(url, http_client, playwright_instance, processed_urls, global_unique_nodes_map, semaphore):
                try:
                    async with semaphore:
                        return await process_url_and_extract_nodes(url, http_client, playwright_instance, processed_urls, global_unique_nodes_map)
                except Exception as e:
                    logger.error(f"处理 URL {url} 时发生错误: {e}")
                    return 0

            processing_tasks = [bounded_process_url_and_extract_nodes(url, http_client, p, processed_urls, global_unique_nodes_map, semaphore) for url in list(valid_urls_after_dns)]
            
            await asyncio.gather(*processing_tasks, return_exceptions=True)
            
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
    
    logger.info("--- 脚本运行结束 ---")

if __name__ == "__main__":
    asyncio.run(main())
