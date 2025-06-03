import base64
import json
import logging
import re
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import unquote, urlparse

import requests
import yaml

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 定义协议类型
PROTOCOL_TYPE_SS = "ss"
PROTOCOL_TYPE_VMESS = "vmess"
PROTOCOL_TYPE_VLESS = "vless"
PROTOCOL_TYPE_HY2 = "hy2"
PROTOCOL_TYPE_TROJAN = "trojan"
PROTOCOL_TYPE_REALITY = "reality"
PROTOCOL_TYPE_TUIC = "tuic"
PROTOCOL_TYPE_WG = "wg"
PROTOCOL_TYPE_WARP = "warp"
PROTOCOL_TYPE_SHADOW_TLS = "shadow-tls"

# --- 配置加载类 ---
class Config:
    _instance = None
    _config_data = {}
    _config_path = "config_proxy.yaml"

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Config, cls).__new__(cls)
            cls._instance._load_config()
        return cls._instance

    def _load_config(self):
        try:
            with open(self._config_path, 'r', encoding='utf-8') as f:
                self._config_data = yaml.safe_load(f)
            logger.info(f"Configuration loaded successfully from: {self._config_path}")
        except FileNotFoundError:
            logger.error(f"Config file not found: {self._config_path}")
            sys.exit(1)
        except yaml.YAMLError as e:
            logger.error(f"Error parsing config file: {e}")
            sys.exit(1)

    def get(self, key, default=None):
        keys = key.split('.')
        val = self._config_data
        for k in keys:
            if isinstance(val, dict) and k in val:
                val = val[k]
            else:
                return default
        return val

# --- 缓存管理类 ---
class CacheManager:
    def __init__(self, cache_path, ttl_config_key):
        self.cache_path = cache_path
        self.ttl_config_key = ttl_config_key
        self.cache_data = self._load_cache()
        self.lock = threading.Lock() # 用于线程安全

    def _load_cache(self):
        try:
            with open(self.cache_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {"timestamp": 0, "data": {}} # timestamp for TTL check

    def _save_cache(self):
        with self.lock:
            with open(self.cache_path, 'w', encoding='utf-8') as f:
                json.dump(self.cache_data, f, indent=4)
            logger.info(f"Cache saved to {self.cache_path}.")

    def is_cache_valid(self):
        config = Config()
        ttl = config.get(self.ttl_config_key)
        if ttl is None:
            logger.warning(f"TTL for {self.ttl_config_key} not found in config. Cache will always be considered invalid.")
            return False # 如果没有配置TTL，则认为缓存无效，每次都更新

        # 检查缓存是否存在且未过期
        current_time = int(time.time())
        last_update_time = self.cache_data.get("timestamp", 0)
        is_valid = (current_time - last_update_time) < ttl and self.cache_data.get("data")
        
        if is_valid:
            logger.info(f"Cache for {self.cache_path} is valid (last updated {current_time - last_update_time}s ago).")
        else:
            logger.info(f"Cache for {self.cache_path} is expired or empty (last updated {current_time - last_update_time}s ago). Will refresh.")
        return is_valid

    def get_data(self):
        return self.cache_data.get("data", {})

    def set_data(self, data):
        with self.lock:
            self.cache_data["timestamp"] = int(time.time())
            self.cache_data["data"] = data
            self._save_cache()

# --- GitHub 搜索类 ---
class GitHubSearcher:
    def __init__(self):
        config = Config()
        self.search_keywords = config.get('search_keywords')
        self.per_page = config.get('per_page')
        self.max_search_pages = config.get('max_search_pages')
        self.github_api_timeout = config.get('github_api_timeout')
        self.github_api_retry_wait = config.get('github_api_retry_wait')
        self.rate_limit_threshold = config.get('rate_limit_threshold')
        self.max_urls = config.get('max_urls')
        self.search_cache = CacheManager(config.get('search_cache_path'), 'search_cache_ttl')

        self.github_token = self._get_github_token()
        self.headers = {'Authorization': f'token {self.github_token}'} if self.github_token else {}
        self.base_url = "https://api.github.com/search/code" # 针对文件内容的搜索

        self.found_raw_urls = set()
        self.lock = threading.Lock() # 用于同步访问 self.found_raw_urls

    def _get_github_token(self):
        token = os.getenv('GITHUB_TOKEN')
        if token:
            logger.info("GitHub Token loaded from environment variable.")
            return token
        else:
            logger.warning("GitHub Token not found in environment variable. API rate limit will be very low.")
            return None

    def _check_rate_limit(self, session):
        try:
            response = session.get("https://api.github.com/rate_limit", headers=self.headers, timeout=self.github_api_timeout)
            response.raise_for_status()
            rate_limit_data = response.json()
            core_limit = rate_limit_data['resources']['core']
            remaining = core_limit['remaining']
            reset_time = core_limit['reset']
            
            logger.info(f"GitHub API Rate Limit: Remaining {remaining} of {core_limit['limit']}, Resets at {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(reset_time))}")

            if remaining < self.rate_limit_threshold:
                wait_time = max(self.github_api_retry_wait, reset_time - int(time.time()) + 5) # +5秒确保避开
                logger.warning(f"GitHub API rate limit hit, {remaining} remaining. Waiting for {wait_time:.1f} seconds.")
                time.sleep(wait_time)
                return True # Indicate that we waited
            return False
        except requests.exceptions.RequestException as e:
            logger.error(f"Error checking GitHub API rate limit: {e}")
            return False # Assume no wait, or error, proceed with caution

    def search_github(self):
        if self.search_cache.is_cache_valid():
            self.found_raw_urls = set(self.search_cache.get_data())
            logger.info(f"Loaded search cache with {len(self.found_raw_urls)} entries.")
            # return # 这里不再直接返回，而是继续尝试获取新的，但不会重复处理
            # 即使缓存有效，我们依然可以尝试获取新的数据，然后合并。
            # 如果是 CI/CD 环境，为了效率可以返回。但本地运行时，可以继续尝试。
            # 为避免重复添加，用 set 确保唯一性。

        session = requests.Session()
        retry_strategy = requests.packages.urllib3.util.retry.Retry(
            total=Config().get('requests_retry_total'),
            backoff_factor=Config().get('requests_retry_backoff_factor'),
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods={"HEAD", "GET", "OPTIONS"}
        )
        adapter = requests.adapters.HTTPAdapter(max_retries=retry_strategy, pool_connections=Config().get('requests_pool_size'), pool_maxsize=Config().get('requests_pool_size'))
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        for keyword in self.search_keywords:
            if len(self.found_raw_urls) >= self.max_urls:
                logger.info(f"Reached max_urls limit ({self.max_urls}). Stopping GitHub search.")
                break

            logger.info(f"Starting search for keyword: '{keyword}'")
            for page in range(1, self.max_search_pages + 1):
                if len(self.found_raw_urls) >= self.max_urls:
                    break

                self._check_rate_limit(session) # 每次请求前检查速率限制

                params = {
                    'q': keyword,
                    'per_page': self.per_page,
                    'page': page
                }
                try:
                    response = session.get(self.base_url, headers=self.headers, params=params, timeout=self.github_api_timeout)
                    response.raise_for_status()
                    data = response.json()
                    
                    items = data.get('items', [])
                    current_page_urls = set()
                    for item in items:
                        # 对于 'raw.githubusercontent.com' 或 'gist.github.com' 的关键词，item['html_url'] 本身可能就是我们想要的
                        # 但对于其他代码搜索，我们需要 item['git_url'] 或 item['url'] 来构建 raw_url
                        # GitHub search code API returns 'raw_url' directly for file content matches.
                        raw_url = item.get('raw_url') 
                        if raw_url:
                            current_page_urls.add(raw_url)
                        # 额外处理针对 raw.githubusercontent.com 或 gist.github.com 的关键词
                        # 如果搜索关键词本身就是完整url的一部分，item['html_url']可能包含我们需要的url
                        # 例如搜索 "raw.githubusercontent.com ss://"
                        elif "raw.githubusercontent.com" in keyword or "gist.github.com" in keyword:
                            # 尝试从html_url中解析，如果它是符合raw格式的
                            if item.get('html_url') and ("raw.githubusercontent.com" in item['html_url'] or "gist.github.com" in item['html_url']):
                                # 这是一个不太精确的方法，可能需要更复杂的正则匹配来提取确切的raw文件URL
                                # 简单处理：如果html_url看起来像raw_url，就添加
                                if "/blob/" in item['html_url']:
                                    potential_raw_url = item['html_url'].replace("/blob/", "/raw/")
                                    current_page_urls.add(potential_raw_url)
                                elif "/gist.github.com/" in item['html_url'] and "/raw/" in item['html_url']:
                                    current_page_urls.add(item['html_url']) # gists的raw URL通常直接在html_url里
                        
                    with self.lock:
                        self.found_raw_urls.update(current_page_urls)
                    
                    logger.info(f"Found {len(items)} items, extracted {len(current_page_urls)} raw URLs for '{keyword}' (page {page}). Total collected: {len(self.found_raw_urls)}")

                    if len(items) < self.per_page: # 如果当前页结果少于 per_page，说明没有更多页了
                        logger.info(f"Less than {self.per_page} items on page {page}, assuming last page for '{keyword}'.")
                        break

                except requests.exceptions.HTTPError as e:
                    if e.response.status_code == 403 and 'rate limit exceeded' in e.response.text:
                        logger.warning(f"GitHub API rate limit exceeded for keyword '{keyword}'. Will wait and retry.")
                        self._check_rate_limit(session)
                    else:
                        logger.error(f"HTTP error for keyword '{keyword}' (page {page}): {e}")
                        break # Encountered an error, stop searching for this keyword
                except requests.exceptions.RequestException as e:
                    logger.error(f"Request error for keyword '{keyword}' (page {page}): {e}")
                    break # Encountered an error, stop searching for this keyword
        
        self.search_cache.set_data(list(self.found_raw_urls)) # 更新缓存
        if not self.found_raw_urls:
            logger.warning("No potential raw file URLs found. Please check GitHub Token, search keywords, or increase max_search_pages.")
        return list(self.found_raw_urls)


# --- 节点提取和验证类 ---
class ProxyExtractor:
    def __init__(self, raw_urls):
        config = Config()
        self.raw_urls = raw_urls
        self.proxy_states_cache = CacheManager(config.get('proxy_states_path'), 'proxy_states_ttl')
        self.proxy_check_timeout = config.get('proxy_check_timeout')
        self.proxy_check_workers = config.get('proxy_check_workers')
        self.channel_extract_workers = config.get('channel_extract_workers')
        self.requests_retry_total = config.get('requests_retry_total')
        self.requests_retry_backoff_factor = config.get('requests_retry_backoff_factor')
        self.requests_pool_size = config.get('requests_pool_size')
        self.output_file = config.get('output_file')

        self.available_proxies = []
        self.lock = threading.Lock() # 用于同步访问 available_proxies

        # 用于存储已解析的节点，以便进行内存去重和避免重复测试
        self.parsed_nodes_cache = set() 
        # 用于存储已测试的URL及其结果，避免重复下载和解析
        self.url_processing_cache = self.proxy_states_cache.get_data() # 从缓存加载

    def _download_content(self, url):
        session = requests.Session()
        retry_strategy = requests.packages.urllib3.util.retry.Retry(
            total=self.requests_retry_total,
            backoff_factor=self.requests_retry_backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods={"HEAD", "GET", "OPTIONS"}
        )
        adapter = requests.adapters.HTTPAdapter(max_retries=retry_strategy, pool_connections=self.requests_pool_size, pool_maxsize=self.requests_pool_size)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        try:
            response = session.get(url, timeout=self.proxy_check_timeout)
            response.raise_for_status() # Raises HTTPError for bad responses (4xx or 5xx)
            return response.text
        except requests.exceptions.RequestException as e:
            logger.warning(f"Failed to download content from {url}: {e}")
            return None

    def _parse_ss(self, link):
        # 尝试解码 SS 链接，处理可能存在的 Base64 编码和 URL 编码
        # 格式: ss://[base64_encoded_info]#[tag]
        try:
            # 移除 ss://
            encoded_part = link[5:]
            
            # 分割 Base64 部分和 Tag 部分
            tag_part = ""
            if "#" in encoded_part:
                encoded_part, tag_part = encoded_part.split("#", 1)
                tag_part = unquote(tag_part) # 解码 Tag

            # Base64 解码，增加对非标准Base64填充的处理
            try:
                missing_padding = len(encoded_part) % 4
                if missing_padding:
                    encoded_part += '='* (4 - missing_padding)
                decoded_info = base64.urlsafe_b64decode(encoded_part).decode('utf-8')
            except (base64.binascii.Error, UnicodeDecodeError) as e:
                # 尝试用 latin-1 解码 Base64，然后强制转换为 UTF-8
                try:
                    decoded_info = base64.urlsafe_b64decode(encoded_part).decode('latin-1').encode('latin-1').decode('utf-8', errors='ignore')
                    logger.debug(f"Attempted non-UTF-8 decoding for SS link {link}")
                except Exception as ex:
                    raise ValueError(f"Base64 decode or UTF-8 conversion error: {e}, {ex}")

            # 解析 decoded_info，格式通常是 method:password@server:port
            parts = decoded_info.split('@')
            if len(parts) != 2:
                raise ValueError("Invalid SS decoded info format: missing @")

            method_password, server_port = parts
            method, password = method_password.split(':', 1)
            server, port = server_port.split(':', 1)

            port = int(port)

            node_data = {
                "protocol": PROTOCOL_TYPE_SS,
                "server": server,
                "port": port,
                "method": method,
                "password": password,
                "tag": tag_part if tag_part else f"{server}:{port}"
            }
            return node_data
        except Exception as e:
            logger.warning(f"Failed to parse SS link '{link}': {e}")
            return None

    def _parse_vmess(self, link):
        # 格式: vmess://[base64_encoded_json]
        try:
            encoded_json = link[8:]
            # Base64 解码，增加对非标准Base64填充的处理
            try:
                missing_padding = len(encoded_json) % 4
                if missing_padding:
                    encoded_json += '='* (4 - missing_padding)
                decoded_json = base64.b64decode(encoded_json).decode('utf-8')
            except (base64.binascii.Error, UnicodeDecodeError) as e:
                # 尝试用 latin-1 解码 Base64，然后强制转换为 UTF-8
                try:
                    decoded_json = base64.b64decode(encoded_json).decode('latin-1').encode('latin-1').decode('utf-8', errors='ignore')
                    logger.debug(f"Attempted non-UTF-8 decoding for VMess link {link}")
                except Exception as ex:
                    raise ValueError(f"Base64 decode or UTF-8 conversion error: {e}, {ex}")

            node_data = json.loads(decoded_json)
            # 统一字段名
            node_data['protocol'] = PROTOCOL_TYPE_VMESS
            node_data['server'] = node_data.pop('add', None)
            node_data['port'] = int(node_data.pop('port', None))
            node_data['uuid'] = node_data.pop('id', None)
            node_data['alterId'] = node_data.pop('aid', 0)
            node_data['security'] = node_data.pop('scy', 'auto') # vmess-aead
            node_data['network'] = node_data.pop('net', 'tcp')
            node_data['type'] = node_data.pop('type', 'none')
            node_data['host'] = node_data.pop('host', '')
            node_data['path'] = node_data.pop('path', '')
            node_data['tls'] = node_data.pop('tls', '')
            node_data['sni'] = node_data.pop('sni', '')
            node_data['tag'] = node_data.pop('ps', f"{node_data['server']}:{node_data['port']}") # 备注名

            # 删除多余字段
            keys_to_remove = ['v', 'ps', 'add', 'port', 'id', 'aid', 'scy', 'net', 'type', 'host', 'path', 'tls', 'sni']
            for key in keys_to_remove:
                node_data.pop(key, None)

            return node_data
        except (json.JSONDecodeError, ValueError) as e:
            logger.warning(f"Failed to parse VMess link '{link}': {e}")
            return None

    def _parse_vless(self, link):
        # 格式: vless://uuid@server:port?params#tag
        try:
            parsed = urlparse(link)
            if not parsed.hostname or not parsed.port:
                raise ValueError("Missing hostname or port")

            uuid_part = parsed.username
            if not uuid_part:
                raise ValueError("Missing UUID")
            
            tag = unquote(parsed.fragment) if parsed.fragment else f"{parsed.hostname}:{parsed.port}"

            node_data = {
                "protocol": PROTOCOL_TYPE_VLESS,
                "server": parsed.hostname,
                "port": parsed.port,
                "uuid": uuid_part,
                "flow": parsed.query.get('flow', [''])[0],
                "security": parsed.query.get('security', [''])[0], # e.g., "tls", "reality"
                "encryption": parsed.query.get('encryption', ['none'])[0],
                "type": parsed.query.get('type', ['tcp'])[0], # network type, e.g. "tcp", "ws", "grpc"
                "host": parsed.query.get('host', [''])[0],
                "path": parsed.query.get('path', [''])[0],
                "sni": parsed.query.get('sni', [''])[0],
                "fp": parsed.query.get('fp', [''])[0], # fingerPrint
                "pbk": parsed.query.get('pbk', [''])[0], # public key for Reality
                "sid": parsed.query.get('sid', [''])[0], # short ID for Reality
                "tag": tag
            }

            # 兼容处理 reality 字段
            if node_data.get('security') == 'reality':
                node_data['protocol'] = PROTOCOL_TYPE_REALITY

            # 从 query string 中解析所有参数
            query_params = {k: v[0] for k, v in parsed.query.items()}
            node_data.update(query_params)
            
            # 清理 URL 解析器可能遗留的额外字段
            keys_to_remove = ['username', 'password', 'hostname', 'fragment', 'query']
            for key in keys_to_remove:
                node_data.pop(key, None)

            return node_data
        except Exception as e:
            logger.warning(f"Failed to parse VLESS link '{link}': {e}")
            return None

    def _parse_trojan(self, link):
        # 格式: trojan://password@server:port?params#tag
        try:
            parsed = urlparse(link)
            if not parsed.hostname or not parsed.port:
                raise ValueError("Missing hostname or port")

            password = parsed.username
            if not password:
                raise ValueError("Missing password")
            
            tag = unquote(parsed.fragment) if parsed.fragment else f"{parsed.hostname}:{parsed.port}"

            node_data = {
                "protocol": PROTOCOL_TYPE_TROJAN,
                "server": parsed.hostname,
                "port": parsed.port,
                "password": password,
                "security": parsed.query.get('security', ['tls'])[0], # e.g., "tls"
                "type": parsed.query.get('type', ['tcp'])[0], # network type, e.g. "tcp", "ws", "grpc"
                "host": parsed.query.get('host', [''])[0],
                "path": parsed.query.get('path', [''])[0],
                "sni": parsed.query.get('sni', [''])[0],
                "alpn": parsed.query.get('alpn', [''])[0],
                "tag": tag
            }

            # 从 query string 中解析所有参数
            query_params = {k: v[0] for k, v in parsed.query.items()}
            node_data.update(query_params)
            
            # 清理 URL 解析器可能遗留的额外字段
            keys_to_remove = ['username', 'password', 'hostname', 'fragment', 'query']
            for key in keys_to_remove:
                node_data.pop(key, None)

            return node_data
        except Exception as e:
            logger.warning(f"Failed to parse Trojan link '{link}': {e}")
            return None

    def _parse_hy2(self, link):
        # 格式: hy2://base64_encoded_config_json 或者 hy2://server:port?params#tag
        try:
            if link.startswith("hy2://"):
                # 尝试解析 URL 格式
                parsed = urlparse(link)
                if parsed.hostname and parsed.port:
                    tag = unquote(parsed.fragment) if parsed.fragment else f"{parsed.hostname}:{parsed.port}"
                    node_data = {
                        "protocol": PROTOCOL_TYPE_HY2,
                        "server": parsed.hostname,
                        "port": parsed.port,
                        "tag": tag
                    }
                    query_params = {k: v[0] for k, v in parsed.query.items()}
                    node_data.update(query_params)
                    return node_data
                
                # 如果不是标准 URL 格式，尝试 Base64 解码 JSON
                encoded_json = link[6:] # 移除 hy2://
                missing_padding = len(encoded_json) % 4
                if missing_padding:
                    encoded_json += '=' * (4 - missing_padding)
                
                try:
                    decoded_json = base64.b64decode(encoded_json).decode('utf-8')
                except (base64.binascii.Error, UnicodeDecodeError):
                    # 尝试用 latin-1 解码 Base64，然后强制转换为 UTF-8
                    decoded_json = base64.b64decode(encoded_json).decode('latin-1').encode('latin-1').decode('utf-8', errors='ignore')
                    logger.debug(f"Attempted non-UTF-8 decoding for Hy2 link {link}")
                
                node_data = json.loads(decoded_json)
                node_data['protocol'] = PROTOCOL_TYPE_HY2
                # 统一字段名 (根据 Hysteria 2 配置结构)
                node_data['server'] = node_data.pop('server', None)
                node_data['port'] = int(node_data.pop('port', None))
                node_data['auth'] = node_data.pop('auth', None)
                node_data['up_mbps'] = node_data.pop('up_mbps', None)
                node_data['down_mbps'] = node_data.pop('down_mbps', None)
                node_data['obfs'] = node_data.pop('obfs', None)
                node_data['obfs_password'] = node_data.pop('obfs_password', None)
                node_data['tag'] = node_data.pop('remark', f"{node_data['server']}:{node_data['port']}") # 备注名
                
                return node_data
        except (json.JSONDecodeError, ValueError) as e:
            logger.warning(f"Failed to parse Hy2 link '{link}': {e}")
            return None

    def _parse_tuic(self, link):
        # 格式: tuic://[uuid]:[password]@[server]:[port]
        # 或者更复杂的带参数
        try:
            parsed = urlparse(link)
            if not parsed.hostname or not parsed.port:
                raise ValueError("Missing hostname or port")

            # TUIC 链接的用户名部分通常是 UUID，密码部分是密码
            uuid_pass = parsed.username
            if uuid_pass:
                uuid_parts = uuid_pass.split(':', 1)
                uuid = uuid_parts[0]
                password = uuid_parts[1] if len(uuid_parts) > 1 else ''
            else:
                uuid = ''
                password = ''
            
            tag = unquote(parsed.fragment) if parsed.fragment else f"{parsed.hostname}:{parsed.port}"

            node_data = {
                "protocol": PROTOCOL_TYPE_TUIC,
                "server": parsed.hostname,
                "port": parsed.port,
                "uuid": uuid,
                "password": password,
                "tag": tag
            }
            # 解析所有查询参数
            query_params = {k: v[0] for k, v in parsed.query.items()}
            node_data.update(query_params)

            return node_data
        except Exception as e:
            logger.warning(f"Failed to parse TUIC link '{link}': {e}")
            return None

    def _parse_wireguard(self, link):
        # WireGuard 链接通常是 wg://[base64_encoded_config] 或包含 Endpoint 的直接 URL
        # 简单处理，如果直接是wg://链接，我们假设其Base64编码了配置
        try:
            if link.startswith("wg://"):
                encoded_config = link[5:]
                missing_padding = len(encoded_config) % 4
                if missing_padding:
                    encoded_config += '=' * (4 - missing_padding)
                
                try:
                    decoded_config = base64.b64decode(encoded_config).decode('utf-8')
                except (base64.binascii.Error, UnicodeDecodeError):
                    decoded_config = base64.b64decode(encoded_config).decode('latin-1').encode('latin-1').decode('utf-8', errors='ignore')
                    logger.debug(f"Attempted non-UTF-8 decoding for WG link {link}")
                
                # 尝试解析 WireGuard 配置，这里简化处理，只标记为WG类型
                # 实际的WireGuard配置解析更复杂，需要提取PublicKey, PrivateKey, Endpoint等
                if "Endpoint" in decoded_config and "PublicKey" in decoded_config:
                    return {
                        "protocol": PROTOCOL_TYPE_WG,
                        "config": decoded_config, # 完整的 WireGuard 配置内容
                        "tag": "WireGuard Node (from wg://)"
                    }
            # 也可以尝试直接从文件中提取 .conf 内容
            elif link.endswith(".conf"):
                # 如果是 .conf 文件，下载后直接作为 WireGuard 配置处理
                return {
                    "protocol": PROTOCOL_TYPE_WG,
                    "url": link, # 记录原始URL，可能需要下载后处理
                    "tag": "WireGuard Config File"
                }
            return None
        except Exception as e:
            logger.warning(f"Failed to parse WireGuard link '{link}': {e}")
            return None

    def _parse_warp(self, link):
        # Cloudflare Warp 通常是 wgcf:// 或直接是一个 WARP URL
        try:
            if link.startswith("warp://") or link.startswith("wgcf://"):
                # 这里只进行简单识别，不深入解析 WARP 配置
                # WARP 配置通常需要特定的客户端工具来导入
                return {
                    "protocol": PROTOCOL_TYPE_WARP,
                    "link": link,
                    "tag": "Cloudflare WARP Node"
                }
            return None
        except Exception as e:
            logger.warning(f"Failed to parse WARP link '{link}': {e}")
            return None

    def _parse_shadow_tls(self, link):
        # shadow-tls://[host]:[port]?password=[password]&sni=[sni]
        try:
            parsed = urlparse(link)
            if not parsed.hostname or not parsed.port:
                raise ValueError("Missing hostname or port")
            
            tag = unquote(parsed.fragment) if parsed.fragment else f"{parsed.hostname}:{parsed.port}"

            node_data = {
                "protocol": PROTOCOL_TYPE_SHADOW_TLS,
                "server": parsed.hostname,
                "port": parsed.port,
                "password": parsed.query.get('password', [''])[0],
                "sni": parsed.query.get('sni', [''])[0],
                "tag": tag
            }
            return node_data
        except Exception as e:
            logger.warning(f"Failed to parse Shadow-TLS link '{link}': {e}")
            return None

    def _extract_nodes_from_content(self, content):
        nodes = []
        # SS 链接
        ss_links = re.findall(r'ss://[a-zA-Z0-9%_-]+(?:=|==)?(?:#.+)?', content)
        for link in ss_links:
            node = self._parse_ss(link)
            if node:
                nodes.append(node)

        # VMess 链接
        vmess_links = re.findall(r'vmess://[a-zA-Z0-9+/=]+', content)
        for link in vmess_links:
            node = self._parse_vmess(link)
            if node:
                nodes.append(node)
        
        # VLESS 链接
        vless_links = re.findall(r'vless://[a-zA-Z0-9\-]+@[a-zA-Z0-9\.\-]+:\d+(\?.+)?(#.+)?', content)
        for link in vless_links:
            node = self._parse_vless(link)
            if node:
                nodes.append(node)

        # Trojan 链接
        trojan_links = re.findall(r'trojan://[a-zA-Z0-9\-\._~]+@[a-zA-Z0-9\.\-]+:\d+(\?.+)?(#.+)?', content)
        for link in trojan_links:
            node = self._parse_trojan(link)
            if node:
                nodes.append(node)
        
        # Hysteria2 (Hy2) 链接
        # 两种格式：hy2://base64_json 和 hy2://server:port
        hy2_links_b64 = re.findall(r'hy2://[a-zA-Z0-9+/=]+', content)
        hy2_links_url = re.findall(r'hy2://[a-zA-Z0-9\.\-]+:\d+(\?.+)?(#.+)?', content)
        for link in hy2_links_b64 + hy2_links_url:
            node = self._parse_hy2(link)
            if node:
                nodes.append(node)
        
        # Reality 链接 (VLESS with security=reality)
        # Reality 链接是 VLESS 的子集，VLESS 解析器已经处理了，这里不需要单独的正则

        # Tuic 链接
        tuic_links = re.findall(r'tuic://[a-zA-Z0-9\-\._~:]+@[a-zA-Z0-9\.\-]+:\d+(\?.+)?(#.+)?', content)
        for link in tuic_links:
            node = self._parse_tuic(link)
            if node:
                nodes.append(node)

        # WireGuard (wg) 链接
        # wg://[base64_encoded_config] 或直接提及 .conf 文件
        wg_links = re.findall(r'wg://[a-zA-Z0-9+/=]+', content)
        for link in wg_links:
            node = self._parse_wireguard(link)
            if node:
                nodes.append(node)
        
        # Cloudflare Warp (warp) 链接
        warp_links = re.findall(r'warp://[a-zA-Z0-9+/=]+', content)
        for link in warp_links:
            node = self._parse_warp(link)
            if node:
                nodes.append(node)

        # Shadow-TLS 链接
        shadow_tls_links = re.findall(r'shadow-tls://[a-zA-Z0-9\.\-]+:\d+\?password=[a-zA-Z0-9]+&sni=[a-zA-Z0-9\.\-]+', content)
        for link in shadow_tls_links:
            node = self._parse_shadow_tls(link)
            if node:
                nodes.append(node)

        return nodes

    def _process_url(self, url):
        # 检查 URL 是否在缓存中且未过期
        if self.proxy_states_cache.is_cache_valid() and url in self.url_processing_cache:
            status = self.url_processing_cache[url].get("status")
            if status == "success":
                # 如果 URL 之前成功解析过，可以尝试从缓存中获取节点信息
                # 但为了确保最新，这里选择重新解析
                logger.debug(f"URL {url} found in valid cache, but re-processing for latest nodes.")
            elif status == "failed":
                logger.debug(f"URL {url} found in valid cache and previously failed. Skipping.")
                return

        content = self._download_content(url)
        if not content:
            self.url_processing_cache[url] = {"status": "failed", "timestamp": int(time.time())}
            return

        parsed_nodes = self._extract_nodes_from_content(content)
        newly_added_count = 0
        with self.lock:
            for node in parsed_nodes:
                # 将节点数据转换为可哈希的字符串进行去重
                node_str = json.dumps(node, sort_keys=True)
                if node_str not in self.parsed_nodes_cache:
                    self.parsed_nodes_cache.add(node_str)
                    self.available_proxies.append(node)
                    newly_added_count += 1
        
        if newly_added_count > 0:
            logger.info(f"Extracted {newly_added_count} new nodes from {url}. Total unique nodes: {len(self.available_proxies)}")
            self.url_processing_cache[url] = {"status": "success", "timestamp": int(time.time()), "nodes_count": newly_added_count}
        else:
            logger.debug(f"No new nodes extracted from {url}.")
            self.url_processing_cache[url] = {"status": "success", "timestamp": int(time.time()), "nodes_count": 0} # 即使没有新节点也标记成功处理

    def extract_and_verify_proxies(self):
        logger.info(f"Starting to extract and verify proxies from {len(self.raw_urls)} URLs.")
        
        # 使用 ThreadPoolExecutor 并发下载和初步解析
        with ThreadPoolExecutor(max_workers=self.channel_extract_workers) as executor:
            list(executor.map(self._process_url, self.raw_urls)) # list() ensures all futures complete

        logger.info(f"Finished extracting. Total unique nodes found: {len(self.available_proxies)}")
        
        # 刷新URL处理状态缓存
        self.proxy_states_cache.set_data(self.url_processing_cache)

        # 节点可用性测试 (这里仅作占位，实际需要更复杂的测试逻辑)
        # For simplicity, we'll assume all extracted nodes are "available" for now,
        # but in a real scenario, you'd implement actual connection tests here.
        # This part could also be multithreaded using self.proxy_check_workers
        
        # 模拟可用性测试结果：所有成功解析的节点都视为可用
        final_available_proxies = []
        for node in self.available_proxies:
            # 实际的可用性测试代码会在这里
            # 例如：
            # if self._test_proxy_connection(node):
            #     final_available_proxies.append(node)
            # else:
            #     logger.debug(f"Proxy {node.get('tag', node.get('server'))} is not available.")
            
            # 目前简化为所有解析成功的都放入最终列表
            final_available_proxies.append(node)

        self._save_proxies_to_file(final_available_proxies)
        logger.info(f"Saved {len(final_available_proxies)} available proxies to {self.output_file}")


    def _save_proxies_to_file(self, proxies):
        # 将解析后的节点以可读的格式保存到文件
        # 可以根据需要选择保存为 Clash YAML, V2RayN JSON 等格式
        # 这里为了演示，简单地保存为每行一个链接或基本信息
        
        # 示例：保存为文本文件，每行一个可用的链接（如果能构建）或基本信息
        # 对于不同协议，可能需要不同的输出格式
        with open(self.output_file, 'w', encoding='utf-8') as f:
            for proxy in proxies:
                line = ""
                proto = proxy.get('protocol')
                server = proxy.get('server', 'N/A')
                port = proxy.get('port', 'N/A')
                tag = proxy.get('tag', 'N/A')

                if proto == PROTOCOL_TYPE_SS:
                    line = f"ss://... (SS) {server}:{port} - {tag}" # 实际应是完整的SS链接
                elif proto == PROTOCOL_TYPE_VMESS:
                    line = f"vmess://... (VMess) {server}:{port} - {tag}" # 实际应是完整的VMess链接
                elif proto == PROTOCOL_TYPE_VLESS:
                    line = f"vless://... (VLESS) {server}:{port} - {tag}"
                elif proto == PROTOCOL_TYPE_HY2:
                    line = f"hy2://... (Hysteria2) {server}:{port} - {tag}"
                elif proto == PROTOCOL_TYPE_TROJAN:
                    line = f"trojan://... (Trojan) {server}:{port} - {tag}"
                elif proto == PROTOCOL_TYPE_REALITY:
                    line = f"reality://... (Reality) {server}:{port} - {tag}"
                elif proto == PROTOCOL_TYPE_TUIC:
                    line = f"tuic://... (Tuic) {server}:{port} - {tag}"
                elif proto == PROTOCOL_TYPE_WG:
                    line = f"wg://... (WireGuard) - {tag}"
                elif proto == PROTOCOL_TYPE_WARP:
                    line = f"warp://... (WARP) - {tag}"
                elif proto == PROTOCOL_TYPE_SHADOW_TLS:
                    line = f"shadow-tls://... (Shadow-TLS) {server}:{port} - {tag}"
                
                if line:
                    f.write(line + "\n")
                else:
                    f.write(json.dumps(proxy, ensure_ascii=False) + "\n") # 对于无法转换为链接的，直接保存JSON

        logger.info(f"Available proxies saved to {self.output_file}")

    def _test_proxy_connection(self, proxy_info):
        """
        占位函数：实际的代理可用性测试逻辑将在这里实现。
        这会涉及连接到代理服务器并尝试访问一个公共网站。
        对于不同的协议，测试方法不同。
        """
        # 例如，可以尝试使用 socket 连接到服务器的端口
        server = proxy_info.get('server')
        port = proxy_info.get('port')
        protocol = proxy_info.get('protocol')

        if not server or not port:
            return False

        try:
            # 简单的 TCP 连接测试
            s = socket.create_connection((server, port), timeout=self.proxy_check_timeout)
            s.close()
            logger.debug(f"Proxy {protocol}://{server}:{port} is connectable.")
            return True
        except Exception as e:
            logger.debug(f"Proxy {protocol}://{server}:{port} connection failed: {e}")
            return False

# --- 主函数 ---
def main():
    config_instance = Config() # 加载配置
    
    # 搜索 GitHub 获取原始文件 URL
    searcher = GitHubSearcher()
    raw_urls = searcher.search_github()

    if raw_urls:
        # 从原始 URL 中提取并验证代理节点
        extractor = ProxyExtractor(raw_urls)
        extractor.extract_and_verify_proxies()
    else:
        logger.info("No raw URLs found for proxy extraction.")

if __name__ == "__main__":
    import os
    main()
