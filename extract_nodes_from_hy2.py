import base64
import json
import logging
import re
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import unquote, urlparse, parse_qs

import requests
import yaml
import os

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
        self.lock = threading.Lock()

    def _load_cache(self):
        try:
            with open(self.cache_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {"timestamp": 0, "data": {}}

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
            return False

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
        self.headers = {
            'Authorization': f'token {self.github_token}',
            'Accept': 'application/vnd.github.v3+json'
        } if self.github_token else {'Accept': 'application/vnd.github.v3+json'}
        self.base_url = "https://api.github.com/search/code"

        self.found_raw_urls = set()
        self.lock = threading.Lock()

    def _get_github_token(self):
        token = os.getenv('GITHUB_TOKEN') or os.getenv('BOT')
        if token:
            logger.info(f"GitHub Token loaded from environment variable {'GITHUB_TOKEN' if os.getenv('GITHUB_TOKEN') else 'BOT'}.")
            return token
        else:
            logger.error("GitHub Token not found in GITHUB_TOKEN or BOT environment variables. Please set one.")
            sys.exit(1)
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
                wait_time = max(self.github_api_retry_wait, reset_time - int(time.time()) + 5)
                logger.warning(f"GitHub API rate limit hit, {remaining} remaining. Waiting for {wait_time:.1f} seconds.")
                time.sleep(wait_time)
                return True
            return False
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 403:
                logger.error(f"GitHub API 403 Forbidden: {e.response.text}")
                return True
            logger.error(f"Error checking GitHub API rate limit: {e}")
            return False
        except requests.exceptions.RequestException as e:
            logger.error(f"Error checking GitHub API rate limit: {e}")
            return False

    def search_github(self):
        if self.search_cache.is_cache_valid():
            self.found_raw_urls = set(self.search_cache.get_data())
            logger.info(f"Loaded search cache with {len(self.found_raw_urls)} entries.")
            if self.found_raw_urls:
                return list(self.found_raw_urls)

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

                if self._check_rate_limit(session):
                    continue

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
                        html_url = item.get('html_url')
                        if html_url and "github.com" in html_url and "/blob/" in html_url:
                            raw_url = html_url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
                            current_page_urls.add(raw_url)
                        else:
                            logger.debug(f"No valid html_url in item: {json.dumps(item, indent=2)}")

                    with self.lock:
                        self.found_raw_urls.update(current_page_urls)
                    logger.info(f"Found {len(items)} items, extracted {len(current_page_urls)} raw URLs for '{keyword}' (page {page}). Total collected: {len(self.found_raw_urls)}")

                    if len(items) < self.per_page:
                        logger.info(f"Less than {self.per_page} items on page {page}, assuming last page for '{keyword}'.")
                        break

                except requests.exceptions.HTTPError as e:
                    if hasattr(e, 'response') and e.response.status_code == 401:
                        logger.error("GitHub API authentication failed (401 Unauthorized). Please verify GITHUB_TOKEN or BOT.")
                        sys.exit(1)
                    elif hasattr(e, 'response') and e.response.status_code == 403:
                        logger.warning(f"GitHub API 403 Forbidden for keyword '{keyword}' (page {page}): {e.response.text}")
                        if 'rate limit' in e.response.text.lower():
                            self._check_rate_limit(session)
                        else:
                            break
                    else:
                        logger.error(f"HTTP error for keyword '{keyword}' (page {page}): {e}")
                        break
                except requests.exceptions.RequestException as e:
                    logger.error(f"Request error for keyword '{keyword}' (page {page}): {e}")
                    break
        
        self.search_cache.set_data(list(self.found_raw_urls))
        if not self.found_raw_urls:
            logger.warning("No potential raw file URLs found from GitHub. Will check data/hy2.txt as fallback.")
        return list(self.found_raw_urls)

# --- 节点提取和验证类 ---
class ProxyExtractor:
    def __init__(self, raw_urls, initial_nodes=None):
        config = Config()
        self.raw_urls = raw_urls
        self.initial_nodes = initial_nodes or []  # 从 data/hy2.txt 加载的直接节点
        self.proxy_states_cache = CacheManager(config.get('proxy_states_path'), 'proxy_states_ttl')
        self.proxy_check_timeout = config.get('proxy_check_timeout')
        self.proxy_check_workers = config.get('proxy_check_workers')
        self.channel_extract_workers = config.get('channel_extract_workers')
        self.requests_retry_total = config.get('requests_retry_total')
        self.requests_retry_backoff_factor = config.get('requests_retry_backoff_factor')
        self.requests_pool_size = config.get('requests_pool_size')
        self.output_file = config.get('output_file')

        self.available_proxies = []  # 存储所有可用的代理节点
        self.lock = threading.Lock()
        self.parsed_nodes_cache = set()  # 去重缓存
        self.url_processing_cache = self.proxy_states_cache.get_data()

    def load_hy2_txt(self):
        """
        从 data/hy2.txt 加载 URL 或代理链接，区分 URL 和节点。
        """
        try:
            with open('data/hy2.txt', 'r', encoding='utf-8') as f:
                lines = [line.strip() for line in f if line.strip()]
            urls = []
            nodes = []
            for line in lines:
                if line.startswith(('ss://', 'vmess://', 'vless://', 'trojan://', 'hy2://', 'tuic://', 'wg://', 'warp://', 'shadow-tls://')):
                    node = self._parse_node(line)
                    if node:
                        nodes.append(node)
                elif line.startswith(('http://', 'https://')):
                    urls.append(line)
                else:
                    logger.debug(f"Ignoring invalid line in data/hy2.txt: {line}")
            logger.info(f"Loaded {len(urls)} URLs and {len(nodes)} nodes from data/hy2.txt")
            return urls, nodes
        except FileNotFoundError:
            logger.error("File data/hy2.txt not found")
            return [], []

    def _download_content(self, url):
        """
        下载 URL 内容。
        """
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
            response.raise_for_status()
            return response.text
        except requests.exceptions.RequestException as e:
            logger.warning(f"Failed to download content from {url}: {e}")
            return None

    def _parse_node(self, link):
        """
        解析单条代理链接，调用对应协议的解析方法。
        """
        if link.startswith("ss://"):
            return self._parse_ss(link)
        elif link.startswith("vmess://"):
            return self._parse_vmess(link)
        elif link.startswith("vless://"):
            return self._parse_vless(link)
        elif link.startswith("trojan://"):
            return self._parse_trojan(link)
        elif link.startswith("hy2://"):
            return self._parse_hy2(link)
        elif link.startswith("tuic://"):
            return self._parse_tuic(link)
        elif link.startswith("wg://"):
            return self._parse_wireguard(link)
        elif link.startswith("warp://"):
            return self._parse_warp(link)
        elif link.startswith("shadow-tls://"):
            return self._parse_shadow_tls(link)
        return None

    def _parse_ss(self, link):
        try:
            encoded_part = link[5:]
            tag_part = ""
            if "#" in encoded_part:
                encoded_part, tag_part = encoded_part.split("#", 1)
                tag_part = unquote(tag_part)

            try:
                missing_padding = len(encoded_part) % 4
                if missing_padding:
                    encoded_part += '=' * (4 - missing_padding)
                decoded_info = base64.urlsafe_b64decode(encoded_part).decode('utf-8')
            except (base64.binascii.Error, UnicodeDecodeError) as e:
                try:
                    decoded_info = base64.urlsafe_b64decode(encoded_part).decode('latin-1').encode('latin-1').decode('utf-8', errors='ignore')
                    logger.debug(f"Attempted non-UTF-8 decoding for SS link {link}")
                except Exception as ex:
                    raise ValueError(f"Base64 decode or UTF-8 conversion error: {e}, {ex}")

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
        try:
            encoded_json = link[8:]
            try:
                missing_padding = len(encoded_json) % 4
                if missing_padding:
                    encoded_json += '=' * (4 - missing_padding)
                decoded_json = base64.b64decode(encoded_json).decode('utf-8')
            except (base64.binascii.Error, UnicodeDecodeError) as e:
                try:
                    decoded_json = base64.b64decode(encoded_json).decode('latin-1').encode('latin-1').decode('utf-8', errors='ignore')
                    logger.debug(f"Attempted non-UTF-8 decoding for VMess link {link}")
                except Exception as ex:
                    raise ValueError(f"Base64 decode or UTF-8 conversion error: {e}, {ex}")

            node_data = json.loads(decoded_json)
            node_data['protocol'] = PROTOCOL_TYPE_VMESS
            node_data['server'] = node_data.pop('add', None)
            node_data['port'] = int(node_data.pop('port', None))
            node_data['uuid'] = node_data.pop('id', None)
            node_data['alterId'] = node_data.pop('aid', 0)
            node_data['security'] = node_data.pop('scy', 'auto')
            node_data['network'] = node_data.pop('net', 'tcp')
            node_data['type'] = node_data.pop('type', 'none')
            node_data['host'] = node_data.pop('host', '')
            node_data['path'] = node_data.pop('path', '')
            node_data['tls'] = node_data.pop('tls', '')
            node_data['sni'] = node_data.pop('sni', '')
            node_data['tag'] = node_data.pop('ps', f"{node_data['server']}:{node_data['port']}")

            keys_to_remove = ['v', 'ps', 'add', 'port', 'id', 'aid', 'scy', 'net', 'type', 'host', 'path', 'tls', 'sni']
            for key in keys_to_remove:
                node_data.pop(key, None)

            return node_data
        except (json.JSONDecodeError, ValueError) as e:
            logger.warning(f"Failed to parse VMess link '{link}': {e}")
            return None

    def _parse_vless(self, link):
        try:
            parsed = urlparse(link)
            if not parsed.hostname or not parsed.port:
                raise ValueError("Missing hostname or port")

            uuid_part = parsed.username
            if not uuid_part:
                raise ValueError("Missing UUID")
            
            tag = unquote(parsed.fragment) if parsed.fragment else f"{parsed.hostname}:{parsed.port}"

            query_params = parse_qs(parsed.query)
            node_data = {
                "protocol": PROTOCOL_TYPE_VLESS,
                "server": parsed.hostname,
                "port": parsed.port,
                "uuid": uuid_part,
                "flow": query_params.get('flow', [''])[0],
                "security": query_params.get('security', [''])[0],
                "encryption": query_params.get('encryption', ['none'])[0],
                "type": query_params.get('type', ['tcp'])[0],
                "host": query_params.get('host', [''])[0],
                "path": query_params.get('path', [''])[0],
                "sni": query_params.get('sni', [''])[0],
                "fp": query_params.get('fp', [''])[0],
                "pbk": query_params.get('pbk', [''])[0],
                "sid": query_params.get('sid', [''])[0],
                "tag": tag
            }

            if node_data.get('security') == 'reality':
                node_data['protocol'] = PROTOCOL_TYPE_REALITY

            return node_data
        except Exception as e:
            logger.warning(f"Failed to parse VLESS link '{link}': {e}")
            return None

    def _parse_trojan(self, link):
        try:
            parsed = urlparse(link)
            if not parsed.hostname or not parsed.port:
                raise ValueError("Missing hostname or port")

            password = parsed.username
            if not password:
                raise ValueError("Missing password")
            
            tag = unquote(parsed.fragment) if parsed.fragment else f"{parsed.hostname}:{parsed.port}"

            query_params = parse_qs(parsed.query)
            node_data = {
                "protocol": PROTOCOL_TYPE_TROJAN,
                "server": parsed.hostname,
                "port": parsed.port,
                "password": password,
                "security": query_params.get('security', ['tls'])[0],
                "type": query_params.get('type', ['tcp'])[0],
                "host": query_params.get('host', [''])[0],
                "path": query_params.get('path', [''])[0],
                "sni": query_params.get('sni', [''])[0],
                "alpn": query_params.get('alpn', [''])[0],
                "tag": tag
            }
            return node_data
        except Exception as e:
            logger.warning(f"Failed to parse Trojan link '{link}': {e}")
            return None

    def _parse_hy2(self, link):
        try:
            if link.startswith("hy2://"):
                parsed = urlparse(link)
                if parsed.hostname and parsed.port:
                    tag = unquote(parsed.fragment) if parsed.fragment else f"{parsed.hostname}:{parsed.port}"
                    query_params = parse_qs(parsed.query)
                    node_data = {
                        "protocol": PROTOCOL_TYPE_HY2,
                        "server": parsed.hostname,
                        "port": parsed.port,
                        "tag": tag
                    }
                    node_data.update({k: v[0] for k, v in query_params.items()})
                    return node_data
                
                encoded_json = link[6:]
                missing_padding = len(encoded_json) % 4
                if missing_padding:
                    encoded_json += '=' * (4 - missing_padding)
                
                try:
                    decoded_json = base64.b64decode(encoded_json).decode('utf-8')
                except (base64.binascii.Error, UnicodeDecodeError):
                    decoded_json = base64.b64decode(encoded_json).decode('latin-1').encode('latin-1').decode('utf-8', errors='ignore')
                    logger.debug(f"Attempted non-UTF-8 decoding for Hy2 link {link}")
                
                node_data = json.loads(decoded_json)
                node_data['protocol'] = PROTOCOL_TYPE_HY2
                node_data['server'] = node_data.pop('server', None)
                node_data['port'] = int(node_data.pop('port', None))
                node_data['auth'] = node_data.pop('auth', None)
                node_data['up_mbps'] = node_data.pop('up_mbps', None)
                node_data['down_mbps'] = node_data.pop('down_mbps', None)
                node_data['obfs'] = node_data.pop('obfs', None)
                node_data['obfs_password'] = node_data.pop('obfs_password', None)
                node_data['tag'] = node_data.pop('remark', f"{node_data['server']}:{node_data['port']}")
                
                return node_data
        except (json.JSONDecodeError, ValueError) as e:
            logger.warning(f"Failed to parse Hy2 link '{link}': {e}")
            return None

    def _parse_tuic(self, link):
        try:
            parsed = urlparse(link)
            if not parsed.hostname or not parsed.port:
                raise ValueError("Missing hostname or port")

            uuid_pass = parsed.username
            if uuid_pass:
                uuid_parts = uuid_pass.split(':', 1)
                uuid = uuid_parts[0]
                password = uuid_parts[1] if len(uuid_parts) > 1 else ''
            else:
                uuid = ''
                password = ''
            
            tag = unquote(parsed.fragment) if parsed.fragment else f"{parsed.hostname}:{parsed.port}"

            query_params = parse_qs(parsed.query)
            node_data = {
                "protocol": PROTOCOL_TYPE_TUIC,
                "server": parsed.hostname,
                "port": parsed.port,
                "uuid": uuid,
                "password": password,
                "tag": tag
            }
            node_data.update({k: v[0] for k, v in query_params.items()})
            return node_data
        except Exception as e:
            logger.warning(f"Failed to parse TUIC link '{link}': {e}")
            return None

    def _parse_wireguard(self, link):
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
                
                if "Endpoint" in decoded_config and "PublicKey" in decoded_config:
                    return {
                        "protocol": PROTOCOL_TYPE_WG,
                        "config": decoded_config,
                        "tag": "WireGuard Node (from wg://)"
                    }
            elif link.endswith(".conf"):
                return {
                    "protocol": PROTOCOL_TYPE_WG,
                    "url": link,
                    "tag": "WireGuard Config File"
                }
            return None
        except Exception as e:
            logger.warning(f"Failed to parse WireGuard link '{link}': {e}")
            return None

    def _parse_warp(self, link):
        try:
            if link.startswith("warp://") or link.startswith("wgcf://"):
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
        try:
            parsed = urlparse(link)
            if not parsed.hostname or not parsed.port:
                raise ValueError("Missing hostname or port")
            
            tag = unquote(parsed.fragment) if parsed.fragment else f"{parsed.hostname}:{parsed.port}"

            query_params = parse_qs(parsed.query)
            node_data = {
                "protocol": PROTOCOL_TYPE_SHADOW_TLS,
                "server": parsed.hostname,
                "port": parsed.port,
                "password": query_params.get('password', [''])[0],
                "sni": query_params.get('sni', [''])[0],
                "tag": tag
            }
            return node_data
        except Exception as e:
            logger.warning(f"Failed to parse Shadow-TLS link '{link}': {e}")
            return None

    def _extract_nodes_from_content(self, content):
        """
        从下载的内容中提取代理节点。
        """
        nodes = []
        if not content:
            return nodes

        ss_links = re.findall(r'ss://[a-zA-Z0-9%_-]+(?:=|==)?(?:#.+)?', content)
        for link in ss_links:
            node = self._parse_ss(link)
            if node:
                nodes.append(node)

        vmess_links = re.findall(r'vmess://[a-zA-Z0-9+/=]+', content)
        for link in vmess_links:
            node = self._parse_vmess(link)
            if node:
                nodes.append(node)
        
        vless_links = re.findall(r'vless://[a-zA-Z0-9\-]+@[a-zA-Z0-9\.\-]+:\d+(\?.+)?(#.+)?', content)
        for link in vless_links:
            node = self._parse_vless(link)
            if node:
                nodes.append(node)

        trojan_links = re.findall(r'trojan://[a-zA-Z0-9\-\._~]+@[a-zA-Z0-9\.\-]+:\d+(\?.+)?(#.+)?', content)
        for link in trojan_links:
            node = self._parse_trojan(link)
            if node:
                nodes.append(node)
        
        hy2_links_b64 = re.findall(r'hy2://[a-zA-Z0-9+/=]+', content)
        hy2_links_url = re.findall(r'hy2://[a-zA-Z0-9\.\-]+:\d+(\?.+)?(#.+)?', content)
        for link in hy2_links_b64 + hy2_links_url:
            node = self._parse_hy2(link)
            if node:
                nodes.append(node)
        
        tuic_links = re.findall(r'tuic://[a-zA-Z0-9\-\._~:]+@[a-zA-Z0-9\.\-]+:\d+(\?.+)?(#.+)?', content)
        for link in tuic_links:
            node = self._parse_tuic(link)
            if node:
                nodes.append(node)

        wg_links = re.findall(r'wg://[a-zA-Z0-9+/=]+', content)
        for link in wg_links:
            node = self._parse_wireguard(link)
            if node:
                nodes.append(node)
        
        warp_links = re.findall(r'warp://[a-zA-Z0-9+/=]+', content)
        for link in warp_links:
            node = self._parse_warp(link)
            if node:
                nodes.append(node)

        shadow_tls_links = re.findall(r'shadow-tls://[a-zA-Z0-9\.\-]+:\d+\?password=[a-zA-Z0-9]+&sni=[a-zA-Z0-9\.\-]+', content)
        for link in shadow_tls_links:
            node = self._parse_shadow_tls(link)
            if node:
                nodes.append(node)

        return nodes

    def _process_url(self, url):
        """
        处理单个 URL，下载内容并提取节点。
        """
        if self.proxy_states_cache.is_cache_valid() and url in self.url_processing_cache:
            status = self.url_processing_cache[url].get("status")
            if status == "failed":
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
            self.url_processing_cache[url] = {"status": "success", "timestamp": int(time.time()), "nodes_count": 0}

    def extract_and_verify_proxies(self):
        """
        从 URL 和初始节点中提取并验证代理。
        """
        logger.info(f"Starting to extract and verify proxies from {len(self.raw_urls)} URLs and {len(self.initial_nodes)} initial nodes.")

        # 先添加初始节点（从 data/hy2.txt 直接解析的节点）
        with self.lock:
            for node in self.initial_nodes:
                node_str = json.dumps(node, sort_keys=True)
                if node_str not in self.parsed_nodes_cache:
                    self.parsed_nodes_cache.add(node_str)
                    self.available_proxies.append(node)
            logger.info(f"Added {len(self.initial_nodes)} nodes from data/hy2.txt. Total unique nodes: {len(self.available_proxies)}")

        # 处理 URL
        with ThreadPoolExecutor(max_workers=self.channel_extract_workers) as executor:
            list(executor.map(self._process_url, self.raw_urls))

        logger.info(f"Finished extracting. Total unique nodes found: {len(self.available_proxies)}")
        
        self.proxy_states_cache.set_data(self.url_processing_cache)

        # 验证节点可用性
        final_available_proxies = []
        for node in self.available_proxies:
            if self._test_proxy_connection(node):
                final_available_proxies.append(node)

        self._save_proxies_to_file(final_available_proxies)
        logger.info(f"Saved {len(final_available_proxies)} available proxies to {self.output_file}")

    def _save_proxies_to_file(self, proxies):
        """
        将可用代理保存到文件。
        """
        with open(self.output_file, 'w', encoding='utf-8') as f:
            for proxy in proxies:
                line = ""
                proto = proxy.get('protocol')
                server = proxy.get('server', 'N/A')
                port = proxy.get('port', 'N/A')
                tag = proxy.get('tag', 'N/A')

                if proto == PROTOCOL_TYPE_SS:
                    line = f"ss://... (SS) {server}:{port} - {tag}"
                elif proto == PROTOCOL_TYPE_VMESS:
                    line = f"vmess://... (VMess) {server}:{port} - {tag}"
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
                    f.write(json.dumps(proxy, ensure_ascii=False) + "\n")

        logger.info(f"Available proxies saved to {self.output_file}")

    def _test_proxy_connection(self, proxy_info):
        """
        测试代理节点的 TCP 连接。
        """
        server = proxy_info.get('server')
        port = proxy_info.get('port')
        protocol = proxy_info.get('protocol')

        if not server or not port:
            return False

        try:
            s = socket.create_connection((server, port), timeout=self.proxy_check_timeout)
            s.close()
            logger.debug(f"Proxy {protocol}://{server}:{port} is connectable.")
            return True
        except Exception as e:
            logger.debug(f"Proxy {protocol}://{server}:{port} connection failed: {e}")
            return False

# --- 主函数 ---
def main():
    config_instance = Config()
    
    searcher = GitHubSearcher()
    raw_urls = searcher.search_github()

    # 如果 GitHub 搜索无结果，尝试加载 data/hy2.txt
    if not raw_urls:
        logger.info("No raw URLs found from GitHub, attempting to load from data/hy2.txt")
        extractor = ProxyExtractor([], [])
        raw_urls, initial_nodes = extractor.load_hy2_txt()
    else:
        initial_nodes = []
        logger.info(f"Found {len(raw_urls)} raw URLs from GitHub.")

    # 即使有 GitHub URL，也尝试加载 data/hy2.txt 以补充
    extractor = ProxyExtractor(raw_urls, initial_nodes)
    hy2_urls, hy2_nodes = extractor.load_hy2_txt()
    raw_urls.extend(hy2_urls)
    initial_nodes.extend(hy2_nodes)

    if not raw_urls and not initial_nodes:
        logger.info("No raw URLs or nodes found from GitHub or data/hy2.txt.")
        return

    logger.info(f"Processing {len(raw_urls)} URLs and {len(initial_nodes)} nodes.")
    extractor.extract_and_verify_proxies()

if __name__ == "__main__":
    main()
