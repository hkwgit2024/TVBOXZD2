import requests
import base64
import json
import yaml
import time
import re
import socket
import logging
from urllib.parse import urlparse, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- 配置加载 ---
CONFIG = {}
logger = logging.getLogger(__name__)

def load_config(config_path="config/config_proxy.yaml"):
    global CONFIG
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            CONFIG = yaml.safe_load(f)
        logging.basicConfig(level=getattr(logging, CONFIG.get('log_level', 'INFO').upper()),
                            format='%(asctime)s - %(levelname)s - %(message)s')
        logger.info(f"配置加载成功：{config_path}")
    except FileNotFoundError:
        logger.error(f"配置文件未找到：{config_path}，请创建它。")
        exit(1)
    except yaml.YAMLError as e:
        logger.error(f"配置文件解析错误：{e}")
        exit(1)

# --- GitHub 搜索模块 (与原tv.py类似) ---
class GitHubSearcher:
    def __init__(self):
        self.headers = {'Accept': 'application/vnd.github.v3.text-match+json'}
        # 实际项目中，你需要从环境变量或安全配置中获取 GitHub Token
        # self.headers['Authorization'] = f"token {os.getenv('GITHUB_TOKEN')}"
        self.base_url = "https://api.github.com/search/code"
        self.search_cache = {} # 简单的内存缓存
        self.load_cache(CONFIG.get('search_cache_path'))

    def load_cache(self, path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                self.search_cache = json.load(f)
            logger.info(f"加载搜索缓存：{len(self.search_cache)} 条")
        except (FileNotFoundError, json.JSONDecodeError):
            logger.warning("未找到搜索缓存文件或文件损坏，将从头开始搜索。")
            self.search_cache = {}

    def save_cache(self, path):
        try:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(self.search_cache, f, ensure_ascii=False, indent=2)
            logger.info("搜索缓存已保存。")
        except IOError as e:
            logger.error(f"保存搜索缓存失败: {e}")

    def search_github(self, keyword):
        query_url = f"{self.base_url}?q={keyword}&per_page={CONFIG['per_page']}"
        results = []
        for page in range(1, CONFIG['max_search_pages'] + 1):
            url = f"{query_url}&page={page}"
            if url in self.search_cache:
                logger.info(f"从缓存获取搜索结果：{keyword} (页 {page})")
                results.extend(self.search_cache[url])
                continue

            try:
                response = requests.get(url, headers=self.headers, timeout=CONFIG['github_api_timeout'])
                response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
                data = response.json()

                # 检查速率限制
                remaining_requests = int(response.headers.get('X-RateLimit-Remaining', 0))
                if remaining_requests < CONFIG['rate_limit_threshold']:
                    reset_time = int(response.headers.get('X-RateLimit-Reset', time.time()))
                    wait_time = max(CONFIG['github_api_retry_wait'], reset_time - time.time() + 1)
                    logger.warning(f"GitHub API 速率限制，剩余 {remaining_requests}。等待 {wait_time:.1f} 秒。")
                    time.sleep(wait_time)

                items = data.get('items', [])
                if not items:
                    break # 没有更多结果

                # 提取 raw_url
                current_page_urls = []
                for item in items:
                    if 'git_url' in item: # For code search, git_url often leads to raw content
                        # Attempt to derive raw URL from git_url, it's often like:
                        # git_url: https://api.github.com/repos/user/repo/git/blobs/sha
                        # raw_url: https://raw.githubusercontent.com/user/repo/sha
                        # This is a simplification; a more robust way is to fetch blob content.
                        # For simple code search, the html_url might be more useful to get the repo
                        html_url = item.get('html_url')
                        if html_url and "blob" in html_url:
                            raw_url = html_url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
                            current_page_urls.append(raw_url)
                        else:
                            # Fallback for other item types, might need more specific handling
                            logger.warning(f"Could not derive raw_url for item: {item.get('html_url')}")

                results.extend(current_page_urls)
                self.search_cache[url] = current_page_urls # 缓存当前页结果
                logger.info(f"搜索到 {len(items)} 个项目，提取 {len(current_page_urls)} 个原始URL，关键词：{keyword} (页 {page})")

                if len(items) < CONFIG['per_page']: # 如果当前页结果少于每页最大值，说明是最后一页
                    break

            except requests.exceptions.RequestException as e:
                logger.error(f"GitHub API 请求失败 for keyword '{keyword}', page {page}: {e}")
                break # 失败就停止当前关键词的搜索
            except Exception as e:
                logger.error(f"处理 GitHub API 响应时发生错误: {e}")
                break
        return results

    def get_all_raw_urls(self):
        all_raw_urls = set()
        keywords = CONFIG.get('search_keywords', [])
        for keyword in keywords:
            logger.info(f"开始搜索关键词: {keyword}")
            urls = self.search_github(keyword)
            all_raw_urls.update(urls)
            if len(all_raw_urls) >= CONFIG['max_urls']:
                logger.warning(f"已达到最大 URL 数量 {CONFIG['max_urls']}，停止搜索。")
                break
        self.save_cache(CONFIG.get('search_cache_path'))
        return list(all_raw_urls)[:CONFIG['max_urls']]

# --- 代理链接提取与解析模块 ---
class ProxyExtractor:
    def __init__(self):
        self.session = requests.Session()
        retry = requests.packages.urllib3.util.retry.Retry(
            total=CONFIG.get('requests_retry_total', 3),
            backoff_factor=CONFIG.get('requests_retry_backoff_factor', 1.5),
            status_forcelist=[500, 502, 503, 504]
        )
        adapter = requests.adapters.HTTPAdapter(max_retries=retry, pool_connections=CONFIG.get('requests_pool_size', 100), pool_maxsize=CONFIG.get('requests_pool_size', 100))
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

    def fetch_url_content(self, url):
        try:
            response = self.session.get(url, timeout=CONFIG['github_api_timeout'])
            response.raise_for_status()
            return response.text
        except requests.exceptions.RequestException as e:
            logger.error(f"无法获取 URL 内容 {url}: {e}")
            return None

    def extract_ss_link(self, line):
        """
        解析 Shadowsocks 链接。
        SS 链接格式通常是 ss://[base64(method:password@server:port)]#tag
        """
        if not line.startswith("ss://"):
            return None

        try:
            parts = line[5:].split('#', 1)
            encoded_info = parts[0]
            tag = unquote(parts[1]) if len(parts) > 1 else ""

            # 尝试 Base64 解码，支持 URL 安全 Base64
            decoded_info = base64.urlsafe_b64decode(encoded_info + '==').decode('utf-8')
            
            # 格式：method:password@server:port
            match = re.match(r"([^:]+):([^@]+)@([^:]+):(\d+)", decoded_info)
            if match:
                method, password, server, port = match.groups()
                return {
                    "protocol": "ss",
                    "server": server,
                    "port": int(port),
                    "method": method,
                    "password": password,
                    "tag": tag
                }
            else:
                logger.warning(f"无法解析 SS 链接信息: {decoded_info} (原始编码: {encoded_info})")
                return None
        except Exception as e:
            logger.warning(f"解析 SS 链接 '{line}' 失败: {e}")
            return None

    def extract_proxies_from_content(self, content):
        proxies = []
        if not content:
            return proxies

        lines = content.splitlines()
        for line in lines:
            line = line.strip()
            if line.startswith("ss://"):
                proxy_info = self.extract_ss_link(line)
                if proxy_info:
                    proxies.append(proxy_info)
            # 这里可以添加对其他协议的解析逻辑
            # elif line.startswith("vmess://"):
            #     proxy_info = self.extract_vmess_link(line)
            #     if proxy_info: proxies.append(proxy_info)
            # elif line.startswith("hy2://"):
            #     proxy_info = self.extract_hy2_link(line)
            #     if proxy_info: proxies.append(proxy_info)
        return proxies

    def get_proxies_from_urls(self, urls):
        all_proxies = []
        with ThreadPoolExecutor(max_workers=CONFIG.get('channel_extract_workers', 10)) as executor:
            future_to_url = {executor.submit(self.fetch_url_content, url): url for url in urls}
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    content = future.result()
                    if content:
                        proxies_in_url = self.extract_proxies_from_content(content)
                        all_proxies.extend(proxies_in_url)
                        logger.info(f"从 {url} 提取到 {len(proxies_in_url)} 个代理节点。")
                except Exception as e:
                    logger.error(f"处理 URL {url} 时发生错误: {e}")
        return all_proxies

# --- 代理节点验证模块 ---
class ProxyChecker:
    def __init__(self):
        self.proxy_states = {} # 存储代理状态的字典
        self.load_states(CONFIG.get('proxy_states_path'))

    def load_states(self, path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                self.proxy_states = json.load(f)
            logger.info(f"加载代理状态缓存：{len(self.proxy_states)} 条")
        except (FileNotFoundError, json.JSONDecodeError):
            logger.warning("未找到代理状态缓存文件或文件损坏，将从头开始检测。")
            self.proxy_states = {}

    def save_states(self, path):
        try:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(self.proxy_states, f, ensure_ascii=False, indent=2)
            logger.info("代理状态缓存已保存。")
        except IOError as e:
            logger.error(f"保存代理状态缓存失败: {e}")

    def check_ss_proxy(self, proxy_info):
        """
        对 Shadowsocks 节点进行简单的 TCP 连接测试。
        这只是验证服务器可达性，不验证代理功能。
        """
        server = proxy_info['server']
        port = proxy_info['port']
        key = f"{server}:{port}"

        # 检查缓存
        if key in self.proxy_states:
            cached_status, timestamp = self.proxy_states[key]
            if time.time() - timestamp < CONFIG.get('url_states_ttl', 604800): # 默认一周有效期
                logger.debug(f"从缓存获取 SS 节点状态 {key}: {cached_status}")
                return cached_status == "ok"

        try:
            sock = socket.create_connection((server, port), timeout=CONFIG['proxy_check_timeout'])
            sock.close()
            status = "ok"
            logger.info(f"SS 节点可用: {server}:{port}")
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            status = "fail"
            logger.debug(f"SS 节点不可用 {server}:{port}: {e}")
        except Exception as e:
            status = "fail"
            logger.error(f"检测 SS 节点 {server}:{port} 时发生未知错误: {e}")
        
        self.proxy_states[key] = (status, time.time())
        return status == "ok"

    def check_all_proxies(self, proxies):
        available_proxies = []
        with ThreadPoolExecutor(max_workers=CONFIG.get('proxy_check_workers', 50)) as executor:
            future_to_proxy = {}
            for proxy in proxies:
                if proxy['protocol'] == 'ss':
                    future = executor.submit(self.check_ss_proxy, proxy)
                    future_to_proxy[future] = proxy
                # 这里可以添加其他协议的提交逻辑
                # elif proxy['protocol'] == 'vmess':
                #     future = executor.submit(self.check_vmess_proxy, proxy)
                #     future_to_proxy[future] = proxy

            for i, future in enumerate(as_completed(future_to_proxy), 1):
                proxy = future_to_proxy[future]
                is_available = False
                try:
                    is_available = future.result()
                except Exception as e:
                    logger.error(f"检测代理 {proxy.get('server')} 时发生异常: {e}")
                
                if is_available:
                    available_proxies.append(proxy)
                
                # 打印进度
                if i % 100 == 0:
                    logger.info(f"已检测 {i}/{len(proxies)} 个代理节点。")
        
        self.save_states(CONFIG.get('proxy_states_path'))
        return available_proxies

# --- 主程序逻辑 ---
def main():
    load_config()

    logger.info("开始搜索 GitHub 中的代理链接...")
    searcher = GitHubSearcher()
    raw_urls = searcher.get_all_raw_urls()
    logger.info(f"共找到 {len(raw_urls)} 个潜在的原始文件 URL。")

    logger.info("开始提取代理节点...")
    extractor = ProxyExtractor()
    extracted_proxies = extractor.get_proxies_from_urls(raw_urls)
    logger.info(f"共提取到 {len(extracted_proxies)} 个代理节点。")

    if not extracted_proxies:
        logger.warning("未提取到任何代理节点，程序退出。")
        return

    logger.info("开始验证代理节点可用性...")
    checker = ProxyChecker()
    available_proxies = checker.check_all_proxies(extracted_proxies)
    logger.info(f"共发现 {len(available_proxies)} 个可用代理节点。")

    # 输出可用节点到文件
    output_file_path = CONFIG.get('output_file', 'available_proxies.txt')
    with open(output_file_path, 'w', encoding='utf-8') as f:
        for proxy in available_proxies:
            # 根据协议类型，将其转换回可用的链接格式
            # 例如，对于SS：ss://base64(method:password@server:port)#tag
            if proxy['protocol'] == 'ss':
                info = f"{proxy['method']}:{proxy['password']}@{proxy['server']}:{proxy['port']}"
                encoded_info = base64.urlsafe_b64encode(info.encode('utf-8')).decode('utf-8').rstrip('=')
                link = f"ss://{encoded_info}"
                if proxy.get('tag'):
                    link += f"#{proxy['tag']}"
                f.write(link + "\n")
            # 添加其他协议的输出格式
            # elif proxy['protocol'] == 'vmess':
            #     f.write(vmess_to_link(proxy) + "\n")
    logger.info(f"可用代理节点已保存到 {output_file_path}")

if __name__ == "__main__":
    main()
