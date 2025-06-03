import requests
import base64
import json
import yaml
import time
import re
import socket
import logging
import os
from urllib.parse import urlparse, unquote, quote
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- Configuration Loading ---
CONFIG = {}
logger = logging.getLogger(__name__)

def load_config(config_path="config_proxy.yaml"):
    """
    Loads configuration from a YAML file.
    """
    global CONFIG
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            CONFIG = yaml.safe_load(f)
        logging.basicConfig(level=getattr(logging, CONFIG.get('log_level', 'INFO').upper()),
                            format='%(asctime)s - %(levelname)s - %(message)s')
        logger.info(f"Configuration loaded successfully from: {config_path}")
    except FileNotFoundError:
        logger.error(f"Configuration file not found: {config_path}. Please create it.")
        exit(1)
    except yaml.YAMLError as e:
        logger.error(f"Error parsing configuration file: {e}")
        exit(1)

# --- GitHub Search Module ---
class GitHubSearcher:
    def __init__(self):
        self.headers = {'Accept': 'application/vnd.github.v3.text-match+json'}
        github_token = os.getenv('BOT')
        if github_token:
            self.headers['Authorization'] = f"token {github_token}"
            logger.info("GitHub Token loaded from environment variable.")
        else:
            logger.warning("GITHUB_TOKEN environment variable not set. GitHub API rate limits might be lower.")

        self.base_url = "https://api.github.com/search/code"
        self.search_cache = {}  # Stores {'url': (timestamp, results)}
        self.load_cache(CONFIG.get('search_cache_path', 'github_search_cache.json'))
        self.session = requests.Session()

    def load_cache(self, path):
        """
        Loads the search cache from a JSON file.
        """
        try:
            with open(path, 'r', encoding='utf-8') as f:
                loaded_cache = json.load(f)
                # Convert list of lists back to tuples for timestamp
                self.search_cache = {k: (v[0], v[1]) for k, v in loaded_cache.items()}
            logger.info(f"Loaded search cache with {len(self.search_cache)} entries.")
        except (FileNotFoundError, json.JSONDecodeError):
            logger.warning("Search cache file not found or corrupted, starting with an empty cache.")
            self.search_cache = {}

    def save_cache(self, path):
        """
        Saves the search cache to a JSON file.
        """
        try:
            # Convert tuples to lists for JSON serialization
            serializable_cache = {k: [v[0], v[1]] for k, v in self.search_cache.items()}
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(serializable_cache, f, ensure_ascii=False, indent=2)
            logger.info("Search cache saved.")
        except IOError as e:
            logger.error(f"Failed to save search cache: {e}")

    def search_github(self, keyword):
        """
        Searches GitHub for the given keyword and returns raw file URLs.
        Applies caching with a configurable TTL.
        """
        query_url = f"{self.base_url}?q={keyword}&per_page={CONFIG['per_page']}"
        results = []
        cache_ttl = CONFIG.get('search_cache_ttl', 86400) # Default to 24 hours (24*60*60)

        for page in range(1, CONFIG['max_search_pages'] + 1):
            url = f"{query_url}&page={page}"
            current_time = time.time()

            if url in self.search_cache:
                timestamp, cached_results = self.search_cache[url]
                if (current_time - timestamp) < cache_ttl:
                    logger.info(f"Retrieving search results from cache for: '{keyword}' (page {page})")
                    results.extend(cached_results)
                    # If cached results are less than per_page, it means it was the last page when cached
                    if len(cached_results) < CONFIG['per_page']:
                        break
                    continue
                else:
                    logger.info(f"Cache for '{keyword}' (page {page}) is stale, fetching fresh data.")
                    # Invalidate stale cache entry
                    del self.search_cache[url]

            try:
                response = self.session.get(url, headers=self.headers, timeout=CONFIG['github_api_timeout'])
                response.raise_for_status()
                data = response.json()

                remaining_requests = int(response.headers.get('X-RateLimit-Remaining', 0))
                if remaining_requests < CONFIG['rate_limit_threshold']:
                    reset_time = int(response.headers.get('X-RateLimit-Reset', time.time()))
                    wait_time = max(CONFIG['github_api_retry_wait'], reset_time - time.time() + 1)
                    logger.warning(f"GitHub API rate limit hit, {remaining_requests} remaining. Waiting for {wait_time:.1f} seconds.")
                    time.sleep(wait_time)

                items = data.get('items', [])
                if not items:
                    logger.info(f"No more results found for keyword '{keyword}' (page {page}).")
                    break

                current_page_urls = []
                for item in items:
                    html_url = item.get('html_url')
                    if html_url and "github.com" in html_url and "/blob/" in html_url:
                        raw_url = html_url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
                        current_page_urls.append(raw_url)
                    else:
                        logger.debug(f"Could not derive raw URL from HTML URL: {html_url}")

                results.extend(current_page_urls)
                self.search_cache[url] = (current_time, current_page_urls) # Cache with timestamp
                logger.info(f"Found {len(items)} items, extracted {len(current_page_urls)} raw URLs for '{keyword}' (page {page}).")

                if len(items) < CONFIG['per_page']:
                    break

            except requests.exceptions.RequestException as e:
                logger.error(f"GitHub API request failed for keyword '{keyword}', page {page}: {e}")
                if isinstance(e, requests.exceptions.HTTPError) and e.response.status_code == 401:
                    logger.critical("GitHub API authentication failed (401 Unauthorized). Please check if GITHUB_TOKEN is valid and has correct permissions.")
                    return []
                break
            except Exception as e:
                logger.error(f"An error occurred while processing GitHub API response: {e}")
                break
        return results

    def get_all_raw_urls(self):
        """
        Collects all raw URLs from GitHub based on configured keywords.
        """
        all_raw_urls = set()
        keywords = CONFIG.get('search_keywords', [])
        for keyword in keywords:
            logger.info(f"Starting search for keyword: '{keyword}'")
            urls = self.search_github(keyword)
            if not urls and (not self.headers.get('Authorization') or self.headers.get('Authorization') == 'token None'):
                logger.critical("Cannot proceed with search due to authentication failure. Please set a valid GITHUB_TOKEN.")
                return []

            all_raw_urls.update(urls)
            if len(all_raw_urls) >= CONFIG['max_urls']:
                logger.warning(f"Reached maximum URL count of {CONFIG['max_urls']}, stopping search.")
                break
        self.save_cache(CONFIG.get('search_cache_path', 'github_search_cache.json'))
        return list(all_raw_urls)[:CONFIG['max_urls']]

# --- Proxy Link Extraction and Parsing Module ---
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
        """
        Asynchronously fetches content from a given URL.
        """
        try:
            response = self.session.get(url, timeout=CONFIG['github_api_timeout'])
            response.raise_for_status()
            logger.debug(f"Successfully fetched URL content: {url}")
            return url, response.text
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch URL content {url}: {e}")
            return url, None

    def extract_ss_link(self, line):
        """
        Parses a Shadowsocks link.
        SS link format is typically ss://[base64(method:password@server:port)]#tag
        """
        if not line.startswith("ss://"):
            return None

        try:
            parts = line[5:].split('#', 1)
            encoded_info = parts[0]
            tag = unquote(parts[1]) if len(parts) > 1 else ""

            # Attempt Base64 decoding, supporting URL-safe Base64, and handling missing padding
            decoded_info_bytes = base64.urlsafe_b64decode(encoded_info + '===')
            decoded_info = decoded_info_bytes.decode('utf-8')
            
            # Format: method:password@server:port
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
                logger.warning(f"Could not parse SS link info: {decoded_info} (original encoded: {encoded_info})")
                return None
        except Exception as e:
            logger.warning(f"Failed to parse SS link '{line}': {e}")
            return None

    def extract_proxies_from_content(self, content):
        """
        Extracts proxy links from the given content.
        """
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
            # TODO: Add parsing logic for other protocols here (e.g., vmess://, hy2://)
            # elif line.startswith("vmess://"):
            #     proxy_info = self.extract_vmess_link(line)
            #     if proxy_info: proxies.append(proxy_info)
            # elif line.startswith("hy2://"):
            #     proxy_info = self.extract_hy2_link(line)
            #     if proxy_info: proxies.append(proxy_info)
        return proxies

    def get_proxies_from_urls(self, urls):
        """
        Fetches content from a list of URLs and extracts proxy information.
        """
        all_proxies = []
        with ThreadPoolExecutor(max_workers=CONFIG.get('channel_extract_workers', 10)) as executor:
            future_to_url = {executor.submit(self.fetch_url_content, url): url for url in urls}
            
            for i, future in enumerate(as_completed(future_to_url), 1):
                original_url = future_to_url[future]
                try:
                    url_fetched, content = future.result()
                    if content:
                        proxies_in_url = self.extract_proxies_from_content(content)
                        all_proxies.extend(proxies_in_url)
                        logger.info(f"Extracted {len(proxies_in_url)} proxy nodes from {url_fetched}.")
                except Exception as e:
                    logger.error(f"Error processing URL {original_url}: {e}")
                
                if i % 10 == 0 or i == len(future_to_url):
                    logger.info(f"Processed {i}/{len(future_to_url)} file content URLs.")

        # Deduplicate based on protocol + server + port + method
        unique_proxies = {}
        for proxy in all_proxies:
            # For SS nodes, use server:port:method as a unique key
            key = f"{proxy['protocol']}://{proxy['server']}:{proxy['port']}/{proxy['method']}"
            unique_proxies[key] = proxy
            
        return list(unique_proxies.values())

# --- Proxy Node Validation Module ---
class ProxyChecker:
    def __init__(self):
        self.proxy_states = {}  # Stores {'key': (status, timestamp)}
        self.load_states(CONFIG.get('proxy_states_path', 'proxy_states_cache.json'))

    def load_states(self, path):
        """
        Loads cached proxy states from a JSON file.
        """
        try:
            with open(path, 'r', encoding='utf-8') as f:
                loaded_states = json.load(f)
                # Convert list of lists back to tuples for timestamp
                self.proxy_states = {k: (v[0], v[1]) for k, v in loaded_states.items()}
            logger.info(f"Loaded proxy states cache with {len(self.proxy_states)} entries.")
        except (FileNotFoundError, json.JSONDecodeError):
            logger.warning("Proxy states cache file not found or corrupted, starting fresh detection.")
            self.proxy_states = {}

    def save_states(self, path):
        """
        Saves current proxy states to a JSON file.
        """
        try:
            # Convert tuples to lists for JSON serialization
            serializable_states = {k: [v[0], v[1]] for k, v in self.proxy_states.items()}
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(serializable_states, f, ensure_ascii=False, indent=2)
            logger.info("Proxy states cache saved.")
        except IOError as e:
            logger.error(f"Failed to save proxy states cache: {e}")

    def check_ss_proxy(self, proxy_info):
        """
        Performs a simple TCP connection test for a Shadowsocks node.
        This only verifies server reachability, not proxy functionality.
        """
        server = proxy_info['server']
        port = proxy_info['port']
        # Use server:port:method as a specific cache key
        key = f"{server}:{port}:{proxy_info.get('method', 'unknown')}"
        
        cache_ttl = CONFIG.get('proxy_states_ttl', 3600) # Default to 1 hour (60*60)
        current_time = time.time()

        # Check cache
        if key in self.proxy_states:
            cached_status, timestamp = self.proxy_states[key]
            if (current_time - timestamp) < cache_ttl:
                logger.debug(f"Retrieving SS node status from cache for {key}: {cached_status}")
                return cached_status == "ok"
            else:
                logger.info(f"Cache for SS node {key} is stale, re-checking.")
                del self.proxy_states[key] # Invalidate stale cache entry

        try:
            sock = socket.create_connection((server, port), timeout=CONFIG['proxy_check_timeout'])
            sock.close()
            status = "ok"
            logger.info(f"SS node available: {server}:{port}")
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            status = "fail"
            logger.debug(f"SS node unavailable {server}:{port}: {e}")
        except Exception as e:
            status = "fail"
            logger.error(f"Unknown error checking SS node {server}:{port}: {e}")
            
        self.proxy_states[key] = (status, current_time) # Cache with timestamp
        return status == "ok"

    def check_all_proxies(self, proxies):
        """
        Checks the availability of all provided proxy nodes concurrently.
        """
        available_proxies = []
        with ThreadPoolExecutor(max_workers=CONFIG.get('proxy_check_workers', 50)) as executor:
            future_to_proxy = {}
            for proxy in proxies:
                if proxy['protocol'] == 'ss':
                    future = executor.submit(self.check_ss_proxy, proxy)
                    future_to_proxy[future] = proxy
                # TODO: Add submission logic for other protocols here
                # elif proxy['protocol'] == 'vmess':
                #     future = executor.submit(self.check_vmess_proxy, proxy)
                #     future_to_proxy[future] = proxy
            
            for i, future in enumerate(as_completed(future_to_proxy), 1):
                proxy = future_to_proxy[future]
                is_available = False
                try:
                    is_available = future.result()
                except Exception as e:
                    logger.error(f"Exception occurred while checking proxy {proxy.get('server')}: {e}")
                
                if is_available:
                    available_proxies.append(proxy)
                
                if i % 100 == 0 or i == len(future_to_proxy):
                    logger.info(f"Checked {i}/{len(future_to_proxy)} proxy nodes.")
            
        self.save_states(CONFIG.get('proxy_states_path', 'proxy_states_cache.json'))
        return available_proxies

# --- Main Program Logic ---
def main():
    load_config()

    logger.info("Starting to search for proxy links on GitHub...")
    searcher = GitHubSearcher()
    raw_urls = searcher.get_all_raw_urls()
    
    if not raw_urls:
        logger.warning("No potential raw file URLs found. Exiting. Please check GitHub Token and search keywords.")
        return

    logger.info(f"Found {len(raw_urls)} potential raw file URLs.")

    logger.info("Starting to extract proxy nodes...")
    extractor = ProxyExtractor()
    extracted_proxies = extractor.get_proxies_from_urls(raw_urls)
    
    if not extracted_proxies:
        logger.warning("No proxy nodes extracted. Exiting.")
        return

    logger.info(f"Extracted {len(extracted_proxies)} proxy nodes.")

    logger.info("Starting to verify proxy node availability...")
    checker = ProxyChecker()
    available_proxies = checker.check_all_proxies(extracted_proxies)
    logger.info(f"Found {len(available_proxies)} available proxy nodes.")

    # Output available nodes to a file
    output_file_path = CONFIG.get('output_file', 'available_proxies.txt')
    with open(output_file_path, 'w', encoding='utf-8') as f:
        for proxy in available_proxies:
            if proxy['protocol'] == 'ss':
                info = f"{proxy['method']}:{proxy['password']}@{proxy['server']}:{proxy['port']}"
                # Ensure URL-safe base64 encoding and remove padding
                encoded_info = base64.urlsafe_b64encode(info.encode('utf-8')).decode('utf-8').rstrip('=')
                link = f"ss://{encoded_info}"
                if proxy.get('tag'):
                    # Ensure tag is URL encoded
                    link += f"#{quote(proxy['tag'])}"
                f.write(link + "\n")
            # TODO: Add output formatting for other protocols (e.g., vmess, hy2)
            # elif proxy['protocol'] == 'vmess':
            #     f.write(vmess_to_link(proxy) + "\n")
    logger.info(f"Available proxy nodes saved to {output_file_path}")

if __name__ == "__main__":
    main()
