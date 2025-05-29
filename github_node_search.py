import os
import re
import base64
import yaml
import time
import requests # 新增：用于发送HTTP请求
from github import Github
from github.GithubException import RateLimitExceededException

GITHUB_TOKEN = os.getenv("BOT") 

if not GITHUB_TOKEN:
    print("Error: GitHub token (BOT) not found. Please set the 'BOT' environment variable or assign it directly in the script.")
    exit(1)

g = Github(GITHUB_TOKEN)

extracted_nodes = set()
verified_nodes = set() # 新增：用于存储验证通过的节点

# --- 调整后的搜索关键字 (保持不变，因为是您需要的代理协议前缀) ---
search_keywords = [
    "ss://", "ssr://", "vmess://", "trojan://", "vless://", "hysteria://",
    "vmess", "trojan", "ss", "ssr", "vless", "hysteria"
]

search_extensions = ['txt', 'md', 'json', 'yaml', 'yml', 'conf', 'cfg'] 

excluded_extensions = [
    'zip', 'tar', 'gz', 'rar', '7z',
    'jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg', 'ico',
    'mp3', 'wav', 'ogg',
    'mp4', 'avi', 'mov', 'mkv',
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
    'exe', 'dll', 'so', 'bin',
    'class', 'jar', 'pyc',
]

search_queries = []

for ext in search_extensions:
    for kw in search_keywords:
        search_queries.append(f'"{kw}" in:file extension:{ext}')

search_queries.append(f'("ss://" OR "ssr://" OR "vmess://") in:file filename:config') 
search_queries.append(f'("ss://" OR "ssr://" OR "vmess://") in:file filename:nodes') 
search_queries.append(f'("ss://" OR "ssr://" OR "vmess://") in:file filename:sub')

excluded_query_part = " ".join([f"-extension:{e}" for e in excluded_extensions])
general_nodes_query = f'("ss://" OR "ssr://" OR "vmess://" OR "trojan://" OR "vless://" OR "hysteria://") in:file {excluded_query_part}'
search_queries.append(general_nodes_query)

# --- 节点匹配模式 (保持不变，用于提取代理链接) ---
NODE_PATTERN = re.compile(r"(ss://[^\s]+|ssr://[^\s]+|vmess://[^\s]+|trojan://[^\s]+|vless://[^\s]+|hysteria://[^\s]+)")

# --- 新增：HTTP/HTTPS 链接匹配模式 ---
HTTP_URL_PATTERN = re.compile(r"http[s]?://[^\s\"\'<>`]+")

# --- 新增：模拟HTTP请求头 ---
COMMON_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
    "Connection": "keep-alive"
}

# --- 新增：验证HTTP/HTTPS链接函数 ---
def verify_http_url(url, timeout=5):
    try:
        response = requests.head(url, headers=COMMON_HEADERS, timeout=timeout, allow_redirects=True)
        # 2xx 状态码表示成功，3xx 表示重定向
        if 200 <= response.status_code < 400:
            print(f"INFO: Verified HTTP/HTTPS URL: {url} (Status: {response.status_code})")
            return True
        else:
            print(f"WARNING: Failed to verify HTTP/HTTPS URL: {url} (Status: {response.status_code})")
            return False
    except requests.exceptions.RequestException as e:
        print(f"WARNING: Error verifying HTTP/HTTPS URL: {url} - {e}")
        return False

def extract_from_base64(text):
    links = []
    try:
        cleaned_text = text.replace(" ", "").replace("\n", "").replace("\r", "")
        padding_needed = 4 - (len(cleaned_text) % 4)
        if padding_needed != 4:
            cleaned_text += '=' * padding_needed

        decoded_bytes = base64.b64decode(cleaned_text, validate=True)
        decoded_string = decoded_bytes.decode('utf-8', errors='ignore')
        links.extend(NODE_PATTERN.findall(decoded_string))
        links.extend(HTTP_URL_PATTERN.findall(decoded_string)) # 提取可能存在的HTTP/HTTPS链接
    except Exception:
        pass
    return links

def extract_from_yaml(content):
    links = []
    try:
        data = yaml.safe_load(content)
        if isinstance(data, (dict, list)):
            def find_urls_in_yaml(item):
                if isinstance(item, dict):
                    for key, value in item.items():
                        if isinstance(value, str):
                            links.extend(NODE_PATTERN.findall(value))
                            links.extend(HTTP_URL_PATTERN.findall(value)) # 提取可能存在的HTTP/HTTPS链接
                        else:
                            find_urls_in_yaml(value)
                elif isinstance(item, list):
                    for value in item:
                        if isinstance(value, str):
                            links.extend(NODE_PATTERN.findall(value))
                            links.extend(HTTP_URL_PATTERN.findall(value)) # 提取可能存在的HTTP/HTTPS链接
                        else:
                            find_urls_in_yaml(value)
                elif isinstance(item, str):
                    links.extend(NODE_PATTERN.findall(item))
                    links.extend(HTTP_URL_PATTERN.findall(item)) # 提取可能存在的HTTP/HTTPS链接
            find_urls_in_yaml(data)
    except yaml.YAMLError:
        pass
    return links

def process_search_result(result):
    global extracted_nodes
    try:
        file_content_bytes = result.decoded_content
        file_content = file_content_bytes.decode('utf-8', errors='ignore')

        found_nodes = NODE_PATTERN.findall(file_content)
        found_http_urls = HTTP_URL_PATTERN.findall(file_content) # 提取HTTP/HTTPS链接

        for node_link in found_nodes:
            extracted_nodes.add(node_link)

        for http_link in found_http_urls:
            extracted_nodes.add(http_link) # 即使是HTTP链接也先加入总列表

        if result.path.lower().endswith(('.yaml', '.yml')):
            found_links_yaml = extract_from_yaml(file_content)
            for link in found_links_yaml:
                extracted_nodes.add(link)

        base64_pattern = re.compile(r"[A-Za-z0-9+/]{16,}(?:={0,2})") 
        potential_base64_strings = base64_pattern.findall(file_content)

        for b64_str in potential_base64_strings:
            found_links_b64 = extract_from_base64(b64_str)
            for link in found_links_b64:
                extracted_nodes.add(link)

    except RateLimitExceededException:
        raise
    except Exception as e:
        print(f"Error processing {result.path} in repo {result.repository.full_name}: {e}")
        pass

QUERY_DELAY_SECONDS = 2 

for current_query in search_queries:
    print(f"\nSearching GitHub for: '{current_query}'...")
    try:
        rate_limit_before = g.get_rate_limit().core
        print(f"DEBUG: Before query - Remaining API calls: {rate_limit_before.remaining}/{rate_limit_before.limit}, Resets at: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(rate_limit_before.reset))}")

        search_results = g.search_code(query=current_query)
        
        count = 0
        for result in search_results:
            process_search_result(result)
            count += 1
            if count % 50 == 0:
                print(f"DEBUG: Processed {count} results for query '{current_query[:50]}...'")

        print(f"DEBUG: Finished processing {count} results for query '{current_query}'")

        time.sleep(QUERY_DELAY_SECONDS)

    except RateLimitExceededException:
        print("\n--- GitHub API Rate Limit Exceeded ---")
        rate_limit = g.get_rate_limit().core
        reset_time_utc = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(rate_limit.reset))
        print(f"Current remaining API calls: {rate_limit.remaining}")
        print(f"Rate limit will reset at: {reset_time_utc}")
        print("Stopping further GitHub API calls for this run due to rate limit.")
        break

    except Exception as e:
        print(f"An unexpected error occurred during search query '{current_query}': {e}")
        continue 

# --- 新增：验证提取到的所有节点 (只针对HTTP/HTTPS，代理协议链接不会被验证) ---
print("\n--- Starting node verification (HTTP/HTTPS only) ---")
initial_extracted_count = len(extracted_nodes)
nodes_to_verify = list(extracted_nodes) # 复制一份，避免在迭代时修改
nodes_to_verify.sort() # 排序以便日志清晰

for i, node_link in enumerate(nodes_to_verify):
    if node_link.startswith("http://") or node_link.startswith("https://"):
        print(f"Verifying HTTP/HTTPS node {i+1}/{initial_extracted_count}: {node_link}")
        if verify_http_url(node_link):
            verified_nodes.add(node_link)
        # 增加延迟，避免对目标网站造成负担或被ban
        time.sleep(0.5) # 每次验证后暂停0.5秒
    else:
        # 非HTTP/HTTPS链接直接加入已验证列表 (因为无法通过HTTP请求验证)
        verified_nodes.add(node_link)
        # print(f"INFO: Skipping HTTP/HTTPS verification for non-HTTP/HTTPS node: {node_link}") # 可以选择打印

print(f"\n--- Finished node verification ---")

output_file_path = "data/hy2.txt"
os.makedirs(os.path.dirname(output_file_path), exist_ok=True)

with open(output_file_path, "w", encoding="utf-8") as f:
    for node in sorted(list(verified_nodes)): # 保存已验证（或跳过验证）的节点
        f.write(node + "\n")

print(f"\nExtracted {initial_extracted_count} total nodes.")
print(f"Saved {len(verified_nodes)} unique (and partially verified) nodes to '{output_file_path}'")
