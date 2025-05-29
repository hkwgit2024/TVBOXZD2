import os
import re
import base64
import yaml
import time
from github import Github
from github.GithubException import RateLimitExceededException
import datetime # 新增导入 datetime 模块

GITHUB_TOKEN = os.getenv("BOT") 

if not GITHUB_TOKEN:
    print("Error: GitHub token (BOT) not found. Please set the 'BOT' environment variable or assign it directly in the script.")
    exit(1)

g = Github(GITHUB_TOKEN)

extracted_nodes = set()

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

NODE_PATTERN = re.compile(r"(ss://[^\s]+|ssr://[^\s]+|vmess://[^\s]+|trojan://[^\s]+|vless://[^\s]+|hysteria://[^\s]+)")

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
                        else:
                            find_urls_in_yaml(value)
                elif isinstance(item, list):
                    for value in item:
                        if isinstance(value, str):
                            links.extend(NODE_PATTERN.findall(value))
                        else:
                            find_urls_in_yaml(value)
                elif isinstance(item, str):
                    links.extend(NODE_PATTERN.findall(item))
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
        for node_link in found_nodes:
            extracted_nodes.add(node_link)

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
        # 修正：将 datetime 对象转换为 timestamp
        reset_timestamp = rate_limit_before.reset.timestamp() 
        print(f"DEBUG: Before query - Remaining API calls: {rate_limit_before.remaining}/{rate_limit_before.limit}, Resets at: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(reset_timestamp))}")

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
        # 修正：将 datetime 对象转换为 timestamp
        reset_timestamp = rate_limit.reset.timestamp() 
        reset_time_utc = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(reset_timestamp))
        print(f"Current remaining API calls: {rate_limit.remaining}")
        print(f"Rate limit will reset at: {reset_time_utc}")
        print("Stopping further GitHub API calls for this run due to rate limit.")
        break

    except Exception as e:
        print(f"An unexpected error occurred during search query '{current_query}': {e}")
        continue 

output_file_path = "data/hy2.txt"
os.makedirs(os.path.dirname(output_file_path), exist_ok=True)

with open(output_file_path, "w", encoding="utf-8") as f:
    for node in sorted(list(extracted_nodes)):
        f.write(node + "\n")

print(f"\nExtracted {len(extracted_nodes)} unique nodes and saved to '{output_file_path}'")
