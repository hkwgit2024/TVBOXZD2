import os
import re
import base64
import yaml
import time
from github import Github
from github.GithubException import RateLimitExceededException

# --- 配置 ---
# GitHub Token 从环境变量 'BOT' 获取
GITHUB_TOKEN = os.getenv("BOT") 

if not GITHUB_TOKEN:
    print("Error: GitHub token (BOT) not found. Please set the 'BOT' environment variable or assign it directly in the script.")
    exit(1) # 以错误码退出

g = Github(GITHUB_TOKEN)

# 用于存储去重后的节点
extracted_nodes = set()

# --- 搜索关键字和策略 ---
# 增加更多关键字，覆盖可能包含链接的场景
search_keywords = [
    "http", "https", "url", "link", "node", "server", "endpoint", "api", 
    "address", "host", "port", "credentials", "proxy", "vpn", "gateway", 
    "config", "source", "dest"
]

# 组合搜索查询。GitHub搜索查询有长度限制，且过于复杂的查询可能导致性能问题。
# 这里我们尝试通过文件扩展名来细分搜索，以提高效率和减少无关结果。
# 可以根据需要调整或增加文件类型。
search_queries = [
    f'({" OR ".join([f'"{kw}"' for kw in search_keywords])}) in:file extension:txt',
    f'({" OR ".join([f'"{kw}"' for kw in search_keywords])}) in:file extension:md',
    f'({" OR ".join([f'"{kw}"' for kw in search_keywords])}) in:file extension:json',
    f'({" OR ".join([f'"{kw}"' for kw in search_keywords])}) in:file extension:yaml',
    f'({" OR ".join([f'"{kw}"' for kw in search_keywords])}) in:file extension:yml',
    f'({" OR ".join([f'"{kw}"' for kw in search_keywords])}) in:file extension:conf', 
    f'({" OR ".join([f'"{kw}"' for kw in search_keywords])}) in:file extension:cfg',
    # 也可以搜索特定文件名模式
    f'({" OR ".join([f'"{kw}"' for kw in search_keywords])}) in:file filename:config', 
    f'({" OR ".join([f'"{kw}"' for kw in search_keywords])}) in:file filename:nodes', 
]


# --- 正则表达式和解析函数 ---

# 通用URL匹配模式。可以根据实际情况调整。
# 这个模式会匹配以http(s)://开头的URL，直到遇到空格、引号、尖括号或换行。
URL_PATTERN = re.compile(r"http[s]?://[^\s\"\'<>`]+") 

# 尝试解码Base64并提取链接
def extract_from_base64(text):
    links = []
    try:
        # Base64字符串通常是多行，所以需要移除空白符，并且长度是4的倍数
        cleaned_text = text.replace(" ", "").replace("\n", "").replace("\r", "")
        # 尝试填充 Base64 字符串
        padding_needed = 4 - (len(cleaned_text) % 4)
        if padding_needed != 4: # 只有当需要填充时才添加
            cleaned_text += '=' * padding_needed

        decoded_bytes = base64.b64decode(cleaned_text, validate=True)
        decoded_string = decoded_bytes.decode('utf-8', errors='ignore') # 忽略解码错误
        links.extend(URL_PATTERN.findall(decoded_string))
    except Exception:
        pass # 不是有效的Base64或解码失败
    return links

# 尝试从YAML中提取链接
def extract_from_yaml(content):
    links = []
    try:
        data = yaml.safe_load(content)
        if isinstance(data, (dict, list)):
            # 递归遍历YAML结构查找字符串中的URL
            def find_urls_in_yaml(item):
                if isinstance(item, dict):
                    for key, value in item.items():
                        if isinstance(value, str):
                            links.extend(URL_PATTERN.findall(value))
                        else:
                            find_urls_in_yaml(value)
                elif isinstance(item, list):
                    for value in item:
                        if isinstance(value, str):
                            links.extend(URL_PATTERN.findall(value))
                        else:
                            find_urls_in_yaml(value)
                elif isinstance(item, str): # 如果顶层就是字符串
                    links.extend(URL_PATTERN.findall(item))
            find_urls_in_yaml(data)
    except yaml.YAMLError:
        pass # 不是有效的YAML
    return links

# --- 主逻辑 ---
# 定义一个函数来处理单个搜索结果，避免代码重复
def process_search_result(result):
    global extracted_nodes
    try:
        file_content_bytes = result.decoded_content
        file_content = file_content_bytes.decode('utf-8', errors='ignore')

        # 1. 尝试从明文中提取链接
        found_links_plain = URL_PATTERN.findall(file_content)
        for link in found_links_plain:
            extracted_nodes.add(link)

        # 2. 尝试从YAML中提取链接 (基于文件扩展名)
        if result.path.lower().endswith(('.yaml', '.yml')):
            found_links_yaml = extract_from_yaml(file_content)
            for link in found_links_yaml:
                extracted_nodes.add(link)

        # 3. 尝试识别并解码Base64，然后从解码后的内容中提取链接
        # 这是一个启发式的方法，查找看起来像Base64的字符串
        # 匹配包含大写字母、小写字母、数字、+、/、= 的连续字符串，至少16个字符长
        # 并且是4的倍数（或通过填充补齐）
        base64_pattern = re.compile(r"[A-Za-z0-9+/]{16,}(?:={0,2})") 
        potential_base64_strings = base64_pattern.findall(file_content)

        for b64_str in potential_base64_strings:
            found_links_b64 = extract_from_base64(b64_str)
            for link in found_links_b64:
                extracted_nodes.add(link)

    except RateLimitExceededException:
        raise # 重新抛出速率限制异常，以便外部捕获和处理
    except Exception as e:
        # 忽略文件内容解码或处理中的个别错误，但打印出来方便调试
        print(f"Error processing {result.path} in repo {result.repository.full_name}: {e}")
        pass # 继续处理下一个文件

for current_query in search_queries:
    print(f"\nSearching GitHub for: '{current_query}'...")
    try:
        # 使用 g.search_code 搜索代码文件
        # 注意：每次查询都是独立的API调用，会消耗速率限制
        for result in g.search_code(query=current_query):
            process_search_result(result)

    except RateLimitExceededException:
        print("\n--- GitHub API Rate Limit Exceeded ---")
        rate_limit = g.get_rate_limit().core # 获取核心API的速率限制信息
        reset_time_utc = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(rate_limit.reset))
        print(f"Current remaining API calls: {rate_limit.remaining}")
        print(f"Rate limit will reset at: {reset_time_utc}")
        # 如果在 Actions 中运行，可能会直接失败，否则可以等待
        # time.sleep(max(0, rate_limit.reset - time.time() + 5)) # 等待直到重置时间 + 5秒余量
        # 鉴于在 CI/CD 环境，通常直接停止并等待下次运行更合理
        print("Stopping further GitHub API calls for this run due to rate limit.")
        break # 跳出所有查询循环

    except Exception as e:
        print(f"An unexpected error occurred during search query '{current_query}': {e}")
        continue # 继续尝试下一个查询

# --- 保存结果 ---
output_file_path = "data/hy2.txt"
os.makedirs(os.path.dirname(output_file_path), exist_ok=True)

with open(output_file_path, "w", encoding="utf-8") as f:
    for node in sorted(list(extracted_nodes)): # 可以选择排序
        f.write(node + "\n")

print(f"\nExtracted {len(extracted_nodes)} unique nodes and saved to '{output_file_path}'")
