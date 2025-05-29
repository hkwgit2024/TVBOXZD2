import os
import re
import base64
import yaml
from github import Github
from github.GithubException import RateLimitExceededException

# --- 配置 ---
# 假设您的token已经设置在环境变量中
GITHUB_TOKEN = os.getenv("BOT") 

if not GITHUB_TOKEN:
    print("Error: GitHub token (BOT) not found. Please set the 'BOT' environment variable or assign it directly in the script.")
    exit()

g = Github(GITHUB_TOKEN)

# 用于存储去重后的节点
extracted_nodes = set()

# --- 搜索关键字和策略 ---
# 增加更多关键字，并考虑在不同的文件类型中搜索
# 'in:file' 搜索文件内容, 'extension:txt' 'extension:md' 'extension:yaml' 'extension:yml' 指定文件类型
# 您可以根据实际情况调整这些关键字和组合
search_keywords = [
    "http", "https", "url", "link", "node", "server", "endpoint", "
"
]

# 组合搜索查询。GitHub搜索查询有长度限制，且过于复杂的查询可能导致性能问题。
# 建议分批进行搜索，或者使用更精炼的关键字组合。
# 这里的示例是搜索所有文件中的这些关键字。
# 如果需要，可以针对特定文件类型组合，例如：
# search_queries = ["http extension:txt", "url extension:yaml", "node extension:md"]
# 为了演示，我们先尝试一个相对宽泛的组合
search_query_base = " OR ".join([f'"{kw}"' for kw in search_keywords])
search_queries = [
    f"{search_query_base} in:file extension:txt",
    f"{search_query_base} in:file extension:md",
    f"{search_query_base} in:file extension:json",
    f"{search_query_base} in:file extension:yaml",
    f"{search_query_base} in:file extension:yml",
    f"{search_query_base} in:file extension:conf", # 常见配置
    f"{search_query_base} in:file extension:cfg",
    f"{search_query_base} in:file filename:config", # 查找名称中包含config的文件
    f"{search_query_base} in:file filename:nodes", # 查找名称中包含nodes的文件
    f"{search_query_base} in:file" # 更广泛的搜索
]


# --- 正则表达式和解析函数 ---

# 通用URL匹配模式。可以根据实际情况调整。
# 这个模式会匹配以http(s)://开头的URL，直到遇到空格、引号、尖括号或换行。
URL_PATTERN = re.compile(r"http[s]?://[^\s\"\'<>]+") 

# 尝试解码Base64并提取链接
def extract_from_base64(text):
    try:
        # Base64字符串通常是多行，所以需要移除空白符，并且长度是4的倍数
        cleaned_text = text.replace(" ", "").replace("\n", "").replace("\r", "")
        if len(cleaned_text) % 4 != 0:
            # 尝试填充 Base64 字符串
            padding_needed = 4 - (len(cleaned_text) % 4)
            if padding_needed != 4: # Only add padding if it's not already a multiple of 4
                cleaned_text += '=' * padding_needed

        decoded_bytes = base64.b64decode(cleaned_text, validate=True)
        decoded_string = decoded_bytes.decode('utf-8', errors='ignore') # 忽略解码错误
        return URL_PATTERN.findall(decoded_string)
    except Exception:
        return []

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
                elif isinstance(item, str): # 顶层如果是字符串
                    links.extend(URL_PATTERN.findall(item))
            find_urls_in_yaml(data)
    except yaml.YAMLError:
        pass # 不是有效的YAML
    return links

# --- 主逻辑 ---
for current_query in search_queries:
    print(f"\nSearching GitHub for: '{current_query}'...")
    try:
        # 使用 g.search_code 搜索代码文件
        # 注意：每次查询都是独立的API调用，会消耗速率限制
        for result in g.search_code(query=current_query):
            try:
                # 获取文件内容
                file_content_bytes = result.decoded_content
                file_content = file_content_bytes.decode('utf-8', errors='ignore')

                # 1. 尝试从明文中提取链接
                found_links_plain = URL_PATTERN.findall(file_content)
                for link in found_links_plain:
                    extracted_nodes.add(link)

                # 2. 尝试从YAML中提取链接
                # 只有当文件扩展名是yaml或yml时才尝试解析YAML
                if result.path.lower().endswith(('.yaml', '.yml')):
                    found_links_yaml = extract_from_yaml(file_content)
                    for link in found_links_yaml:
                        extracted_nodes.add(link)

                # 3. 尝试识别并解码Base64，然后从解码后的内容中提取链接
                # 这是一个启发式的方法，因为无法确定哪些字符串是Base64编码的链接
                # 我们可以查找看起来像Base64的字符串（由特定字符集组成，长度是4的倍数）
                # 这里的模式非常宽泛，可能会有很多误报
                # 例如：匹配包含大写字母、小写字母、数字、+、/、= 的连续字符串
                base64_pattern = re.compile(r"[A-Za-z0-9+/=]{16,}(?:={0,2})") # 至少16个字符长，且可能带填充
                potential_base64_strings = base64_pattern.findall(file_content)

                for b64_str in potential_base64_strings:
                    found_links_b64 = extract_from_base64(b64_str)
                    for link in found_links_b64:
                        extracted_nodes.add(link)

            except RateLimitExceededException:
                print("Rate limit exceeded. Please wait and try again later.")
                # 这里可以添加等待逻辑，例如 time.sleep(g.rate_limiting_resettime - time.time())
                break # 跳出当前搜索结果循环，等待下次查询
            except Exception as e:
                # 忽略文件内容解码或处理中的个别错误
                # print(f"Error processing {result.path} in repo {result.repository.full_name}: {e}")
                continue # 继续处理下一个文件

    except RateLimitExceededException:
        print("Rate limit exceeded for search query. Moving to next query or exiting.")
        # 如果整个查询的速率限制被触发，则不再进行后续查询
        break
    except Exception as e:
        print(f"An error occurred during search query '{current_query}': {e}")
        continue # 继续尝试下一个查询

# --- 保存结果 ---
output_file_path = "data/hy2.txt"
os.makedirs(os.path.dirname(output_file_path), exist_ok=True)

with open(output_file_path, "w", encoding="utf-8") as f:
    for node in sorted(list(extracted_nodes)): # 可以选择排序
        f.write(node + "\n")

print(f"\nExtracted {len(extracted_nodes)} unique nodes and saved to '{output_file_path}'")
