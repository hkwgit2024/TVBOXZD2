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

# 定义要搜索的文件扩展名 (已包含 'md')
# GitHub API 通常使用文件扩展名来搜索 Markdown 文件 (如 README.md)
search_extensions = ['txt', 'md', 'json', 'yaml', 'yml', 'conf', 'cfg', 'ini', 'xml'] 

# 定义要排除的文件扩展名
# 这些文件通常不包含您要查找的“节点”链接，可减少无关搜索结果
excluded_extensions = [
    'zip', 'tar', 'gz', 'rar', '7z',  # 压缩文件
    'jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg', 'ico', # 图片文件
    'mp3', 'wav', 'ogg', # 音频文件
    'mp4', 'avi', 'mov', 'mkv', # 视频文件
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', # 文档文件
    'exe', 'dll', 'so', 'bin', # 可执行文件/二进制文件
    'class', 'jar', 'pyc', # 编译后的代码或字节码
    'min.js', 'min.css', # 压缩/混淆的JS/CSS (通常不包含可读的节点信息)
    'lock', 'log', # 锁定文件和日志文件
    'db', 'sqlite' # 数据库文件
]

# 构建搜索查询列表
search_queries = []

# 为每个关键字和每个“搜索扩展名”组合生成一个查询
for ext in search_extensions:
    for kw in search_keywords:
        search_queries.append(f'"{kw}" in:file extension:{ext}')

# 添加针对特定文件名的搜索，但避免过于复杂的OR操作，只使用核心关键字
search_queries.append(f'("http" OR "https" OR "node") in:file filename:config') 
search_queries.append(f'("http" OR "https" OR "node") in:file filename:nodes') 

# 添加一个针对所有文件类型但只包含核心关键字的通用搜索，以防遗漏
# 这里的 'NOT extension:...' 子句会排除不需要的扩展名
# 注意：GitHub API 查询字符串有长度限制，如果排除的扩展名过多，可能导致查询过长
excluded_query_part = " ".join([f"-extension:{e}" for e in excluded_extensions])
general_keywords_query = f'("http" OR "https" OR "node" OR "url") in:file {excluded_query_part}'
search_queries.append(general_keywords_query)

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

# 在每个查询之间添加短暂延迟，以避免过快达到速率限制
QUERY_DELAY_SECONDS = 2 

for current_query in search_queries:
    print(f"\nSearching GitHub for: '{current_query}'...")
    try:
        # 使用 g.search_code 搜索代码文件
        # 注意：每次查询都是独立的API调用，会消耗速率限制
        for result in g.search_code(query=current_query):
            process_search_result(result)
        
        # 每次查询后延迟
        time.sleep(QUERY_DELAY_SECONDS)

    except RateLimitExceededException:
        print("\n--- GitHub API Rate Limit Exceeded ---")
        rate_limit = g.get_rate_limit().core # 获取核心API的速率限制信息
        reset_time_utc = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(rate_limit.reset))
        print(f"Current remaining API calls: {rate_limit.remaining}")
        print(f"Rate limit will reset at: {reset_time_utc}")
        # 在 CI/CD 环境中，通常直接停止并等待下次运行更合理
        print("Stopping further GitHub API calls for this run due to rate limit.")
        break # 跳出所有查询循环

    except Exception as e:
        print(f"An unexpected error occurred during search query '{current_query}': {e}")
        # 继续尝试下一个查询，即使当前查询失败
        continue 

# --- 保存结果 ---
output_file_path = "data/hy2.txt"
os.makedirs(os.path.dirname(output_file_path), exist_ok=True)

with open(output_file_path, "w", encoding="utf-8") as f:
    for node in sorted(list(extracted_nodes)): # 可以选择排序
        f.write(node + "\n")

print(f"\nExtracted {len(extracted_nodes)} unique nodes and saved to '{output_file_path}'")
