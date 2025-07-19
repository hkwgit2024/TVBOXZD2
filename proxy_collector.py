import os
import json
import base64
import yaml
import requests
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from github import Github, RateLimitExceededException, UnknownObjectException
import time
import logging

# --- 配置 ---
# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# GitHub API 配置
# 强烈建议使用 envars.GITHUB_TOKEN 或者 GitHub Actions secrets
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')
if not GITHUB_TOKEN:
    logger.error("GITHUB_TOKEN is not set. Please set the environment variable.")
    exit(1) # 没有token就退出，防止不必要的运行

# 搜索关键词，可以根据需求添加更多
SEARCH_KEYWORDS = ['vmess', 'vless', 'trojan', 'hysteria2', 'shadowsocks'] # 增加ss/ssr关键词以便搜索
# 代理节点模式，用于识别文件内容
NODE_PATTERNS = [
    r'hysteria2://',
    r'vmess://',
    r'trojan://',
    r'ss://',
    r'ssr://',
    r'vless://',
    r'warp://' # 增加对warp协议的识别
]
# 支持的文件扩展名
SUPPORTED_FILE_EXTENSIONS = ['.txt', '.yml', '.yaml', '.json']
# 默认的搜索仓库数量限制
MAX_REPOS_TO_SEARCH = 50 # 增加搜索的仓库数量，提高发现率
# 下载文件的最大并发线程数
MAX_WORKERS = 10 # 适当增加线程数，平衡性能和速率限制

# 文件和目录配置
DATA_DIR = 'data'
TIMESTAMP_FILE = 'timestamps.json'
REPOS_CACHE = 'repos.json'

# --- 初始化 ---
# 初始化 GitHub 客户端
try:
    g = Github(GITHUB_TOKEN)
    # 提前检查一次API限速，如果Token无效或达到上限，会抛出异常
    g.get_user().login
except Exception as e:
    logger.error(f"Failed to initialize GitHub client or check token: {e}")
    exit(1)

# 确保 data 目录存在
os.makedirs(DATA_DIR, exist_ok=True)

# --- 辅助函数 ---
def load_json_file(file_path, default_value={}):
    """加载 JSON 文件，如果文件不存在或解析失败则返回默认值。"""
    if os.path.exists(file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to decode JSON from {file_path}: {e}. Returning default value.")
        except Exception as e:
            logger.warning(f"Error loading {file_path}: {e}. Returning default value.")
    return default_value

def save_json_file(file_path, data):
    """保存数据到 JSON 文件。"""
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        logger.error(f"Failed to save data to {file_path}: {e}")

def get_current_utc_timestamp():
    """获取当前的 UTC 时间戳（ISO 8601 格式）。"""
    return datetime.now(timezone.utc).isoformat(timespec='seconds') + 'Z'

def is_valid_node_link(text):
    """检查文本是否包含任何已知节点模式。"""
    for pattern in NODE_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False

def decode_and_check_content(content):
    """尝试解码 base64 内容，并检查是否包含节点。"""
    try:
        decoded_content = base64.b64decode(content).decode('utf-8', errors='ignore')
        if is_valid_node_link(decoded_content):
            return decoded_content, True
    except Exception:
        pass # 不是有效的base64编码或者解码失败
    return content, False # 返回原始内容和未解码标志

def contains_nodes(content):
    """
    检查文件内容是否包含节点。
    支持直接文本、base64解码、YAML和JSON格式。
    """
    # 1. 检查原始文本是否包含节点
    if is_valid_node_link(content):
        return True

    # 2. 尝试 Base64 解码后检查
    decoded_content, is_base64_decoded = decode_and_check_content(content)
    if is_base64_decoded:
        return True

    # 3. 尝试 YAML 解析后检查
    if content.strip().startswith('---'):
        try:
            data = yaml.safe_load(content)
            if isinstance(data, dict):
                # 遍历字典中的所有字符串值
                for key, value in data.items():
                    if isinstance(value, str) and is_valid_node_link(value):
                        return True
                    # 也可以进一步遍历列表中的字典或字符串
                    if isinstance(value, list):
                        for item in value:
                            if isinstance(item, str) and is_valid_node_link(item):
                                return True
                            elif isinstance(item, dict):
                                for sub_value in item.values():
                                    if isinstance(sub_value, str) and is_valid_node_link(sub_value):
                                        return True
            elif isinstance(data, list): # 某些yaml文件可能是列表形式
                for item in data:
                    if isinstance(item, str) and is_valid_node_link(item):
                        return True
                    elif isinstance(item, dict):
                        for sub_value in item.values():
                            if isinstance(sub_value, str) and is_valid_node_link(sub_value):
                                return True
        except yaml.YAMLError:
            pass # 不是有效的 YAML

    # 4. 尝试 JSON 解析后检查
    if content.strip().startswith('{') or content.strip().startswith('['):
        try:
            data = json.loads(content)
            if isinstance(data, dict):
                # 遍历字典中的所有字符串值
                for key, value in data.items():
                    if isinstance(value, str) and is_valid_node_link(value):
                        return True
                    if isinstance(value, list):
                        for item in value:
                            if isinstance(item, str) and is_valid_node_link(item):
                                return True
                            elif isinstance(item, dict):
                                for sub_value in item.values():
                                    if isinstance(sub_value, str) and is_valid_node_link(sub_value):
                                        return True
            elif isinstance(data, list): # 某些json文件可能是列表形式
                for item in data:
                    if isinstance(item, str) and is_valid_node_link(item):
                        return True
                    elif isinstance(item, dict):
                        for sub_value in item.values():
                            if isinstance(sub_value, str) and is_valid_node_link(sub_value):
                                return True
        except json.JSONDecodeError:
            pass # 不是有效的 JSON

    return False

# --- GitHub API 交互函数 ---
def handle_rate_limit(e):
    """处理 GitHub API 速率限制。"""
    reset_time = g.get_rate_limit().core.reset.timestamp()
    sleep_time = max(60, reset_time - time.time() + 5) # 至少等60秒，或等到重置时间
    logger.warning(f"GitHub API rate limit exceeded. Waiting {sleep_time:.2f} seconds until {datetime.fromtimestamp(reset_time)}.")
    time.sleep(sleep_time)

def get_repo_files(repo):
    """递归获取仓库中所有支持的文件。"""
    files_to_download = []
    contents_stack = [''] # 使用栈来模拟递归，避免深度递归问题

    while contents_stack:
        path = contents_stack.pop()
        try:
            contents = repo.get_contents(path)
            if not isinstance(contents, list): # 如果只有一个文件，get_contents会返回单个ContentFile对象
                contents = [contents]

            for file_content in contents:
                if file_content.type == "dir":
                    contents_stack.append(file_content.path)
                elif file_content.type == "file":
                    # 检查文件扩展名，或没有扩展名但可能包含节点的文件
                    if any(file_content.path.lower().endswith(ext) for ext in SUPPORTED_FILE_EXTENSIONS) or \
                       (os.path.basename(file_content.path).count('.') == 0): # 没有扩展名的文件
                        files_to_download.append((file_content.path, file_content.download_url))
        except RateLimitExceededException as e:
            handle_rate_limit(e)
            contents_stack.append(path) # 将当前路径重新加入栈，以便重试
            time.sleep(1) # 稍作等待再重试
        except UnknownObjectException:
            logger.warning(f"Path not found in repo {repo.full_name}: {path}. Skipping.")
        except Exception as e:
            logger.error(f"Error getting contents for {repo.full_name}/{path}: {e}")
    return files_to_download

def download_and_save_file(repo, file_path, file_url, timestamps):
    """下载并保存文件，并更新时间戳。"""
    project_name = repo.full_name.replace('/', '__') # 使用双下划线避免与路径分隔符混淆
    save_dir = os.path.join(DATA_DIR, project_name)
    os.makedirs(save_dir, exist_ok=True)
    
    # 规范化文件路径作为本地文件名，避免/在文件名中
    local_file_name = file_path.replace('/', '_') 
    local_path = os.path.join(save_dir, local_file_name)

    file_key = f"{repo.full_name}:{file_path}"
    last_modified = timestamps.get(file_key)

    try:
        # 使用 requests.head 获取 Last-Modified 头，避免下载整个文件
        response_head = requests.head(file_url, headers={'Authorization': f'token {GITHUB_TOKEN}'}, timeout=10)
        response_head.raise_for_status() # 对非200状态码抛出异常
        current_modified = response_head.headers.get('Last-Modified')

        if last_modified and last_modified == current_modified:
            logger.debug(f"Skipping unchanged file: {file_path} in {repo.full_name}")
            return # 文件未更改，直接跳过

        # 文件有更新或首次下载
        # 适当延迟以避免触发IP层面的限速
        time.sleep(0.5)
        
        response_get = requests.get(file_url, headers={'Authorization': f'token {GITHUB_TOKEN}'}, timeout=30)
        response_get.raise_for_status() # 对非200状态码抛出异常

        content = response_get.text

        if contains_nodes(content):
            with open(local_path, 'w', encoding='utf-8') as f:
                f.write(content)
            logger.info(f"Saved node file: {local_path} from {repo.full_name}")
            timestamps[file_key] = current_modified
        else:
            logger.debug(f"No nodes found in: {file_path} from {repo.full_name}")
    except requests.exceptions.Timeout:
        logger.warning(f"Timeout downloading {file_url}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to download {file_url} (HTTP Error): {e}")
    except Exception as e:
        logger.error(f"Error in download_and_save_file for {file_url}: {e}")


# --- 主逻辑函数 ---
def main():
    logger.info("Starting ProxyPool collector.")
    timestamps = load_json_file(TIMESTAMP_FILE, default_value={})
    cached_repos_names = load_json_file(REPOS_CACHE, default_value=[])
    
    repos_to_process = []

    # 尝试从缓存加载仓库
    if cached_repos_names:
        logger.info(f"Using {len(cached_repos_names)} cached repositories.")
        # 从缓存的名称获取 repo 对象，这里可能会遇到速率限制
        for repo_name in cached_repos_names:
            try:
                repos_to_process.append(g.get_repo(repo_name))
            except RateLimitExceededException as e:
                handle_rate_limit(e)
                # 再次尝试，或者跳过当前周期，取决于需求
                logger.warning(f"Rate limit hit while getting cached repo {repo_name}. Skipping remaining cached repos for now.")
                break
            except UnknownObjectException:
                logger.warning(f"Cached repo {repo_name} not found or deleted. Skipping.")
            except Exception as e:
                logger.error(f"Error getting cached repo {repo_name}: {e}")
    else:
        # 如果没有缓存，则执行搜索
        logger.info("No cached repositories found, performing new search.")
        all_found_repos = []
        for keyword in SEARCH_KEYWORDS:
            if not g.get_rate_limit().search.remaining > 0:
                logger.warning("Search API limit reached during keyword search, waiting...")
                handle_rate_limit(RateLimitExceededException(None)) # 模拟抛出异常来触发等待
                if not g.get_rate_limit().search.remaining > 0: # 再次检查，避免无限循环
                    logger.error("Search API limit still reached after waiting. Exiting search.")
                    break

            logger.info(f"Searching for repositories with keyword: '{keyword}'")
            # 优化查询：只搜索readme或description中包含关键词的仓库，避免搜索整个代码库
            # 结合语言限制可以进一步提高精度
            query = f'"{keyword}" in:readme,description language:python,go,shell,javascript' # 缩小搜索范围
            try:
                # 仅获取前几页的结果，避免过多的API请求
                # per_page=100是最大值
                found_repos_iter = g.search_repositories(query=query, sort='stars', order='desc')
                
                # 限制迭代次数以控制搜索结果数量
                for i, repo in enumerate(found_repos_iter):
                    if repo.fork: # 过滤掉fork的仓库，因为通常原创仓库内容更稳定
                        continue
                    all_found_repos.append(repo)
                    if len(all_found_repos) >= MAX_REPOS_TO_SEARCH:
                        logger.info(f"Reached max search limit of {MAX_REPOS_TO_SEARCH} repos.")
                        break
                if len(all_found_repos) >= MAX_REPOS_TO_SEARCH:
                    break
            except RateLimitExceededException as e:
                handle_rate_limit(e)
                # 继续下一个关键词搜索，或者跳过，取决于当前剩余时间
            except Exception as e:
                logger.error(f"Error during repository search for '{keyword}': {e}")
        
        repos_to_process = all_found_repos[:MAX_REPOS_TO_SEARCH] # 确保只处理限制数量的仓库
        if repos_to_process:
            save_json_file(REPOS_CACHE, [repo.full_name for repo in repos_to_process])
            logger.info(f"Cached {len(repos_to_process)} repositories.")
        else:
            logger.warning("No repositories found to process.")
            return # 没有仓库就直接退出

    logger.info(f"Processing files from {len(repos_to_process)} repositories with {MAX_WORKERS} workers.")
    
    files_to_download_all = []
    # 使用线程池获取所有仓库的文件列表，这部分也可能触发限速
    with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(repos_to_process))) as executor:
        future_to_repo = {executor.submit(get_repo_files, repo): repo.full_name for repo in repos_to_process}
        for future in as_completed(future_to_repo):
            repo_name = future_to_repo[future]
            try:
                repo_files = future.result()
                files_to_download_all.extend([(repos_to_process[repos_to_process.index(g.get_repo(repo_name))], fp, fu) for fp, fu in repo_files])
            except Exception as e:
                logger.error(f"Error getting files for {repo_name}: {e}")

    logger.info(f"Found {len(files_to_download_all)} potential node files to check and download.")

    # 使用线程池下载和保存文件
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # 使用 functools.partial 或 lambda 来传递额外的参数
        futures = [executor.submit(download_and_save_file, repo, file_path, file_url, timestamps)
                   for repo, file_path, file_url in files_to_download_all]
        
        # 遍历完成的future以确保所有任务执行完毕（即使结果不需要）
        for future in as_completed(futures):
            try:
                future.result() # 获取结果，如果任务中发生异常会在这里重新抛出
            except Exception as e:
                logger.error(f"An error occurred during file download: {e}")

    save_json_file(TIMESTAMP_FILE, timestamps)
    logger.info("ProxyPool collection complete. Timestamps saved.")

if __name__ == '__main__':
    main()
