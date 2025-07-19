import os
import json
import base64
import yaml
import requests
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from github import Github, RateLimitExceededException
import time
import logging

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# GitHub API 配置
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')
SEARCH_KEYWORDS = [ 'vmess', 'vless', 'trojan',  'hysteria2']
NODE_PATTERNS = [
    r'hysteria2://',
    r'vmess://',
    r'trojan://',
    r'ss://',
    r'ssr://',
    r'vless://'
]
DATA_DIR = 'data'
TIMESTAMP_FILE = 'timestamps.json'
REPOS_CACHE = 'repos.json'
MAX_WORKERS = 5  # 减少线程数

# 初始化 GitHub 客户端
g = Github(GITHUB_TOKEN)

# 确保 data 目录存在
os.makedirs(DATA_DIR, exist_ok=True)

# 加载时间戳文件
def load_timestamps():
    if os.path.exists(TIMESTAMP_FILE):
        with open(TIMESTAMP_FILE, 'r') as f:
            return json.load(f)
    return {}

# 保存时间戳文件
def save_timestamps(timestamps):
    with open(TIMESTAMP_FILE, 'w') as f:
        json.dump(timestamps, f, indent=2)

# 加载缓存的仓库列表
def load_cached_repos():
    if os.path.exists(REPOS_CACHE):
        with open(REPOS_CACHE, 'r') as f:
            return json.load(f)
    return None

# 保存缓存的仓库列表
def save_cached_repos(repos):
    with open(REPOS_CACHE, 'w') as f:
        json.dump([repo.full_name for repo in repos], f)

# 检查文件是否包含节点
def contains_nodes(content, is_base64=False):
    try:
        if is_base64:
            try:
                content = base64.b64decode(content).decode('utf-8', errors='ignore')
            except Exception:
                return False
        for pattern in NODE_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        if content.strip().startswith('---'):
            try:
                data = yaml.safe_load(content)
                if isinstance(data, dict):
                    for value in data.values():
                        if isinstance(value, str):
                            for pattern in NODE_PATTERNS:
                                if pattern in value.lower():
                                    return True
            except yaml.YAMLError:
                pass
        if content.strip().startswith('{'):
            try:
                data = json.loads(content)
                if isinstance(data, dict):
                    for value in data.values():
                        if isinstance(value, str):
                            for pattern in NODE_PATTERNS:
                                if pattern in value.lower():
                                    return True
            except json.JSONDecodeError:
                pass
        return False
    except Exception as e:
        logger.error(f"Error checking content: {e}")
        return False

# 下载并保存文件
def download_file(repo, file_path, file_url, timestamps):
    project_name = repo.full_name.replace('/', '_')
    save_dir = os.path.join(DATA_DIR, project_name)
    os.makedirs(save_dir, exist_ok=True)
    local_path = os.path.join(save_dir, file_path.replace('/', '_'))

    file_key = f"{repo.full_name}:{file_path}"
    last_modified = timestamps.get(file_key)
    headers = {'Authorization': f'token {GITHUB_TOKEN}'}
    response = requests.head(file_url, headers=headers)
    current_modified = response.headers.get('Last-Modified')

    if last_modified and last_modified == current_modified:
        logger.info(f"Skipping unchanged file: {file_path}")
        return

    time.sleep(0.5)  # 添加延迟
    response = requests.get(file_url, headers=headers)
    if response.status_code == 200:
        content = response.text
        is_base64 = False
        try:
            base64.b64decode(content)
            is_base64 = True
        except Exception:
            pass

        if contains_nodes(content, is_base64):
            with open(local_path, 'w', encoding='utf-8') as f:
                f.write(content)
            logger.info(f"Saved node file: {local_path}")
            timestamps[file_key] = current_modified
        else:
            logger.info(f"No nodes found in: {file_path}")
    else:
        logger.error(f"Failed to download {file_path}: {response.status_code}")

# 处理单个仓库
def process_repo(repo, timestamps):
    try:
        contents = repo.get_contents("")
        files_to_download = []
        while contents:
            file_content = contents.pop(0)
            if file_content.type == "dir":
                contents.extend(repo.get_contents(file_content.path))
            else:
                if any(file_content.path.endswith(ext) for ext in ['.txt', '.yml', '.yaml', '.json']):
                    files_to_download.append((file_content.path, file_content.download_url))
                elif not '.' in file_content.path:
                    files_to_download.append((file_content.path, file_content.download_url))

        for file_path, file_url in files_to_download:
            download_file(repo, file_path, file_url, timestamps)
    except RateLimitExceededException:
        logger.warning("Rate limit exceeded, waiting 60 seconds...")
        time.sleep(60)
        process_repo(repo, timestamps)
    except Exception as e:
        logger.error(f"Error processing repo {repo.full_name}: {e}")

# 检查速率限制
def check_rate_limit():
    rate_limit = g.get_rate_limit()
    search_limit = rate_limit.search
    logger.info(f"Search API remaining: {search_limit.remaining}/{search_limit.limit}")
    return search_limit.remaining > 0

# 主函数
def main():
    if not check_rate_limit():
        logger.error("Search API limit reached, exiting...")
        return

    timestamps = load_timestamps()
    cached_repos = load_cached_repos()
    repos = []

    if cached_repos:
        logger.info("Using cached repositories")
        repos = [g.get_repo(name) for name in cached_repos]
    else:
        for keyword in SEARCH_KEYWORDS:
            logger.info(f"Searching for keyword: {keyword}")
            query = f"{keyword} language:python language:go language:shell"
            try:
                for repo in g.search_repositories(query=query, sort='stars', order='desc'):
                    repos.append(repo)
                    if len(repos) >= 20:  # 限制为 20 个仓库
                        break
                if len(repos) >= 20:
                    break
            except RateLimitExceededException:
                logger.warning("Search API rate limit exceeded, waiting 60 seconds...")
                time.sleep(60)
                continue
        save_cached_repos(repos)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        executor.map(lambda repo: process_repo(repo, timestamps), repos)

    save_timestamps(timestamps)
    logger.info("Processing complete.")

if __name__ == '__main__':
    main()
