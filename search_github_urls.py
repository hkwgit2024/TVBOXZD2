import os
import re
import subprocess
import requests
import time
import logging
import logging.handlers
import yaml
from urllib.parse import urlparse
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from tqdm import tqdm

# 配置日志系统，支持文件和控制台输出
def setup_logging(config):
    """配置日志系统，支持文件和控制台输出，日志文件自动轮转以避免过大"""
    log_level = getattr(logging, config['logging']['log_level'], logging.INFO)
    log_file = config['logging']['log_file']
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    logger = logging.getLogger()
    logger.setLevel(log_level)

    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=10*1024*1024, backupCount=1
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    ))

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    ))

    logger.handlers = [file_handler, console_handler]
    return logger

# 加载配置文件
def load_config(config_path="config/config.yaml"):
    """加载并解析 YAML 配置文件"""
    try:
        with open(config_path, 'r', encoding='utf-8') as file:
            config = yaml.safe_load(file)
            logging.info("配置文件 config.yaml 加载成功")
            return config
    except FileNotFoundError:
        logging.error(f"错误：未找到配置文件 '{config_path}'")
        exit(1)
    except yaml.YAMLError as e:
        logging.error(f"错误：配置文件 '{config_path}' 格式错误: {e}")
        exit(1)
    except Exception as e:
        logging.error(f"错误：加载配置文件 '{config_path}' 失败: {e}")
        exit(1)

# 读取本地 TXT 文件
def read_txt_to_array_local(file_name):
    """从本地 TXT 文件读取内容到数组"""
    try:
        with open(file_name, 'r', encoding='utf-8') as file:
            lines = [line.strip() for line in file if line.strip()]
        return lines
    except FileNotFoundError:
        logging.warning(f"文件 '{file_name}' 未找到")
        return []
    except Exception as e:
        logging.error(f"读取文件 '{file_name}' 失败: {e}")
        return []

# 写入本地 TXT 文件
def write_array_to_txt_local(file_path, data_array):
    """将数组内容写入本地 TXT 文件"""
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'a', encoding='utf-8') as file:
            file.write('\n'.join(data_array))
        logging.info(f"写入 {len(data_array)} 行到 '{file_path}'")
    except Exception as e:
        logging.error(f"写入文件 '{file_path}' 失败: {e}")

# 加载配置和设置日志
CONFIG_PATH = "config/config.yaml"
CONFIG = load_config(CONFIG_PATH)
setup_logging(CONFIG)

# 检查环境变量 GITHUB_TOKEN
GITHUB_TOKEN = os.getenv('BOT')
if not GITHUB_TOKEN:
    logging.error("错误：未设置环境变量 'BOT'")
    exit(1)

# URL 文件路径
URLS_PATH = 'config/urls.txt'

# GitHub API 基础 URL
GITHUB_API_BASE_URL = "https://api.github.com"
SEARCH_CODE_ENDPOINT = "/search/code"

# 配置 requests 会话
session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
})
retry_strategy = Retry(
    total=3,
    backoff_factor=CONFIG['network']['requests_retry_backoff_factor'],
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["HEAD", "GET", "OPTIONS"]
)
adapter = HTTPAdapter(max_retries=retry_strategy)
session.mount("http://", adapter)
session.mount("https://", adapter)

def check_url_validity(url):
    """同步检查 URL 是否有效，只通过响应头判断"""
    try:
        response = session.head(url, timeout=5)
        response.raise_for_status()
        content_type = response.headers.get('Content-Type', '').lower()
        if 'text' in content_type or 'json' in content_type:
            return True
        else:
            logging.info(f"URL {url} 的 Content-Type '{content_type}' 不匹配，跳过")
            return False
    except Exception as e:
        # logging.info(f"检查 URL 有效性失败: {url} - {e}")
        return False

def auto_discover_github_urls(urls_file_path_local, github_token):
    """从 GitHub 自动发现新的 IPTV 源 URL，使用同步方式"""
    if not github_token:
        logging.warning("未提供 GitHub token，跳过 URL 自动发现")
        return

    existing_urls = set(read_txt_to_array_local(urls_file_path_local))
    found_urls = set()
    
    # 获取备用 URL
    for backup_url in CONFIG.get('backup_urls', []):
        try:
            response = session.get(backup_url, timeout=10)
            response.raise_for_status()
            existing_urls.update([line.strip() for line in response.text.split('\n') if line.strip()])
        except Exception as e:
            logging.warning(f"从备用 URL {backup_url} 获取失败: {e}")

    headers = {
        "Accept": "application/vnd.github.v3.text-match+json",
        "Authorization": f"token {github_token}"
    }

    logging.warning("开始从 GitHub 自动发现新的 IPTV 源 URL")
    
    keywords_list = CONFIG.get('search_keywords', [])
    for i, keyword in enumerate(tqdm(keywords_list, desc="关键词搜索进度")):
        keyword_found_urls = set()
        
        # 在处理每个关键词之前，强制等待以避免短时间内触发速率限制
        if i > 0:
            wait_time = CONFIG['github'].get('retry_wait', 5)
            logging.warning(f"切换到下一个关键词: '{keyword}'，等待 {wait_time} 秒以避免速率限制")
            time.sleep(wait_time)

        page = 1
        while page <= CONFIG['github']['max_search_pages']:
            params = {
                "q": keyword,
                "sort": "indexed",
                "order": "desc",
                "per_page": CONFIG['github']['per_page'],
                "page": page
            }
            try:
                response = session.get(
                    f"{GITHUB_API_BASE_URL}{SEARCH_CODE_ENDPOINT}",
                    headers=headers,
                    params=params,
                    timeout=CONFIG['github']['api_timeout']
                )
                response.raise_for_status()
                data = response.json()

                rate_limit_remaining = int(response.headers.get('X-RateLimit-Remaining', 0))
                rate_limit_reset = int(response.headers.get('X-RateLimit-Reset', 0))

                if rate_limit_remaining == 0:
                    wait_seconds = max(0, rate_limit_reset - time.time()) + 5
                    logging.warning(f"GitHub API 速率限制达到，剩余请求: 0，等待 {wait_seconds:.0f} 秒")
                    time.sleep(wait_seconds)
                    continue

                if not data.get('items'):
                    logging.info(f"关键词 '{keyword}' 在第 {page} 页无结果")
                    break

                for item in data['items']:
                    html_url = item.get('html_url', '')
                    match = re.search(r'https?://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.*)', html_url)
                    if not match:
                        continue
                    
                    user, repo, branch, file_path = match.groups()
                    raw_url = f"https://raw.githubusercontent.com/{user}/{repo}/{branch}/{file_path}"
                    
                    # 只有当 URL 扩展名符合要求且未曾发现时，才进行下一步检查
                    if re.search(r'\.(m3u8|m3u|txt|csv|json|pls|xspf)$', raw_url, re.IGNORECASE) and raw_url not in existing_urls and raw_url not in found_urls:
                        if check_url_validity(raw_url):
                            found_urls.add(raw_url)
                            keyword_found_urls.add(raw_url)
                            logging.info(f"发现并校验通过的新URL: {raw_url}")
                        else:
                            logging.info(f"URL {raw_url} 无效或不包含文本内容，跳过")

                logging.info(f"完成关键词 '{keyword}' 第 {page} 页，发现 {len(keyword_found_urls)} 个新 URL")
                page += 1

            except requests.exceptions.RequestException as e:
                logging.error(f"搜索 GitHub 关键词 '{keyword}' 失败: {e}")
                break
            except Exception as e:
                logging.error(f"搜索 GitHub 关键词 '{keyword}' 时发生意外错误: {e}")
                break
    
    if found_urls:
        updated_urls = sorted(list(existing_urls | found_urls))
        logging.warning(f"发现 {len(found_urls)} 个新唯一 URL，总计保存 {len(updated_urls)} 个 URL")
        write_array_to_txt_local(urls_file_path_local, updated_urls)
    else:
        logging.warning("未发现新的 IPTV 源 URL")

    for keyword in keywords_list:
        count = len([url for url in found_urls if keyword in url])
        logging.info(f"关键词 '{keyword}' 最终发现 {count} 个新 URL")


if __name__ == "__main__":
    auto_discover_github_urls(URLS_PATH, GITHUB_TOKEN)
